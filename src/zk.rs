// Zero-knowledge algorithms.

use crate::api::{Private, ProofQrCode, QrError, QrRequest, Relation};

use bellman_ce::groth16::Proof as BellmanProof;
use bellman_ce::pairing::{bn256::Bn256, ff::ScalarEngine};
use ff_mimc::{PrimeField, PrimeFieldRepr};
use mimc_rs;
use rand::{thread_rng, ChaChaRng, Rng, SeedableRng};
use serde_json;
use std::io::Cursor;
use zokrates_core::ir::{self, ProgEnum};
use zokrates_core::proof_system::{
    bellman::groth16::{ProofPoints, G16},
    Proof, ProofSystem,
};
use zokrates_core::typed_absy::abi::Abi;
use zokrates_field::{Bn128Field, Field};

static PROGRAM: &'static [u8] = include_bytes!("../zokrates/out");
static ABI: &'static [u8] = include_bytes!("../zokrates/abi.json");
static PROVING_KEY: &'static [u8] = include_bytes!("../zokrates/proving.key");
static VERIFICATION_KEY: &'static [u8] = include_bytes!("../zokrates/verification.key");

// The circuit validates the "is older" relation: birth + delta >
// today.  The inverse "is younger" relation is implemented in the
// same circuit by changing the signs of all quantities. But
// because there is no signed integer among ZoKrates types, an
// unsigned int is used and a constant must be added to both sides
// of the inequality.
const MAX_JULIAN_DAY: i32 = 9999999;

type Fr = <Bn256 as ScalarEngine>::Fr;

pub fn generate_random_private_key() -> Vec<u8> {
    let seed = thread_rng().gen::<[u32; 4]>();
    let mut rng = ChaChaRng::from_seed(&seed);
    let r: Fr = rng.gen();
    Bn128Field::from_bellman(r).into_byte_vector()
}

fn zok2mimc(value: &Bn128Field) -> mimc_rs::Fr {
    // Zokrates uses internal BigInt representation, mimc uses ff with private Repr.

    let s = value.to_dec_string();
    mimc_rs::Fr::from_str(&s).unwrap()
}

fn mimc2zok(value: mimc_rs::Fr) -> Bn128Field {
    let mut res: Vec<u8> = vec![];
    value.into_repr().write_le(&mut res).unwrap();
    Bn128Field::from_byte_vector(res)
}

fn compute_mimc7r10_hash(x: &Bn128Field, k: &Bn128Field) -> Bn128Field {
    let mimc7r10 = mimc_rs::Mimc7::new(10);
    let hash = mimc7r10.hash(&zok2mimc(x), &zok2mimc(k));
    mimc2zok(hash)
}

pub fn generate_card_key(rq: Private) -> Vec<u8> {
    let private_key = Bn128Field::from_byte_vector(rq.private_key);
    let birthday = Bn128Field::from(rq.birthday);
    let photos_digest = Bn128Field::from_byte_vector(rq.photos_digest);

    let k = birthday * private_key;
    let m1 = compute_mimc7r10_hash(&photos_digest, &k);
    let card_key = m1 * photos_digest;
    card_key.into_byte_vector()
}

pub fn compute_challenge(card_key: Vec<u8>, today: i32) -> Vec<u8> {
    let card_key = Bn128Field::from_byte_vector(card_key);
    let today = Bn128Field::from(today);
    let challenge = compute_mimc7r10_hash(&today, &card_key);
    challenge.into_byte_vector()
}

pub fn generate_proof(rq: QrRequest) -> Result<ProofQrCode, String> {
    let prg = match ProgEnum::deserialize(&mut PROGRAM.clone())? {
        ProgEnum::Bn128Program(p) => p,
        _ => panic!("Invalid program type"),
    };

    let abi: Abi = serde_json::from_reader(&mut ABI.clone()).unwrap();
    let _signature = abi.signature();

    let interpreter = ir::Interpreter::default();

    let mut arguments: Vec<Bn128Field> = Vec::new();

    let mut birthday = rq.private.birthday;
    let mut delta = rq.public.delta;
    let mut today = rq.public.today;

    println!("generate proof today: {}", today);
    
    if rq.is_relation_valid() {
        // Inverting the relation.
        if rq.public.relation == Relation::Younger {
            birthday = MAX_JULIAN_DAY - birthday;
            delta = MAX_JULIAN_DAY - delta;
            today = 2 * MAX_JULIAN_DAY - today;
        }
    } else {
        // Generating invalid proof.
        //
        // The user wants us to proof something what is not
        // true. Maybe someone is trying to abuse the phone to learn
        // about the users age. We do not want to report an error because
        // this will allow annyone to guess the age by trial and
        // error. Instead we will generate a valid proof but for
        // another set of input variables. The proof will fail to be
        // verified but it will look similar to a real proof and the
        // generation will take the same time.
        delta = 0;
	// Delta is the only parameter which can be changed or else
	// the challenge will be also changed.
	println!("Generating invalid proof delta={} birthday={} today={} OLDER ", delta, birthday, today);
    }

    arguments.push(Bn128Field::from(birthday));
    arguments.push(Bn128Field::from(delta));
    arguments.push(Bn128Field::from(today));
    arguments.push(Bn128Field::from_byte_vector(rq.private.photos_digest.clone()));
    arguments.push(Bn128Field::from_byte_vector(rq.private.private_key));

    let witness = interpreter
        .execute(&prg, &arguments)
        .map_err(|e| format!("Execution failed: {}", e))?;

    let outs = witness.return_values();
    assert_eq!(1, outs.len());
    let out = &outs[0];

    let proof = G16::generate_proof(prg, witness, PROVING_KEY.to_vec());

    let hidden_proof = hide_bellman_proof(&proof.proof.into_bellman::<Bn128Field>(),
					  &rq.private.photos_digest);
    
    let qr = ProofQrCode {
        public: rq.public,
        proof: hidden_proof,
        challenge: out.into_byte_vector(),
    };
    Ok(qr)
}

pub fn verify_proof(qr: &ProofQrCode, photo_digest: &Vec<u8>) -> Result<(), String> {
    let vk = serde_json::from_reader(VERIFICATION_KEY)
        .map_err(|why| format!("Couldn't deserialize verification key: {}", why))?;

    let mut inputs: Vec<Bn128Field> = Vec::new();

    // Inverting the relation.
    let mut delta = qr.public.delta;
    let mut today = qr.public.today;
    if qr.public.relation == Relation::Younger {
        delta = MAX_JULIAN_DAY - delta;
        today = 2 * MAX_JULIAN_DAY - today;
    }

    inputs.push(Bn128Field::from(delta));
    inputs.push(Bn128Field::from(today));
    inputs.push(Bn128Field::from_byte_vector(qr.challenge.clone()));

    let proof = unhide_bellman_proof(&qr.proof, photo_digest).unwrap(); // TODO error

    
    let mut raw: Vec<u8> = Vec::new();
    proof.write(&mut raw).unwrap();

    let proof_points = ProofPoints::from_bellman::<Bn128Field>(&proof);

    let proof = Proof::<ProofPoints> {
        proof: proof_points,
        inputs: inputs
            .iter()
            .map(|bn128| bn128.to_biguint().to_str_radix(16))
            .collect(),
        raw: hex::encode(&raw),
    };

    let ans = <G16 as ProofSystem<Bn128Field>>::verify(vk, proof);
    if ans {
        Ok(())
    } else {
        Err(String::from("no"))
    }
}

fn hide_buffer(buf: &mut Vec<u8>, hidding: &Vec<u8>) {
    if hidding.len() > 0 {
        for i in 0..buf.len() {
            buf[i] ^= hidding[i % hidding.len()];
        }
    }
}

pub fn hide_bellman_proof(proof: &BellmanProof<Bn256>, hidding: &Vec<u8>) -> Vec<u8> {
    let mut proof_bytes: Vec<u8> = Vec::new();
    proof.write(&mut proof_bytes).unwrap();
    hide_buffer(&mut proof_bytes, hidding);
    proof_bytes
	
}

pub fn unhide_bellman_proof(
    hidden: &Vec<u8>,
    hidding: &Vec<u8>,
) -> Result<BellmanProof<Bn256>, QrError> {
    let mut b = hidden.clone();
    hide_buffer(&mut b, hidding);
    let mut rdr = Cursor::new(b);
    BellmanProof::<Bn256>::read(&mut rdr).map_err(|_| QrError {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Private, ProofQrCode, Public, QrRequest, Relation};
    use std::str::FromStr;
    use zokrates_field::Bn128Field;

    #[test]
    fn generate_random_private_key() {
        let key = super::generate_random_private_key();
        println!("{:?}", key);
        assert_eq!(32, key.len());
    }

    fn bn128(s: &str) -> Bn128Field {
        Bn128Field::try_from_dec_str(s).unwrap()
    }

    #[test]
    fn mimc7r10() {
        // values from ZoKrartes test

        assert_eq!(
            compute_mimc7r10_hash(&bn128("0"), &bn128("0")),
            bn128("6004544488495356385698286530147974336054653445122716140990101827963729149289")
        );
        assert_eq!(
            compute_mimc7r10_hash(&bn128("100"), &bn128("0")),
            bn128("2977550761518141183167168643824354554080911485709001361112529600968315693145")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128("100"),
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                )
            ),
            bn128("2977550761518141183167168643824354554080911485709001361112529600968315693145")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495618"
                ),
                &bn128("1")
            ),
            bn128("11476724043755138071320043459606423473319855817296339514744600646762741571430")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                ),
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                )
            ),
            bn128("6004544488495356385698286530147974336054653445122716140990101827963729149289")
        );
    }

    #[test]
    fn generate_card_key() {
        let m1 =
            bn128("2398929016733331352351677352383442125702690766615627729516078292095018104789");
        assert_eq!(compute_mimc7r10_hash(&bn128("3"), &bn128("20010")), m1);

        let private = Private {
            birthday: 2001,
            private_key: bn128("10").into_byte_vector(),
            photos_digest: bn128("3").into_byte_vector(),
        };
        let key = super::generate_card_key(private);
        assert_eq!(32, key.len());

        assert_eq!(Bn128Field::from_byte_vector(key), bn128("3") * m1);
    }

    #[test]
    fn compute_challenge() {
        let m1 =
            bn128("20806133116655125295815844821187893628062572117889123030572462808546913026234");
        assert_eq!(compute_mimc7r10_hash(&bn128("2020"), &bn128("27")), m1);

        let card_key = bn128("27").into_byte_vector();
        let today = 2020;
        let challenge = super::compute_challenge(card_key, today);
        assert_eq!(32, challenge.len());

        assert_eq!(Bn128Field::from_byte_vector(challenge), m1);
    }

    #[test]
    fn verify_younger() {
	let photos_digest = vec![2u8, 7];
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Older,
                delta: 18,
            },
            private: Private {
                birthday: 2001,
                private_key: Vec::new(),
                photos_digest: photos_digest.clone(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(super::verify_proof(&p, &photos_digest).is_ok());
        let ps = p.to_string();
        assert!(super::verify_proof(&ProofQrCode::from_str(&ps).unwrap(), &photos_digest).is_ok());
    }

    #[test]
    fn verify_older() {
	let photos_digest = Vec::new();
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Younger,
                delta: 21,
            },
            private: Private {
                birthday: 2001,
                private_key: Vec::new(),
                photos_digest: photos_digest.clone(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(super::verify_proof(&p, &photos_digest).is_ok());
        let ps = p.to_string();
        assert!(super::verify_proof(&ProofQrCode::from_str(&ps).unwrap(), &photos_digest).is_ok());
    }

    #[test]
    fn verify_invalid() {
	let photos_digest = Vec::new();
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Older,
                delta: 18,
            },
            private: Private {
                birthday: 2010,
                private_key: Vec::new(),
                photos_digest: photos_digest.clone(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p, &photos_digest).is_ok());
    }

    #[test]
    fn verify_marginal_case_older() {
	let photos_digest = Vec::new();
        // Equality is refused. Wait till midnight.
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Older,
                delta: 20,
            },
            private: Private {
                birthday: 2000,
                private_key: Vec::new(),
                photos_digest: photos_digest.clone(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p, &photos_digest).is_ok());
    }

    #[test]
    fn verify_marginal_case_younger() {
	let photos_digest = Vec::new();
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Older,
                delta: 20,
            },
            private: Private {
                birthday: 2000,
                private_key: Vec::new(),
                photos_digest: photos_digest.clone(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p, &photos_digest).is_ok());
    }
}
