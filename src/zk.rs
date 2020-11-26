// Zero-knowledge algorithms.

use crate::api::{Private, ProofQrCode, QrRequest, Relation};
use serde_json;
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
const MAX_JULIAN_DAY: u32 = 9999999;

pub fn generate_random_private_key() -> Vec<u8> {
    Vec::new()
}

pub fn generate_card_key(_rq: Private) -> Vec<u8> {
    Vec::new()
}

pub fn compute_challenge(_card_key: Vec<u8>, _today: u32) -> Vec<u8> {
    Vec::new()
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
        today = birthday + 1;
    }

    arguments.push(Bn128Field::from(birthday));
    arguments.push(Bn128Field::from(delta));
    arguments.push(Bn128Field::from(today));
    arguments.push(Bn128Field::from_byte_vector(rq.private.photos_digest));
    arguments.push(Bn128Field::from_byte_vector(rq.private.private_key));

    let witness = interpreter
        .execute(&prg, &arguments)
        .map_err(|e| format!("Execution failed: {}", e))?;

    let outs = witness.return_values();
    assert_eq!(1, outs.len());
    let out = &outs[0];

    let proof = G16::generate_proof(prg, witness, PROVING_KEY.to_vec());

    let qr = ProofQrCode {
        public: rq.public,
        proof: proof.proof.into_bellman::<Bn128Field>(),
        challenge: out.into_byte_vector(),
    };
    Ok(qr)
}

pub fn verify_proof(qr: &ProofQrCode) -> Result<(), String> {
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

    let mut raw: Vec<u8> = Vec::new();
    qr.proof.write(&mut raw).unwrap();

    let proof_points = ProofPoints::from_bellman::<Bn128Field>(&qr.proof);

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

#[cfg(test)]
mod tests {
    use crate::api::{Private, ProofQrCode, Public, QrRequest, Relation};
    use std::str::FromStr;

    #[test]
    fn generate_random_private_key() {
	let key = super::generate_random_private_key();
	assert_eq!(0, key.len());
    }

    #[test]
    fn generate_card_key() {
        let private= Private {
                birthday: 2001,
                private_key: Vec::new(),
                photos_digest: Vec::new(),
            };
	let key = super::generate_card_key(private);
	assert_eq!(0, key.len());
    }

    #[test]
    fn compute_challenge() {
	let card_key = Vec::new();
	let today = 0u32;
	let challenge = super::compute_challenge(card_key, today);
	assert_eq!(0, challenge.len());
    }
    
    #[test]
    fn verify_younger() {
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
                photos_digest: Vec::new(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(super::verify_proof(&p).is_ok());
        let ps = p.to_string();
        assert!(super::verify_proof(&ProofQrCode::from_str(&ps).unwrap()).is_ok());
    }

    #[test]
    fn verify_older() {
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
                photos_digest: Vec::new(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(super::verify_proof(&p).is_ok());
        let ps = p.to_string();
        assert!(super::verify_proof(&ProofQrCode::from_str(&ps).unwrap()).is_ok());
    }

    #[test]
    fn verify_invalid() {
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
                photos_digest: Vec::new(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p).is_ok());
    }

    #[test]
    fn verify_marginal_case_older() {
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
                photos_digest: Vec::new(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p).is_ok());
    }

    #[test]
    fn verify_marginal_case_younger() {
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
                photos_digest: Vec::new(),
            },
        };
        let p = super::generate_proof(rq).unwrap();
        assert!(!super::verify_proof(&p).is_ok());
    }
}
