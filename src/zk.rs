use crate::phone_api::{ProofQrCode, Public, QrRequest, Relation};
use serde_json;
use zokrates_core::ir::{self, ProgEnum};
use zokrates_core::proof_system::{
    bellman::{
        groth16::{ProofPoints, G16}
    },
    Proof, ProofSystem,
};
use zokrates_core::typed_absy::abi::Abi;
use zokrates_field::{Bn128Field, Field};

use bellman_ce::groth16::Proof as BellmanProof;
use pairing::{Engine};
use bellman_ce::pairing::bn256::{Bn256, Fq2};


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
const MaxJulianDay: u32 = 9999999;

pub fn generate_proof(rq: QrRequest) -> Result<ProofQrCode, String> {
    let prg = match ProgEnum::deserialize(&mut PROGRAM.clone())? {
        ProgEnum::Bn128Program(p) => p,
        _ => panic!("Invalid program type"),
    };

    let abi: Abi = serde_json::from_reader(&mut ABI.clone()).unwrap();
    let signature = abi.signature();

    let interpreter = ir::Interpreter::default();

    let mut arguments: Vec<Bn128Field> = Vec::new();

    // Inverting the relation.
    let mut birthday = rq.birthday;
    let mut delta = rq.public.delta;
    let mut today = rq.public.today;
    if rq.public.relation == Relation::Younger {
        birthday = MaxJulianDay - birthday;
        delta = MaxJulianDay - delta;
        today = 2 * MaxJulianDay - today;
    }

    arguments.push(Bn128Field::from(birthday));
    arguments.push(Bn128Field::from(delta));
    arguments.push(Bn128Field::from(today));
    arguments.push(Bn128Field::from_byte_vector(rq.photos_digest));
    arguments.push(Bn128Field::from_byte_vector(rq.private_key));

    let witness = interpreter
        .execute(&prg, &arguments)
        .map_err(|e| format!("Execution failed: {}", e))?;

    let outs = witness.return_values();
    assert_eq!(1, outs.len());
    let out = &outs[0];

    let mut proof = G16::generate_proof(prg, witness, PROVING_KEY.to_vec());

    let qr = ProofQrCode {
        public: rq.public,
        proof: proof.proof.into_bellman::<Bn128Field>(),
        challenge: Vec::new(),
    };
    Ok(qr)
}

pub fn verify_proof(qr: ProofQrCode) -> Result<(), String> {
    let vk = serde_json::from_reader(VERIFICATION_KEY)
        .map_err(|why| format!("Couldn't deserialize verification key: {}", why))?;

    let mut inputs: Vec<String> = Vec::new();

    // Inverting the relation.
    let mut delta = qr.public.delta;
    let mut today = qr.public.today;
    if qr.public.relation == Relation::Younger {
        delta = MaxJulianDay - delta;
        today = 2 * MaxJulianDay - today;
    }

    inputs.push(Bn128Field::from(delta).to_string());
    inputs.push(Bn128Field::from(today).to_string());
    println!("{:?}", inputs);

    let mut raw: Vec<u8> = Vec::new();
    qr.proof.write(&mut raw).unwrap();

    let proof_points =  ProofPoints::from_bellman::<Bn128Field>(qr.proof);

    let proof = Proof::<ProofPoints> {
        proof: proof_points,
        inputs: inputs,
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
    use super::*;

    #[test]
    fn verify_ok() {
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Older,
                delta: 18,
            },
            birthday: 2001,
            private_key: Vec::new(),
            photos_digest: Vec::new(),
        };
        let p = generate_proof(rq).unwrap();
        assert!(verify_proof(p).is_ok());
    }

    #[test]
    fn verify_fail() {
        let rq = QrRequest {
            public: Public {
                today: 2020,
                now: 1200,
                relation: Relation::Younger,
                delta: 21,
            },
            birthday: 2001,
            private_key: Vec::new(),
            photos_digest: Vec::new(),
        };
        let p = generate_proof(rq).unwrap();
        assert!(verify_proof(p).is_ok());
    }
}
