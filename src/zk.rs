use crate::phone_api::{ProofQrCode, QrRequest, Relation, Public};
use base64::{decode, encode};
use serde_json;
use zokrates_core::ir::{self, ProgEnum};
use zokrates_core::proof_system::{bellman::groth16::G16, ProofSystem};
use zokrates_core::typed_absy::abi::Abi;
use zokrates_field::{Bn128Field, Field};

static PROGRAM: &'static [u8] = include_bytes!("../zokrates/out");
static ABI: &'static [u8] = include_bytes!("../zokrates/abi.json");
static PROVING_KEY: &'static [u8] = include_bytes!("../zokrates/proving.key");
static VERIFICATION_KEY: &'static [u8] = include_bytes!("../zokrates/verification.key");

pub fn generate_proof(rq: QrRequest) -> Result<ProofQrCode, String> {
    let prg = match ProgEnum::deserialize(&mut PROGRAM.clone())? {
        ProgEnum::Bn128Program(p) => p,
        _ => panic!("Invalid program type"),
    };

    let abi: Abi = serde_json::from_reader(&mut ABI.clone()).unwrap();
    let signature = abi.signature();

    let interpreter = ir::Interpreter::default();

    let mut arguments: Vec<Bn128Field> = Vec::new();

    // The circuit validates the "is older" relation: birth + delta >
    // today.  The inverse "is younger" relation is implemented in the
    // same circuit by changing the signs of all quantities. But
    // because there is no signed integer among ZoKrates types, an
    // unsigned int is used and a constant must be added to both sides
    // of the inequality.
    let MAX_JULIAN_DATE = 9999999;
    let mut birthday = rq.birthday;
    let mut delta = rq.public.delta;
    let mut today = rq.public.today;
    if rq.public.relation == Relation::Younger {
	birthday = MAX_JULIAN_DATE - birthday;
	delta = MAX_JULIAN_DATE - delta;
	today = 2 * MAX_JULIAN_DATE - today;
    }
    
    arguments.push(Bn128Field::from(birthday));
    arguments.push(Bn128Field::from(delta));
    arguments.push(Bn128Field::from(today));
    arguments.push(Bn128Field::from_byte_vector(rq.photos_digest));
    arguments.push(Bn128Field::from_byte_vector(rq.private_key));

    let witness = interpreter
        .execute(&prg, &arguments)
        .map_err(|e| format!("Execution failed: {}", e))?;

    let mut proof = G16::generate_proof(prg, witness, PROVING_KEY.to_vec());

    let proof = serde_json::to_string_pretty(&proof).unwrap();
    println!("Proof:\n{}", format!("{}", proof));

    let mut p = ProofQrCode::new();
    p.raw_proof = proof;
    Ok(p)
}

pub fn verify_proof(qr: ProofQrCode) -> Result<(), String> {
    let vk = serde_json::from_reader(VERIFICATION_KEY)
        .map_err(|why| format!("Couldn't deserialize verification key: {}", why))?;

    let proof = serde_json::from_str(&qr.raw_proof)
        .map_err(|why| format!("Couldn't deserialize proof: {}", why))?;

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
