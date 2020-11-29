use bellman_ce::groth16::Proof as BellmanProof;
use bellman_ce::pairing::bn256::Bn256;
use bs58;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

use std::str::FromStr;

/// Trust level of the verifier.
pub enum VerifierLevel {
    SelfSignedTest,
    HasPublicCertificate,
    Professional
}

/// The relation to be proved.
#[derive(PartialEq, Debug, Clone)]
pub enum Relation {
    Younger,
    Older,
}

/// Public part of the proof.
#[derive(Debug, Clone)]
pub struct Public {
    /// Today julian date.
    pub today: i32,

    /// Current UTC time since midnight. Publicly encoded in the QR code but not used
    /// in the proof.
    pub now: i32,

    /// Relation.
    pub relation: Relation,

    /// Minimal (maximal) difference between 'today' and 'birthday' in days.
    pub delta: i32,
}

impl Public {
    pub fn new() -> Self {
        Public {
            today: 0,
            now: 0,
            relation: Relation::Younger,
            delta: 0,
        }
    }
}

/// Private part of the proof
#[derive(Debug)]
pub struct Private {
    /// Birthday - julian date. Private part of the proof.
    pub birthday: i32,

    /// Private key known only to the prover and to the
    /// certifier. Big-endian encoded number in Field range. Private
    /// part of the proof.
    pub private_key: Vec<u8>,

    /// Digest of the photoset. Big-endian encoded number in Field
    /// range. Private part of the proof.
    pub photos_digest: Vec<u8>,
}

impl Private {
    pub fn new() -> Self {
        Private {
            birthday: 0,
            private_key: Vec::new(),
            photos_digest: Vec::new(),
        }
    }
}


/// Request for QR code generation from phone app.
#[derive(Debug)]
pub struct QrRequest {
    pub public: Public,
    pub private: Private,
}

impl QrRequest {
    pub fn new() -> Self {
        QrRequest {
            public: Public::new(),
	    private: Private::new(),
        }
    }

    pub fn to_qr_code_string() -> String {
        String::from("")
    }

    pub fn from_qr_code_string(_qr_str: &str) -> Self {
        QrRequest::new()
    }

    pub fn is_relation_valid(&self) -> bool {
        match self.public.relation {
            Relation::Younger => self.private.birthday + self.public.delta > self.public.today,
            Relation::Older => self.private.birthday + self.public.delta < self.public.today,
        }
    }
}

/// QR code containing the proof. Is generated by the prover and
/// verified by the verifier
#[derive(Debug, Clone)]
pub struct ProofQrCode {
    /// Public part of the proof.
    pub public: Public,

    // Proof a,b,c curve points.
    pub proof: BellmanProof<Bn256>,

    /// Challenge. Big-endian encoded number in Field
    /// range. Public output of the proof computation.
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct QrError {}

impl ProofQrCode {
    pub fn public_to_string(&self) -> String {
        let mut wtr = vec![];
        wtr.write_i32::<BigEndian>(self.public.today).unwrap();
        wtr.write_i32::<BigEndian>(self.public.now).unwrap();
        wtr.write_i32::<BigEndian>(self.public.delta).unwrap();
        wtr.push(self.public.relation.clone() as u8);
        bs58::encode(wtr).into_string()
    }

    pub fn public_from_str(s: &str) -> Result<Public, QrError> {
        let mut rdr = Cursor::new(bs58::decode(s).into_vec().map_err(|_| QrError {})?);

        let today = rdr.read_i32::<BigEndian>().map_err(|_| QrError {})?;
        let now = rdr.read_i32::<BigEndian>().map_err(|_| QrError {})?;
        let delta = rdr.read_i32::<BigEndian>().map_err(|_| QrError {})?;
        const YOUNGER: u8 = Relation::Younger as u8;
        let relation = match rdr.read_u8().map_err(|_| QrError {})? {
            YOUNGER => Relation::Younger,
            _ => Relation::Older,
        };
        Ok(Public {
            today: today,
            now: now,
            delta: delta,
            relation: relation,
        })
    }

    pub fn proof_to_string(&self) -> String {
        let mut compressed: Vec<u8> = Vec::new();
        self.proof.write(&mut compressed).unwrap();
        bs58::encode(compressed).into_string()
    }

    pub fn proof_from_str(s: &str) -> Result<BellmanProof<Bn256>, QrError> {
        let mut rdr = Cursor::new(bs58::decode(s).into_vec().map_err(|_| QrError {})?);
        BellmanProof::<Bn256>::read(&mut rdr).map_err(|_| QrError {})
    }

    pub fn challenge_to_string(&self) -> String {
        bs58::encode(&self.challenge).into_string()
    }

    pub fn challenge_from_str(s: &str) -> Result<Vec<u8>, QrError> {
        bs58::decode(s).into_vec().map_err(|_| QrError {})
    }
}

impl ToString for ProofQrCode {
    fn to_string(&self) -> String {
        let parts = vec![
            self.public_to_string(),
            self.proof_to_string(),
            self.challenge_to_string(),
        ];
        parts.join(";")
    }
}

impl FromStr for ProofQrCode {
    type Err = QrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(";").collect();
        if parts.len() != 3 {
            Err(QrError {})
        } else {
            Ok(ProofQrCode {
                public: Self::public_from_str(parts[0])?,
                proof: Self::proof_from_str(parts[1])?,
                challenge: Self::challenge_from_str(parts[2])?,
            })
        }
    }
}
