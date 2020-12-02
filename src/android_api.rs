/// Android interface. Compiles on android only.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {

    use crate::phone_api::{ProofQrCode, Public, QrRequest, Relation};
    use crate::zk::{generate_proof, verify_proof};
    use jni::objects::{JClass, JString};
    use jni::sys::{jbyteArray, jint, jobject, jstring};
    use jni::JNIEnv;
    use std::str::FromStr;

    #[no_mangle]
    pub unsafe extern "C" fn Java_eu_legalage_app_logic_RustInterface_generateQrCode(
        env: JNIEnv,
        _: JClass,
        public_info: jobject,
        birthday: jint,
        private_key: jbyteArray,
        photo_digest: jbyteArray,
    ) -> jstring {
        let today_rs = env
            .get_field(public_info, "today", "I")
            .expect("Cannot extract 'PublicInfo::today'.")
            .i()
            .expect("Cannot unwrap 'PublicInfo::today'.") as u32;

        let now_rs = env
            .get_field(public_info, "now", "I")
            .expect("Cannot extract 'PublicInfo::now'.")
            .i()
            .expect("Cannot unwrap 'PublicInfo::now'.") as u32;

        let relation_rs = match env
            .get_field(public_info, "relation", "I")
            .expect("Cannot extract 'PublicInfo::relation'.")
            .i()
        {
            Ok(0) => Relation::Younger,
            Ok(1) => Relation::Older,
            _ => panic!("Cannot unwrap 'PublicInfo::relation'."),
        };

        let delta_rs = env
            .get_field(public_info, "delta", "I")
            .expect("Cannot extract 'PublicInfo::delta'.")
            .i()
            .expect("Cannot unwrap 'PublicInfo::delta'.") as u32;

        let birthday_rs = birthday as u32;

        let private_key_rs = env
            .convert_byte_array(private_key)
            .expect("Cannot unwrap 'private_key'.");

        let photo_digest_rs = env
            .convert_byte_array(photo_digest)
            .expect("Cannot unwrap 'photo_digest'.");

        let rq = QrRequest {
            public: Public {
                today: today_rs,
                now: now_rs,
                relation: relation_rs,
                delta: delta_rs,
            },
            birthday: birthday_rs,
            private_key: private_key_rs,
            photos_digest: photo_digest_rs,
        };

        let p = generate_proof(rq)
            .expect("Cannot generate proof")
            .to_string();

        let output = env.new_string(p).expect("Couldn't create result string!");

        output.into_inner()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_eu_legalage_app_logic_RustInterface_validateQrCode(
        env: JNIEnv,
        _: JClass,
        qr_code: JString,
        photo_digest: jbyteArray,
        _public_info: jobject,
    ) -> jint {
        let qr_code_rs: String = env
            .get_string(qr_code)
            .expect("Cannot extract 'qr_code' string.")
            .into();

        let _photo_digest_rs = env
            .convert_byte_array(photo_digest)
            .expect("Cannot unwrap 'photo_digest'.");

        let result = match &ProofQrCode::from_str(&qr_code_rs) {
            Ok(qr_parsed) => match verify_proof(qr_parsed, photo_digest_rs) {
                Ok(()) => {
                    //		    let proof = ProofQrCode::public_from_str(&qr_code_rs);
                    // TODO copy public objects
                    0
                }
                _ => 1,
            },
            _ => 1,
        };
        result
    }
}
