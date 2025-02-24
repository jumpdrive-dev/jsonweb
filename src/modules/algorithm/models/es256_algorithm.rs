use p256::ecdsa::SigningKey;

pub struct ES256Algorithm {
    inner: SigningKey,
}

impl ES256Algorithm {
    pub fn new(key: SigningKey) -> Self {
        ES256Algorithm {
            inner: key,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use p256::ecdsa::SigningKey;
    use p256::SecretKey;
    use crate::algorithm::models::es256_algorithm::ES256Algorithm;

    #[test]
    fn es256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";

        let signing_key = SecretKey::from_sec1_pem(include_str!("../../../../test-files/es256.key"));

        dbg!(signing_key);

        // let alg = ES256Algorithm::new(signing_key);

        // let signature_bytes = alg.sign(payload);
        // let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);
        //
        // assert_eq!(signature_string, "LM8raaYjKi8HAt4-GsYPlQFSpOJWJUCtUa70beULD6t0Wwvzvn7L3u72KZUfGTgZ7xu-vfAXHrkIRR0ofF2TIw");
        //
        // let verify = alg.verify(payload, &signature_bytes).unwrap();
        //
        // assert!(verify);
    }
}

//