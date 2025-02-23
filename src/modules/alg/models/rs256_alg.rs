pub use rsa::pkcs1::DecodeRsaPrivateKey;
pub use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Sha256};
use crate::modules::alg::JwtAlg;

pub struct RS256Alg {
    inner: SigningKey<Sha256>
}

impl RS256Alg {
    pub fn new(key: SigningKey<Sha256>) -> Self {
        RS256Alg {
            inner: key,
        }
    }
}

impl JwtAlg for RS256Alg {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        self.inner.sign(payload.as_bytes()).to_vec()
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use rsa::pkcs1v15::SigningKey;

    pub use rsa::pkcs1::DecodeRsaPrivateKey;
    pub use rsa::RsaPrivateKey;

    use pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::signature::{SignatureEncoding, Signer};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value};
    use sha2::{Sha256, Digest};
    use crate::modules::alg::{JwtAlg, RS256Alg};

    #[test]
    fn rs256_algorithm_works_as_expected() {
        let payload = "something";

        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../../test-files/rs256.key")).unwrap();
        let signing_key = SigningKey::new(private_key);
        let alg = RS256Alg::new(signing_key);

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "");

        let verify = alg.verify(payload, &signature_bytes);

        assert!(verify);
    }
}