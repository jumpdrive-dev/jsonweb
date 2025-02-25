use std::convert::Infallible;
use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use p256::ecdsa::signature::Verifier;
use crate::algorithm::JwAlg;

/// ```shell
/// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256.pem
/// ```
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

impl JwAlg for ES256Algorithm {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "ES256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        let signature: Signature = self.inner.sign(payload.as_bytes());
        signature.to_vec()
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = self.inner.verifying_key();
        let signature = Signature::try_from(signature).unwrap();

        Ok(verifying_key.verify(payload.as_bytes(), &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use p256::ecdsa::SigningKey;
    use p256::SecretKey;
    use crate::algorithm::JwAlg;
    use crate::algorithm::models::es256_algorithm::ES256Algorithm;

    #[test]
    fn es256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let secret_key = include_str!("../../../../test-files/es256.key").parse::<SecretKey>().unwrap();
        let signing_key = SigningKey::from(secret_key);

        let alg = ES256Algorithm::new(signing_key);

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "XX7zPdDrYpegeS7mBfBIUVXnqVT-XSemrGjgoZBlrN0--n94Lv03J9vzbDDJXPzxnSs_62ymIJr1zBMaoMAveA");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }
}