use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use hmac::{Hmac, Mac};
use hmac::digest::InvalidLength;
use sha2::Sha256;
use crate::algorithm::JwAlg;

#[derive(Clone)]
pub struct HS256Algorithm {
    inner: Hmac<Sha256>,
}

impl HS256Algorithm {
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(HS256Algorithm {
            inner: Hmac::<Sha256>::new_from_slice(key)?
        })
    }
}

impl JwAlg for HS256Algorithm {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "HS256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        let mut inner = self.inner.clone();
        inner.update(payload.as_bytes());

        inner.finalize().into_bytes().to_vec()
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let mut inner = self.inner.clone();
        inner.update(payload.as_bytes());

        let finalized = inner.finalize()
            .into_bytes()
            .to_vec();

        Ok(signature == finalized)
    }
}

impl Debug for HS256Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HS256Algorithm {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use crate::modules::algorithm::{HS256Algorithm, JwAlg};

    #[test]
    fn hs256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";
        let alg = HS256Algorithm::new("qwed".as_ref()).unwrap();

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "AeQU9YyCnBlrJwtd1PVmGW3apn6kQ6yi_U4qT9o0vkQ");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }
}