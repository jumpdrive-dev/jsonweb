use std::convert::Infallible;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use crate::algorithm::JwtAlg;

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

impl JwtAlg for ES256Algorithm {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "ES256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        self.inner.sign(payload.as_bytes())
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        todo!()
    }
}