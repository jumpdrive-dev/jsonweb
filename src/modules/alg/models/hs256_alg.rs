use hmac::{Hmac, Mac};
use hmac::digest::InvalidLength;
use sha2::Sha256;
use crate::modules::alg::JwtAlg;

pub struct HS256Alg {
    inner: Hmac<Sha256>,
}

impl HS256Alg {
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(HS256Alg {
            inner: Hmac::<Sha256>::new_from_slice(key)?
        })
    }
}

impl JwtAlg for HS256Alg {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        let mut inner = self.inner.clone();
        inner.update(payload.as_bytes());

        inner.finalize().into_bytes().to_vec()
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> bool {
        let mut inner = self.inner.clone();
        inner.update(payload.as_bytes());

        let finalized = inner.finalize()
            .into_bytes()
            .to_vec();

        signature == finalized
    }
}