use std::convert::Infallible;
use crate::algorithm::JwtAlg;

pub struct NoneAlgorithm;

impl JwtAlg for NoneAlgorithm {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "none"
    }

    fn sign(&self, _: &str) -> Vec<u8> {
        vec![]
    }

    fn verify(&self, _: &str, _: &[u8]) -> Result<bool, Self::Error> {
        Ok(true)
    }
}