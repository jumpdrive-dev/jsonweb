use std::convert::Infallible;
use crate::algorithm::JwAlg;

#[derive(Clone, Debug)]
pub struct NoneAlgorithm;

impl JwAlg for NoneAlgorithm {
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