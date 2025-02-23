use std::convert::Infallible;
use crate::modules::alg::JwtAlg;

pub struct NoneAlg;

impl JwtAlg for NoneAlg {
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