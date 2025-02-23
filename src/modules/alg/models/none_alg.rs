use crate::modules::alg::JwtAlg;

pub struct NoneAlg;

impl JwtAlg for NoneAlg {
    fn alg() -> impl AsRef<str> {
        "none"
    }

    fn sign(&self, _: &str) -> Vec<u8> {
        vec![]
    }

    fn verify(&self, _: &str, _: &[u8]) -> bool {
        true
    }
}