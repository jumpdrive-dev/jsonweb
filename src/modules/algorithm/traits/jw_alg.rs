pub trait JwAlg {
    type Error: std::error::Error;

    fn alg() -> impl AsRef<str>;
    fn sign(&self, payload: &str) -> Vec<u8>;
    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error>;
}