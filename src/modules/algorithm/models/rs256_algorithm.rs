pub use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use crate::algorithm::JwtAlg;

pub struct RS256Algorithm {
    inner: SigningKey<Sha256>
}

impl RS256Algorithm {
    pub fn new(key: SigningKey<Sha256>) -> Self {
        RS256Algorithm {
            inner: key,
        }
    }
}

impl JwtAlg for RS256Algorithm {
    type Error = rsa::signature::Error;

    fn alg() -> impl AsRef<str> {
        "RS256"
    }

    fn sign(&self, payload: &str) -> Vec<u8> {
        self.inner.sign(payload.as_bytes()).to_vec()
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature)?;

        Ok(self.inner.verifying_key().verify(payload.as_bytes(), &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    pub use rsa::RsaPrivateKey;
    use crate::algorithm::{JwtAlg, RS256Algorithm};

    #[test]
    fn rs256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";

        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../../test-files/rs256.key")).unwrap();
        let signing_key = SigningKey::new(private_key);
        let alg = RS256Algorithm::new(signing_key);

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "ptH8Vc-nhm4gTl7HqaictKQyK3fxiJmSfyu-ouYlmIfyyRBIYw2tUdKxIsxgYMPXC7oV0-ShYtlUm73-q2buLoYGc52d-03RQghcVvZrag2nQCKsBBmTXFUADEaVopO65aND5h7Uif_1aQJXmX-40-V5te0fT3WSyU_1oKayxpi53_c7RXD7gDlWSXAZFDNhPopcRnq2_4FQylzFf4qbwtGWUNdJA4SGOikr1lsTrQRPGXLNXREG0PWv9GFoobQDTj9DWBG4B_cCAUVAjYUCx8BbgHSY9jeiYE_FbDykW0tRSA3XAYpf1QCPZmrCPButUixWY03FTTxsQxlJuY8r-w");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }
}