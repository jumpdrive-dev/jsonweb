use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwtError {
    SerdeJson(#[from] serde_json::Error),
    DecodeError(#[from] base64::DecodeError),

    #[error("JWT token does not specify the correct `alg` in the header")]
    AlgMismatch,

    #[error("No header")]
    NoHeader,

    #[error("No payload")]
    NoPayload,

    #[error("No signature")]
    NoSignature,

    #[error("Invalid signature")]
    InvalidSignature,
}