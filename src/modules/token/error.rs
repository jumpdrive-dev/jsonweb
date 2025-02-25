use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwtError {
    SerdeJson(#[from] serde_json::Error),
    DecodeError(#[from] base64::DecodeError),
    AlgError(Box<dyn std::error::Error>),

    #[error("When setting claims, the payload must serialize to a JSON object")]
    PayloadNotAnObject,

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

    #[error("`iss` was not found in claims")]
    MissingIssClaim,

    #[error("`iss` claim was not correct")]
    MismatchedIssClaim,

    #[error("`aud` was not found in claims")]
    MissingAudClaim,

    #[error("`aud` claim was not correct")]
    MismatchedAudClaim,

    #[error("`nbf` was not found in claims")]
    MissingNbfClaim,

    #[error("`nbf` claim was not correct")]
    MismatchedNbfClaim,

    #[error("`exp` was not found in claims")]
    MissingExpClaim,

    #[error("`exp` claim was not correct")]
    MismatchedExpClaim,

    #[error("`jwi` was not found in claims")]
    MissingJtiClaim,

    #[error("`jwi` claim was not correct")]
    MismatchedJtiClaim,
}