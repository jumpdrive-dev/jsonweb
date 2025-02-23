use std::borrow::Cow;
use serde::{Deserialize, Serialize};

/// The header of a JWT token. Used to identify what signing algorithm is used and what type of
/// token it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtHeader<'a, C = String> {
    /// The algorithm of that the server used to sign the JWT token. Possible values can be found in
    /// [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3).
    pub alg: Cow<'a, str>,

    /// The type of token. This is probably here for future-proofing as currently it should always
    /// be "JWT".
    pub typ: Cow<'a, str>,

    /// This is usually used when using nested JWT tokens, but here it's used to differentiate
    /// between access tokens and refresh tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<C>,
}