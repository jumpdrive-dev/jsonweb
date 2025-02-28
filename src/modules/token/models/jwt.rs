use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::algorithm::JwAlg;
use crate::token::{JwtError, JwtHeader};
use crate::token::models::jwt_claims::JwtClaims;

/// Representation of a (decoded) JWT token.
pub struct Jwt<T>
where T : Serialize + for<'a> Deserialize<'a>,
{
    payload: T,
    claims: JwtClaims,
}

impl<T> Jwt<T>
where T : Serialize + for<'a> Deserialize<'a>,
{
    /// Takes the JWT instance, signs it, and returns the string representation for the token.
    pub fn into_token<A: JwAlg>(self, algorithm: &A) -> Result<String, JwtError> {
        let alg_ref = A::alg();

        let header = JwtHeader {
            alg: Cow::Borrowed(alg_ref.as_ref()),
            typ: Cow::Borrowed("JWT"),
            cty: None,
        };

        let header_bytes = serde_json::to_vec(&header)?;
        let header_string = BASE64_URL_SAFE_NO_PAD.encode(&header_bytes);

        let mut json_value = serde_json::to_value(&self.payload)?;

        if !self.claims.is_empty() {
            let Some(payload_object) = json_value.as_object_mut() else {
                return Err(JwtError::PayloadNotAnObject);
            };

            let mut claims_value = serde_json::to_value(&self.claims)?;
            let claims_object = claims_value
                .as_object_mut()
                .expect("This should always result in an object");

            payload_object.append(claims_object);
        }

        let bytes = serde_json::to_vec(&json_value)?;
        let payload_string = BASE64_URL_SAFE_NO_PAD.encode(&bytes);

        let target = format!("{}.{}", header_string, payload_string);
        let signature = algorithm.sign(&target);

        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", target, signature_string))
    }

    /// Decodes and verifies the given string token with the given algorithm. Returns a JWT token
    /// instance with the expected payload. Note that this does not check any claims. To verify
    /// basic expiry claims you can use [Jwt::verify_now] or you can further verify the token using
    /// [Jwt::against] or [Jwt::guard].
    pub fn check<A: JwAlg>(token: &str, algorithm: &A) -> Result<Jwt<T>, JwtError>
    where <A as JwAlg>::Error: 'static
    {
        let mut parts = token.split('.');

        let header_string = parts.next().ok_or(JwtError::NoHeader)?;
        let header_bytes = BASE64_URL_SAFE_NO_PAD.decode(header_string.as_bytes())?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)?;

        if header.alg != Cow::Borrowed(A::alg().as_ref()) {
            return Err(JwtError::AlgMismatch);
        }

        let payload_string = parts.next().ok_or(JwtError::NoPayload)?;
        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_string.as_bytes())?;
        let payload: T = serde_json::from_slice(&payload_bytes)?;

        // Unwrap or default as these would then be checked later.
        let claims = serde_json::from_slice(&payload_bytes)
            .unwrap_or_default();

        let signature_string = parts.next().ok_or(JwtError::NoSignature)?;
        let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature_string.as_bytes())?;

        let target = format!("{}.{}", header_string, payload_string);
        let verified = algorithm.verify(&target, &signature_bytes)
            .map_err(|e| JwtError::AlgError(Box::new(e)))?;

        if !verified {
            return Err(JwtError::InvalidSignature);
        }

        Ok(Jwt {
            payload,
            claims,
        })
    }

    /// Largely the same as [Jwt::check], but also verifies basic expiry claims. You can further
    /// verify the token using [Jwt::against] or [Jwt::guard].
    pub fn verify_now<A: JwAlg>(token: &str, algorithm: &A) -> Result<Jwt<T>, JwtError>
    where <A as JwAlg>::Error: 'static
    {
        let jwt = Jwt::<T>::check(token, algorithm)?
            .against(&JwtClaims::now())?;

        Ok(jwt)
    }

    /// Verifies the token against the given claims and returns `Self`. To verify claims on a
    /// reference use [Jwt::guard].
    pub fn against(self, other: &JwtClaims) -> Result<Self, JwtError> {
        self.claims.verify(other)?;
        Ok(self)
    }

    /// Verifies the token against the given claims. To verify claims 'in-line' use [Jwt::against].
    pub fn guard(&self, other: &JwtClaims) -> Result<(), JwtError> {
        self.claims.verify(other)
    }

    /// Overwrites the current claims with the given claims.
    pub fn with_claims(mut self, claims: JwtClaims) -> Self {
        self.claims = claims;
        self
    }

    /// Sets the `iss` claim on the JWT.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.claims.iss = Some(issuer.into());
        self
    }

    /// Sets the `sub` claim on the JWT.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.claims.sub = Some(subject.into());
        self
    }

    /// Sets the `aud` claim on the JWT.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.claims.aud = Some(audience.into());
        self
    }

    /// Sets the `iat` claim on the JWT.
    pub fn issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.claims.iat = Some(issued_at.timestamp());
        self
    }

    /// Sets the `iat` claim on the JWT.
    pub fn issued_at_timestamp(mut self, timestamp: i64) -> Self {
        self.claims.iat = Some(timestamp);
        self
    }

    /// Sets the `exp` claim on the JWT.
    pub fn expire_in(mut self, duration: Duration) -> Self {
        self.claims.exp = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    /// Sets the `exp` claim on the JWT.
    pub fn expire_in_seconds(mut self, seconds: i64) -> Self {
        self.claims.exp = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// Sets the `nbf` claim on the JWT.
    pub fn not_before(mut self, duration: Duration) -> Self {
        self.claims.nbf = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    /// Sets the `nbf` claim on the JWT.
    pub fn not_before_seconds(mut self, seconds: i64) -> Self {
        self.claims.nbf = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// Sets the `jti` claim on the JWT.
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.claims.jti = Some(jti.into());
        self
    }

    pub fn with_merge(mut self, other: &JwtClaims) -> Self {
        self.claims = self.claims.with_merge(other);
        self
    }

    /// Returns a reference to the payload for this token.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Consumes the token and returns the payload.
    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl Default for Jwt<Value> {
    fn default() -> Self {
        Jwt::new(json!({}))
    }
}

impl<T> Debug for Jwt<T>
where T : Serialize + for<'a> Deserialize<'a> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Jwt {{ claims: {:?}, payload: {:?} }}", self.claims, self.payload)
    }
}

impl<T> Jwt<T>
where T : Serialize + for<'a> Deserialize<'a>
{
    pub fn new(payload: T) -> Self {
        Jwt {
            payload,
            claims: JwtClaims::default(),
        }
    }
}
