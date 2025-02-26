use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::algorithm::JwAlg;
use crate::token::{JwtError, JwtHeader};
use crate::token::models::jwt_claims::JwtClaims;

pub struct Jwt<T>
where T : Serialize + for<'a> Deserialize<'a>,
{
    payload: T,
    claims: JwtClaims,
}

impl<T> Jwt<T>
where T : Serialize + for<'a> Deserialize<'a>,
{
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

        if self.claims.any_set() {
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

    pub fn verify<A: JwAlg>(token: &str, algorithm: &A) -> Result<Jwt<T>, JwtError>
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

    pub fn against(self, other: &JwtClaims) -> Result<Self, JwtError> {
        self.claims.verify(other)?;
        Ok(self)
    }

    pub fn guard(&self, other: &JwtClaims) -> Result<(), JwtError> {
        self.claims.verify(other)
    }

    pub fn with_claims(mut self, claims: JwtClaims) -> Self {
        self.claims = claims;
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.claims.iss = Some(issuer.into());
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.claims.sub = Some(subject.into());
        self
    }

    pub fn for_audience(mut self, audience: impl Into<String>) -> Self {
        self.claims.aud = Some(audience.into());
        self
    }

    pub fn expire_in(mut self, duration: Duration) -> Self {
        self.claims.exp = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    pub fn valid_after(mut self, duration: Duration) -> Self {
        self.claims.nbf = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.claims.jti = Some(jti.into());
        self
    }

    pub fn payload(&self) -> &T {
        &self.payload
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
