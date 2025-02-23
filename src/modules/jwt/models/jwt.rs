use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use crate::modules::alg::JwtAlg;
use crate::modules::jwt::error::JwtError;
use crate::modules::jwt::models::jwt_header::JwtHeader;

pub struct Jwt<T, C = ()>
where T : Serialize + for<'a> Deserialize<'a>,
      C : Serialize + for<'a> Deserialize<'a>,
{
    cty: Option<C>,
    payload: T,
}

impl<T, C> Jwt<T, C>
where T : Serialize + for<'a> Deserialize<'a>,
      C : Serialize + for<'a> Deserialize<'a>,
{
    pub fn into_token<A: JwtAlg>(self, algorithm: &A) -> Result<String, JwtError> {
        let alg_ref = A::alg();

        let header = JwtHeader {
            alg: Cow::Borrowed(alg_ref.as_ref()),
            typ: Cow::Borrowed("JWT"),
            cty: self.cty,
        };

        let header_bytes = serde_json::to_vec(&header)?;
        let header_string = BASE64_URL_SAFE_NO_PAD.encode(&header_bytes);

        let payload_bytes = serde_json::to_vec(&self.payload)?;
        let payload_string = BASE64_URL_SAFE_NO_PAD.encode(&payload_bytes);

        let target = format!("{}.{}", header_string, payload_string);
        let signature = algorithm.sign(&target);

        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", target, signature_string))
    }

    pub fn verify<A: JwtAlg>(token: &str, algorithm: &A) -> Result<Jwt<T, C>, JwtError>
    where <A as JwtAlg>::Error: 'static
    {
        let mut parts = token.split('.');

        let header_string = parts.next().ok_or(JwtError::NoHeader)?;
        let header_bytes = BASE64_URL_SAFE_NO_PAD.decode(header_string.as_bytes())?;
        let header: JwtHeader<C> = serde_json::from_slice(&header_bytes)?;

        if header.alg != Cow::Borrowed(A::alg().as_ref()) {
            return Err(JwtError::AlgMismatch);
        }

        let payload_string = parts.next().ok_or(JwtError::NoPayload)?;
        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_string.as_bytes())?;
        let payload: T = serde_json::from_slice(&payload_bytes)?;

        let signature_string = parts.next().ok_or(JwtError::NoSignature)?;
        let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature_string.as_bytes())?;

        let target = format!("{}.{}", header_string, payload_string);
        let verified = algorithm.verify(&target, &signature_bytes)
            .map_err(|e| JwtError::AlgError(Box::new(e)))?;

        if !verified {
            return Err(JwtError::InvalidSignature);
        }

        Ok(Jwt {
            cty: header.cty,
            payload,
        })
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }
}

impl<T> Jwt<T, ()>
where T : Serialize + for<'a> Deserialize<'a>
{
    pub fn new(payload: T) -> Self {
        Jwt {
            payload,
            cty: None,
        }
    }
}

// impl<T, C> Debug for Jwt<T, C>
// where T : Serialize + for<'a> Deserialize<'a>,
//     C : Serialize + for<'a> Deserialize<'a>,
// {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "JWT {{}}")
//     }
// }

// impl<T, C> Default for Jwt<T, C>
// where T : Serialize + for<'a> Deserialize<'a>,
//     C : Serialize + for<'a> Deserialize<'a>,
// {
//     fn default() -> Jwt<(), ()> {
//         Jwt {
//             cty: None,
//             payload: (),
//         }
//     }
// }
