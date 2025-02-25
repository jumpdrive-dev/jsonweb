mod models;
mod error;

pub use models::jwt::Jwt;
pub use models::jwt_claims::JwtClaims;
pub use models::jwt_header::JwtHeader;
pub use error::JwtError;

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use crate::algorithm::{HS256Algorithm, JwAlg};
    use crate::token::{Jwt, JwtClaims, JwtError};

    #[test]
    fn simple_jwt_token_can_be_generated() {
        let algorithm = HS256Algorithm::new("something".as_bytes())
            .unwrap();

        let token = Jwt::new("hello world".to_string())
            .into_token(&algorithm)
            .unwrap();

        let jwt = Jwt::<String>::verify(&token, &algorithm)
            .unwrap();
    }

    #[test]
    fn incorrect_signature_key() {
        let algorithm_1 = HS256Algorithm::new("something".as_bytes())
            .unwrap();

        let token = Jwt::new("hello world".to_string())
            .into_token(&algorithm_1)
            .unwrap();

        let algorithm_2 = HS256Algorithm::new("else".as_bytes())
            .unwrap();

        let jwt = Jwt::<String>::verify(&token, &algorithm_2);

        assert!(jwt.is_err());
    }

    // #[test]
    // fn iss_claim_is_checked_correctly() {
    //     let algorithm = test_alg();
    //
    //     let token = Jwt::default()
    //         .with_issuer("someone")
    //         .into_token(&algorithm)
    //         .unwrap();
    //
    //     // Checked claims are correct
    //     let correct_claims = JwtClaims::default()
    //         .with_issuer("someone");
    //
    //     Jwt::<Value>::verify(&token, &algorithm)
    //         .unwrap()
    //         .against(&correct_claims)
    //         .unwrap();
    //
    //     // Missing claim
    //     let token = Jwt::default()
    //         .into_token(&algorithm)
    //         .unwrap();
    //
    //     let error = Jwt::<Value>::verify(&token, &algorithm)
    //         .unwrap()
    //         .against(&correct_claims);
    //
    //     assert!(error.is_err());
    //
    //     // Incorrect value
    //     let incorrect_claims = JwtClaims::default()
    //         .with_issuer("else");
    //
    //     let error = Jwt::<Value>::verify(&token, &algorithm)
    //         .unwrap()
    //         .against(&incorrect_claims);
    //
    //     assert!(error.is_err());
    // }
}