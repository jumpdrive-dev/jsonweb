mod models;
mod error;

pub use models::jwt::Jwt;
pub use models::jwt_claims::JwtClaims;
pub use models::jwt_header::JwtHeader;
pub use error::JwtError;

#[cfg(test)]
mod tests {
    use crate::algorithm::{HS256Algorithm, JwAlg};
    use crate::token::Jwt;

    #[test]
    fn simple_jwt_token_can_be_generated() {
        let algorithm = HS256Algorithm::new("something".as_bytes())
            .unwrap();

        let token = Jwt::new("hello world".to_string())
            .into_token(&algorithm)
            .unwrap();

        let jwt = Jwt::<String>::check(&token, &algorithm)
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

        let jwt = Jwt::<String>::check(&token, &algorithm_2);

        assert!(jwt.is_err());
    }
}