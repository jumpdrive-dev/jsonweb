mod modules;

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use crate::modules::alg::{HS256Alg, NoneAlg};
    use crate::modules::jwt::{Jwt, JwtError};

    #[cfg(feature = "hs256")]
    #[test]
    fn hs256_token_is_generated_correctly() {
        let payload = json!({
            "hj": true
        });

        let jwt = Jwt::new(payload.clone());

        let alg = HS256Alg::new("qwed".as_ref()).unwrap();
        let token = jwt.into_token(&alg).unwrap();

        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0.AeQU9YyCnBlrJwtd1PVmGW3apn6kQ6yi_U4qT9o0vkQ");

        let jwt = Jwt::<Value>::verify(&token, &alg).unwrap();
        assert_eq!(jwt.payload(), &payload);

        let incorrect_alg = HS256Alg::new("??".as_ref()).unwrap();
        let jwt = Jwt::<Value>::verify(&token, &incorrect_alg);

        assert!(jwt.is_err());
    }
}