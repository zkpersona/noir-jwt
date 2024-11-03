use noir_jwt::{types::{JWT, SecretKey}, verify_jwt};

fn main(jwt: JWT, secret_key: SecretKey) -> pub bool {
    let result = verify_jwt(jwt, secret_key);
    result
}
