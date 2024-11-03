use noir_jwt::{types::{JWT, SecretKey}, verify_jwt};

fn main(
    jwt_string: BoundedVec<u8, 1133>,
    secret_key: SecretKey,
    header_length: u32,
    payload_length: u32,
    signature_length: u32,
) -> pub bool {
    let jwt: JWT = JWT::from_vec(jwt_string, header_length, payload_length, signature_length);
    let result: bool = verify_jwt(jwt, secret_key);
    result
}
