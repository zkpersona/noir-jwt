use noir_jwt::JWT_H256 as JWT;
use noir_jwt::types::SecretKey;

pub global MAX_HEADER_LENGTH: u32 = 64;
pub global MAX_PAYLOAD_LENGTH: u32 = 256;
pub global MAX_SIGNATURE_LENGTH: u32 = 43;

pub global MAX_SECRET_KEY_LENGTH: u32 = 64;

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH, MAX_SIGNATURE_LENGTH>,
    secret_key: SecretKey<MAX_SECRET_KEY_LENGTH>,
) -> pub bool {
    jwt.verify(secret_key)
}
