use base64::BASE64_URL_DECODER::decode_var;
use json_parser::JSON1kb;
use noir_jwt::JWT_H256 as JWT;
use noir_jwt::types::{Payload, SecretKey};

pub global MAX_HEADER_LENGTH: u32 = 64;
pub global MAX_PAYLOAD_LENGTH: u32 = 256;
pub global MAX_SIGNATURE_LENGTH: u32 = 43;

pub global MAX_SECRET_KEY_LENGTH: u32 = 64;

unconstrained fn parse_json(payload: Payload<MAX_PAYLOAD_LENGTH>) -> JSON1kb {
    let mut decoded: BoundedVec<u8, (MAX_PAYLOAD_LENGTH * 3) / 4> = decode_var(payload);
    for _i in decoded.len()..decoded.max_len() {
        decoded.push(32); // Whitespace character
    }
    let json: JSON1kb = JSON1kb::parse_json(decoded.storage());
    json
}

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH, MAX_SIGNATURE_LENGTH>,
    secret_key: SecretKey<MAX_SECRET_KEY_LENGTH>,
    expected_email: BoundedVec<u8, 64>,
) -> pub bool {
    let verified = jwt.verify(secret_key);

    assert(verified);

    /// Safety: Payload is already verified
    let json: JSON1kb = unsafe { parse_json(jwt.payload) };

    let email: BoundedVec<u8, 64> = json.get_string_unchecked("sub".as_bytes());

    println(expected_email);
    println(email);

    email == expected_email
}
