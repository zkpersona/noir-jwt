use noir_base64::BASE64_URL_DECODER::decode_var;
use noir_hmac::hmac_sha256::hmac_sha256;

use super::types::{JWT, JWTActions, SecretKey, SigningInput};

pub fn verify_jwt_h256<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32, let SecretKeyLength: u32>(
    jwt: JWT<MaxHeaderLength, MaxPayloadLength, MaxSignatureLength>,
    secret_key: SecretKey<SecretKeyLength>,
) -> bool {
    let decoded_signature = decode_var(jwt.signature());

    let mut signing_input: SigningInput<MaxHeaderLength, MaxPayloadLength> = BoundedVec::new();
    signing_input.extend_from_bounded_vec(jwt.header());
    signing_input.push(46); // .
    signing_input.extend_from_bounded_vec(jwt.payload());

    let hmac_signature = hmac_sha256(secret_key, signing_input);

    hmac_signature == decoded_signature.storage()
}

#[test]
fn test_verify_jwt() {
    let header: BoundedVec<u8, 36> =
        BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());
    let payload: BoundedVec<u8, 234> = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ"
            .as_bytes(),
    );
    let signature: BoundedVec<u8, 43> =
        BoundedVec::from_array("Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key: BoundedVec<u8, 10> = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt_h256(jwt, secret_key);
    assert(res);
}
