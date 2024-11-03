pub mod types;
pub mod constants;

use noir_hmac::hmac_sha256;
use types::{JWT, SecretKey, SigningInput};
use noir_base64::BASE64_URL_DECODER;

pub fn verify_jwt(jwt: JWT, secret_key: SecretKey) -> bool {
    // Step 1: Decode Signature
    let decoded_signature = BASE64_URL_DECODER.decode(jwt.signature.storage());

    // Step 2: Create the signing input
    let mut signing_input: SigningInput = BoundedVec::new();
    signing_input.extend_from_bounded_vec(jwt.header);
    signing_input.push(46); // .
    signing_input.extend_from_bounded_vec(jwt.payload);

    // Step 3: Compute HMAC of the signing input and Secret Key
    let hmac_signature = hmac_sha256(secret_key, signing_input);

    hmac_signature == decoded_signature
}

#[test]
fn test_verify_jwt() {
    let header = BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());
    let payload = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ"
            .as_bytes(),
    );
    let signature =
        BoundedVec::from_array("Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt(jwt, secret_key);
    assert(res);
}

#[test]
fn test_verify_jwt_from_string() {
    let vec: BoundedVec<u8, 1133> = BoundedVec::from_array(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ.Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI"
            .as_bytes(),
    );

    let jwt = JWT::from_vec(vec, 36, 234, 43);

    let secret_key = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt(jwt, secret_key);
    assert(res);
}
