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
fn test_verify_jwt_h256() {
    let header: BoundedVec<u8, 64> =
        BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());

    // {
    //     "iss": "Online JWT Builder",
    //     "iat": 1744254756,
    //     "exp": 1775790756,
    //     "aud": "www.example.com",
    //     "sub": "jdoe@example.com",
    //     "GivenName": "John",
    //     "Surname": "Doe",
    //     "Email": "jdoe@example.com"
    // }
    let payload: BoundedVec<u8, 256> = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDQyNTQ3NTYsImV4cCI6MTc3NTc5MDc1NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoiamRvZUBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG4iLCJTdXJuYW1lIjoiRG9lIiwiRW1haWwiOiJqZG9lQGV4YW1wbGUuY29tIn0"
            .as_bytes(),
    );
    let signature: BoundedVec<u8, 64> =
        BoundedVec::from_array("V76__Az9KeQNpsT7cezbve34B1Mx6OriMLto3vSCeI8".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key: BoundedVec<u8, 10> = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt_h256(jwt, secret_key);
    assert(res);
}
