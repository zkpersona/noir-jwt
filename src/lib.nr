pub mod utils;

use noir_base64_lib::decode::base64_url_decode_var;
use noir_hmac::hmac_sha256_var;
use utils::split_jwt_var;

/// Verifies a JSON Web Token (JWT) using the provided secret key.
///
/// # Parameters
///
/// - `jwt`: A byte array representing the JWT to be verified.
/// - `secret_key`: A byte array representing the secret key used for verification.
///
/// # Returns
///
/// - `bool`: Returns `true` if the JWT is successfully verified, otherwise returns `false`.
///
/// # Type Parameters
///
/// - `M`: The length of the JWT byte array.
/// - `N`: The length of the secret key byte array.
///
pub fn verify_jwt<let M: u32, let N: u32>(jwt: [u8; M], secret_key: [u8; N]) -> bool {
    let mut vec_jwt: Vec<u8> = Vec::new();
    for i in 0..jwt.len() {
        vec_jwt.push(jwt[i]);
    }
    let mut vec_secret_key: Vec<u8> = Vec::new();
    for i in 0..secret_key.len() {
        vec_secret_key.push(secret_key[i]);
    }
    verify_jwt_var(vec_jwt, vec_secret_key)
}

/// Verifies a JSON Web Token (JWT) using the provided secret key.
///
/// # Arguments
///
/// * `jwt` - A vector of bytes representing the JWT to be verified.
/// * `secret_key` - A vector of bytes representing the secret key used for verification.
///
/// # Returns
///
/// * `bool` - Returns `true` if the JWT is successfully verified, otherwise returns `false`.
///
/// # Steps
///
/// 1. Splits the JWT into its constituent parts: header, payload, and signature.
/// 2. Base64 decodes the signature.
/// 3. Creates the signing input by concatenating the encoded header and payload with a period (`.`) separator.
/// 4. Computes the HMAC of the signing input using the provided secret key.
/// 5. Compares the computed HMAC signature with the decoded signature from the JWT.
///
pub fn verify_jwt_var(jwt: Vec<u8>, secret_key: Vec<u8>) -> bool {
    // Step 1: Split the JWT (header.payload.signature)
    let (encoded_header,encoded_payload, encoded_signature) = split_jwt_var(jwt, 46); // 46 is the ASCII code for .

    // Step 2: Base64 decode the Signature
    let decoded_signature: Vec<u8> = base64_url_decode_var(encoded_signature);

    // Step 3: Create the signing input
    let mut signing_input: Vec<u8> = Vec::new();
    for i in 0..encoded_header.len() {
        signing_input.push(encoded_header.get(i));
    }
    signing_input.push(46); // .
    for i in 0..encoded_payload.len() {
        signing_input.push(encoded_payload.get(i));
    }

    // Step 4: Compute HMAC of the signing input and Secret Key
    let hmac_signature: Vec<u8> = Vec::from_slice(hmac_sha256_var(secret_key, signing_input, signing_input.len()));

    hmac_signature.eq(decoded_signature)
}

#[test]
fn test_verify_jwt() {
    let jwt: [u8; 315] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ.Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes();

    let secret_key: [u8; 10] = "secret_key".as_bytes();

    let res: bool = verify_jwt(jwt, secret_key);

    assert(res);
}

#[test]
fn test_verify_jwt_var() {
    let jwt: Vec<u8> = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ.Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes_vec();

    let secret_key: Vec<u8> = "secret_key".as_bytes_vec();

    let res: bool = verify_jwt_var(jwt, secret_key);

    assert(res);
}
