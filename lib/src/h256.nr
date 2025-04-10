use noir_base64::BASE64_URL_DECODER::decode_var;
use noir_hmac::hmac_sha256::hmac_sha256;

use crate::JWT;
use crate::types::{Header, Payload, SecretKey, Signature, SigningInput};

impl<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> JWT<u8, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> {
    pub fn new(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<u8, MaxSignatureLength>,
    ) -> Self {
        Self { header, payload, signature }
    }

    pub fn get_header(self) -> Header<MaxHeaderLength> {
        self.header
    }

    pub fn get_payload(self) -> Payload<MaxPayloadLength> {
        self.payload
    }

    pub fn get_signature(self) -> Signature<u8, MaxSignatureLength> {
        self.signature
    }

    pub fn verify<let MaxSecretKeyLength: u32>(
        self,
        secret_key: SecretKey<MaxSecretKeyLength>,
    ) -> bool {
        let decoded_signature = decode_var(self.signature);

        let mut signing_input: SigningInput<MaxHeaderLength, MaxPayloadLength> = BoundedVec::new();
        signing_input.extend_from_bounded_vec(self.header);
        signing_input.push(46); // .
        signing_input.extend_from_bounded_vec(self.payload);

        let hmac_signature = hmac_sha256(secret_key, signing_input);

        hmac_signature == decoded_signature.storage()
    }
}

#[test]
pub fn test_verify_jwt_h256() {
    let header: BoundedVec<u8, 64> =
        BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());

    let payload: BoundedVec<u8, 256> = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDQyNTQ3NTYsImV4cCI6MTc3NTc5MDc1NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoiamRvZUBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG4iLCJTdXJuYW1lIjoiRG9lIiwiRW1haWwiOiJqZG9lQGV4YW1wbGUuY29tIn0"
            .as_bytes(),
    );
    let signature: BoundedVec<u8, 64> =
        BoundedVec::from_array("V76__Az9KeQNpsT7cezbve34B1Mx6OriMLto3vSCeI8".as_bytes());

    let secret_key: BoundedVec<u8, 64> = BoundedVec::from_array("secret_key".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    assert(jwt.verify(secret_key));
}
