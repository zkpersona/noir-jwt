use crate::constants::{
    MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH, MAX_SIGNATURE_LENGTH, MAX_SECRET_LENGTH,
};

pub type Header = BoundedVec<u8, MAX_HEADER_LENGTH>;
pub type Payload = BoundedVec<u8, MAX_PAYLOAD_LENGTH>;
pub type Signature = BoundedVec<u8, MAX_SIGNATURE_LENGTH>;

pub type SigningInput = BoundedVec<u8, MAX_HEADER_LENGTH + 1 + MAX_PAYLOAD_LENGTH>;

pub type SecretKey = BoundedVec<u8, MAX_SECRET_LENGTH>;

pub struct JWT {
    pub header: Header,
    pub payload: Payload,
    pub signature: Signature,
}

pub trait JWTActions {
    fn new(header: Header, payload: Payload, signature: Signature) -> Self;
    fn from_vec<let M: u32>(
        vec: BoundedVec<u8, M>,
        header_length: u32,
        payload_length: u32,
        signature_length: u32,
    ) -> JWT;
}

impl JWTActions for JWT {
    fn new(header: Header, payload: Payload, signature: Signature) -> JWT {
        JWT { header, payload, signature }
    }
    fn from_vec<let M: u32>(
        vec: BoundedVec<u8, M>,
        header_length: u32,
        payload_length: u32,
        signature_length: u32,
    ) -> JWT {
        let mut header = BoundedVec::new();
        let mut payload = BoundedVec::new();
        let mut signature = BoundedVec::new();
        for i in 0..MAX_HEADER_LENGTH + MAX_PAYLOAD_LENGTH + MAX_SIGNATURE_LENGTH + 2 {
            if (i >= 0 & i < header_length) {
                header.push(vec.get(i));
            } else if (i > header_length & i <= header_length + payload_length) {
                payload.push(vec.get(i));
            } else if (
                i > header_length + payload_length + 1
                    & i < header_length + payload_length + signature_length + 2
            ) {
                signature.push(vec.get(i));
            }
        }

        JWT::new(header, payload, signature)
    }
}
