pub mod types;
pub mod h256;
pub mod r256;
pub mod constants;

mod benchmarks;

use crate::constants::{KEY_LIMBS_1024, KEY_LIMBS_2048};
use crate::types::{Header, Payload, Signature};

pub struct JWT<T, let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> {
    pub header: Header<MaxHeaderLength>,
    pub payload: Payload<MaxPayloadLength>,
    pub signature: Signature<T, MaxSignatureLength>,
}

pub struct RSAPubkey<let KEY_LIMBS: u32, let ModBits: u32> {
    pub modulus: [Field; KEY_LIMBS],
    pub redc: [Field; KEY_LIMBS],
}

impl<T, let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> JWT<T, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> {
    pub fn new(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<T, MaxSignatureLength>,
    ) -> Self {
        Self { header, payload, signature }
    }
}

pub type JWT_H256<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> = JWT<u8, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength>;

pub type JWT_R256_1024<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = JWT<Field, MaxHeaderLength, MaxPayloadLength, KEY_LIMBS_1024>;

pub type JWT_R256_2048<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = JWT<Field, MaxHeaderLength, MaxPayloadLength, KEY_LIMBS_2048>;
