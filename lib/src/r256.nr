use crate::JWT;
use crate::types::{Header, Payload, Signature};
use super::{RSAPubkey, types::SigningInput};

use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;
use std::hash::sha256::sha256_var;

impl<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let LimbsLength: u32> JWT<Field, MaxHeaderLength, MaxPayloadLength, LimbsLength> {
    pub fn new(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<Field, LimbsLength>,
    ) -> Self {
        Self { header, payload, signature }
    }

    pub fn get_header(self) -> Header<MaxHeaderLength> {
        self.header
    }

    pub fn get_payload(self) -> Payload<MaxPayloadLength> {
        self.payload
    }

    pub fn get_signature(self) -> Signature<Field, LimbsLength> {
        self.signature
    }

    pub fn verify<let ModBits: u32>(self, pub_key: RSAPubkey<LimbsLength>, exponent: u32) -> bool {
        let mut signing_input: SigningInput<MaxHeaderLength, MaxPayloadLength> = BoundedVec::new();
        signing_input.extend_from_bounded_vec(self.header);
        signing_input.push(46); // .
        signing_input.extend_from_bounded_vec(self.payload);

        let data_hash = sha256_var(signing_input.storage(), signing_input.len() as u64);

        let params: BigNumParams<LimbsLength, ModBits> =
            BigNumParams::new(false, pub_key.modulus, pub_key.redc);

        let signature: RuntimeBigNum<LimbsLength, ModBits> =
            RuntimeBigNum::from_array(params, self.signature.storage());

        verify_sha256_pkcs1v15(data_hash, signature, exponent)
    }
}
