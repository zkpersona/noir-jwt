pub type Header<let MaxHeaderLength: u32> = BoundedVec<u8, MaxHeaderLength>;
pub type Payload<let MaxPayloadLength: u32> = BoundedVec<u8, MaxPayloadLength>;
pub type Signature<T, let MaxSignatureLength: u32> = BoundedVec<T, MaxSignatureLength>;

pub type SecretKey<let MaxSecretKeyLength: u32> = BoundedVec<u8, MaxSecretKeyLength>;

pub type SigningInput<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = BoundedVec<u8, MaxHeaderLength + 1 + MaxPayloadLength>;
