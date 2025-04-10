pub type Header<let MaxHeaderLength: u32> = BoundedVec<u8, MaxHeaderLength>;
pub type Payload<let MaxPayloadLength: u32> = BoundedVec<u8, MaxPayloadLength>;
pub type Signature<let MaxSignatureLength: u32> = BoundedVec<u8, MaxSignatureLength>;

pub type SecretKey<let MaxSecretKeyLength: u32> = BoundedVec<u8, MaxSecretKeyLength>;

pub type SigningInput<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = BoundedVec<u8, MaxHeaderLength + 1 + MaxPayloadLength>;

pub struct JWT<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> {
    header: Header<MaxHeaderLength>,
    payload: Payload<MaxPayloadLength>,
    signature: Signature<MaxSignatureLength>,
}

pub trait JWTActions<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> {
    fn new(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<MaxSignatureLength>,
    ) -> Self;

    fn header(self) -> Header<MaxHeaderLength>;
    fn payload(self) -> Payload<MaxPayloadLength>;
    fn signature(self) -> Signature<MaxSignatureLength>;
}

impl<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> JWTActions<MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> for JWT<MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> {
    fn new(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<MaxSignatureLength>,
    ) -> Self {
        Self { header, payload, signature }
    }

    fn header(self) -> Header<MaxHeaderLength> {
        self.header
    }

    fn payload(self) -> Payload<MaxPayloadLength> {
        self.payload
    }

    fn signature(self) -> Signature<MaxSignatureLength> {
        self.signature
    }
}
