use super::types::{Header, Payload, SigningInput};

pub unconstrained fn build_signing_input<let MaxHeaderLength: u32, let MaxPayloadLength: u32>(
    header: Header<MaxHeaderLength>,
    payload: Payload<MaxPayloadLength>,
) -> SigningInput<MaxHeaderLength, MaxPayloadLength> {
    let mut signing_input: SigningInput<MaxHeaderLength, MaxPayloadLength> = BoundedVec::new();
    signing_input.extend_from_bounded_vec(header);
    signing_input.push(46); // .
    signing_input.extend_from_bounded_vec(payload);
    signing_input
}
