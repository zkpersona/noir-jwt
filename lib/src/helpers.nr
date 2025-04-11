use super::types::{Header, Payload, SigningInput};

/// Constructs the signing input for JWT verification by concatenating header and payload.
///
/// This function creates the input that will be used for signature verification by:
/// 1. Concatenating the JWT header and payload
/// 2. Separating them with a period (.) character as per JWT specification
///
/// # Arguments
/// * `header` - The JWT header component
/// * `payload` - The JWT payload component
///
/// # Returns
/// Returns a `SigningInput` containing the concatenated header and payload with a period separator.
///
/// # Safety
/// This function is marked as `unconstrained` because it performs array operations
/// that are safe within the Noir circuit context. The function uses fixed-size arrays
/// and bounds checking to prevent buffer overflows.
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
