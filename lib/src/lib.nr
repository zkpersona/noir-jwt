pub mod types;
pub mod h256;
pub mod r256;
pub mod constants;
pub mod helpers;

mod benchmarks;

use crate::constants::KEY_LIMBS_2048;
use crate::types::{Header, Payload, Signature};

/// Core JWT structure representing a JSON Web Token with generic signature type.
///
/// This structure represents a complete JWT with its three main components:
/// header, payload, and signature. The signature type is generic to support
/// different signing algorithms (e.g., HMAC-SHA256 or RSA-SHA256).
///
/// # Generic Parameters
/// * `T` - The type of elements in the signature (e.g., `u8` for HMAC, `Field` for RSA)
/// * `MaxHeaderLength` - Maximum allowed length of the header in bytes
/// * `MaxPayloadLength` - Maximum allowed length of the payload in bytes
/// * `MaxSignatureLength` - Maximum allowed length of the signature
///
/// # Fields
/// * `header` - The JWT header containing metadata and algorithm information
/// * `payload` - The JWT payload containing the claims
/// * `signature` - The JWT signature for verification
pub struct JWT<T, let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> {
    pub header: Header<MaxHeaderLength>,
    pub payload: Payload<MaxPayloadLength>,
    pub signature: Signature<T, MaxSignatureLength>,
}

/// RSA public key structure for RS256 signature verification.
///
/// This structure represents an RSA public key with its modulus and Montgomery
/// reduction parameters. The key size is determined by the number of limbs,
/// where each limb represents a chunk of the key.
///
/// # Generic Parameters
/// * `KEY_LIMBS` - Number of limbs required to represent the RSA key
///
/// # Fields
/// * `modulus` - The RSA modulus (n)
/// * `redc` - Montgomery reduction parameters for efficient modular arithmetic
pub struct RSAPubkey<let KEY_LIMBS: u32> {
    pub modulus: [Field; KEY_LIMBS],
    pub redc: [Field; KEY_LIMBS],
}

impl<T, let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> JWT<T, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> {
    /// Creates a new JWT instance from its components.
    ///
    /// This constructor initializes a JWT with the provided header, payload,
    /// and signature components. All components must be within their specified
    /// maximum lengths.
    ///
    /// # Arguments
    /// * `header` - The JWT header component
    /// * `payload` - The JWT payload component
    /// * `signature` - The JWT signature component
    ///
    /// # Returns
    /// Returns a new `JWT` instance with the provided components.
    pub fn init(
        header: Header<MaxHeaderLength>,
        payload: Payload<MaxPayloadLength>,
        signature: Signature<T, MaxSignatureLength>,
    ) -> Self {
        Self { header, payload, signature }
    }
}

/// Type alias for HMAC-SHA256 (HS256) JWT.
///
/// This type represents a JWT that uses HMAC-SHA256 for signature verification.
/// The signature is represented as a byte array (`u8`).
///
/// # Generic Parameters
/// * `MaxHeaderLength` - Maximum allowed length of the header
/// * `MaxPayloadLength` - Maximum allowed length of the payload
/// * `MaxSignatureLength` - Maximum allowed length of the HMAC signature
pub type JWT_H256<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> = JWT<u8, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength>;

/// Type alias for RSA-SHA256 (RS256) JWT.
///
/// This type represents a JWT that uses RSA-SHA256 for signature verification.
/// The signature is represented as a field element array.
///
/// # Generic Parameters
/// * `MaxHeaderLength` - Maximum allowed length of the header
/// * `MaxPayloadLength` - Maximum allowed length of the payload
///
/// # Note
/// The signature length is fixed to `KEY_LIMBS_2048` (18 limbs) to support
/// 2048-bit RSA keys, which is the standard key size for RS256.
pub type JWT_RS256<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = JWT<Field, MaxHeaderLength, MaxPayloadLength, KEY_LIMBS_2048>;
