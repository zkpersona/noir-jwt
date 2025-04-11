/// Type alias for JWT header component with bounded length.
///
/// Represents the header part of a JWT, which contains metadata about the token
/// and the signing algorithm used. The length is bounded to prevent memory
/// overflow attacks.
///
/// # Generic Parameters
/// * `MaxHeaderLength` - Maximum allowed length of the header in bytes
pub type Header<let MaxHeaderLength: u32> = BoundedVec<u8, MaxHeaderLength>;

/// Type alias for JWT payload component with bounded length.
///
/// Represents the payload (claims) part of a JWT, which contains the actual
/// data being transmitted. The length is bounded to prevent memory overflow
/// attacks and ensure efficient processing within the Noir circuit.
///
/// # Generic Parameters
/// * `MaxPayloadLength` - Maximum allowed length of the payload in bytes
pub type Payload<let MaxPayloadLength: u32> = BoundedVec<u8, MaxPayloadLength>;

/// Type alias for JWT signature component with bounded length.
///
/// Represents the signature part of a JWT, which is used to verify the
/// authenticity of the token. The type parameter `T` allows for different
/// signature representations (e.g., `u8` for HMAC, `Field` for RSA).
///
/// # Generic Parameters
/// * `T` - The type of elements in the signature (e.g., `u8` or `Field`)
/// * `MaxSignatureLength` - Maximum allowed length of the signature
pub type Signature<T, let MaxSignatureLength: u32> = BoundedVec<T, MaxSignatureLength>;

/// Type alias for secret key used in HMAC-based JWT verification.
///
/// Represents the secret key used for HMAC-SHA256 (HS256) signature verification.
/// The length is bounded to ensure secure key sizes and prevent memory overflow.
///
/// # Generic Parameters
/// * `MaxSecretKeyLength` - Maximum allowed length of the secret key in bytes
pub type SecretKey<let MaxSecretKeyLength: u32> = BoundedVec<u8, MaxSecretKeyLength>;

/// Type alias for the concatenated signing input used in JWT verification.
///
/// Represents the input used for signature verification, which is constructed
/// by concatenating the header and payload with a period (.) separator.
/// The length is calculated as: header length + 1 (for '.') + payload length.
///
/// # Generic Parameters
/// * `MaxHeaderLength` - Maximum allowed length of the header
/// * `MaxPayloadLength` - Maximum allowed length of the payload
pub type SigningInput<let MaxHeaderLength: u32, let MaxPayloadLength: u32> = BoundedVec<u8, MaxHeaderLength + 1 + MaxPayloadLength>;
