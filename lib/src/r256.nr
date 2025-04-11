use crate::JWT;
use super::{helpers::build_signing_input, RSAPubkey};

use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;
use std::hash::sha256::sha256_var;

impl<let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> JWT<Field, MaxHeaderLength, MaxPayloadLength, MaxSignatureLength> {

    /// Verifies a JWT using RSA-SHA256 (RS256) algorithm with PKCS#1 v1.5 padding.
    ///
    /// This function performs the following steps:
    /// 1. Constructs the signing input from header and payload
    /// 2. Computes SHA-256 hash of the signing input
    /// 3. Initializes RSA parameters with the public key
    /// 4. Verifies the signature using PKCS#1 v1.5 padding scheme
    ///
    /// # Arguments
    /// * `pub_key` - The RSA public key used for verification
    /// * `exponent` - The RSA public exponent (typically 65537)
    ///
    /// # Returns
    /// Returns `true` if the signature is valid, `false` otherwise.
    ///
    /// # Safety
    /// The `build_signing_input` function is marked as unsafe because it performs
    /// array concatenation. However, this is safe in this context as we're working
    /// with fixed-size arrays and the lengths are checked at compile time.
    ///
    /// # Note
    /// This implementation uses a 2048-bit RSA key size, which is considered secure
    /// for current cryptographic standards. The signature verification is performed
    /// using the PKCS#1 v1.5 padding scheme as specified in RFC 8017.
    pub fn verify(self, pub_key: RSAPubkey<MaxSignatureLength>, exponent: u32) -> bool {
        /// SAFETY: This only does concatenation of header and payload
        let mut signing_input = unsafe { build_signing_input(self.header, self.payload) };

        let data_hash = sha256_var(signing_input.storage(), signing_input.len() as u64);
        let params: BigNumParams<MaxSignatureLength, 2048> =
            BigNumParams::new(false, pub_key.modulus, pub_key.redc);

        let signature: RuntimeBigNum<MaxSignatureLength, 2048> =
            RuntimeBigNum::from_array(params, self.signature.storage());

        verify_sha256_pkcs1v15(data_hash, signature, exponent)
    }
}

#[test]
pub fn test_verify_jwt_rs256() {
    let header: BoundedVec<u8, 64> = BoundedVec::from_array("eyJhbGciOiJSUzI1NiJ9".as_bytes());

    let payload: BoundedVec<u8, 128> = BoundedVec::from_array(
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzQ0MjY3MjgwLCJleHAiOjE3NDQyNzQ0ODB9"
            .as_bytes(),
    );

    let signature_limbs: [Field; 18] = [
        0x1b3bbf04c76757695ce58d6949f2d9,
        0xe7c2c8dd9270401db1abd736442ac8,
        0x24c4990b2d6dd05a510f909e7afb72,
        0xac37a090350fb95ffd974bac434c1c,
        0xd6244a050b02874cdaaeb802d7d7ae,
        0x8ff0300c6ab83449df091ed8ae7cc6,
        0x60134b5e184139978c4aa2726cf86d,
        0xc9f531f04b8bcb734610fd823e7800,
        0x2548f3bca8ead364424ae802377ad7,
        0x3ccb4d9bf60fc8c9fa31324efed9c3,
        0x465fe45b4f328c859fe05c7ad5888e,
        0xd3eb97936bee99967d2b94c5910b8d,
        0x949214b68fda9c0ffcc9b55e17032d,
        0x745ebaab7a730e04699dc69be84b92,
        0x45f5af4f2266c079fb22184ee73a58,
        0x7512ea751a9e81934dd40fe506210d,
        0xd5cf0005ce4ba77cbd93a98f682510,
        0xb2,
    ];

    let signature: BoundedVec<Field, 18> = BoundedVec::from_array(signature_limbs);

    let modulus: [Field; 18] = [
        0x9ce874810fb8c5896defb02ee2e4bd,
        0x3435b4623d41b6e0829d5ba9c1b00f,
        0x865d306f93d80f6bdf9edff707f5f1,
        0x2b7fa40ccbc87b6d2a54a4e9e5f199,
        0xe2a7f78fd85ba91d4745feffb3694a,
        0x7cc53ecbea5b37a716b9ee99b8f9fa,
        0xf6566a8639a4ab7813f837d058a425,
        0x53b3af58e0950fa779a229b646df06,
        0x512548f3036214a042bdfd40cf72db,
        0xb7e86fefafca7159377513786c3ade,
        0x238972a38ac71789d895bd847614fc,
        0x8b81ac69b5539750f62f86254f6c78,
        0x7ba35431198e6a67875baaf6c69cb6,
        0x56cb9f2c7d4839bbb78e0154c8ece2,
        0x6061fd2d93647507edf67040901c9a,
        0x2f77340ea86da9f6e46b72488eb31f,
        0xe2f94071e938cfdd894ac5c7184539,
        0xd2,
    ];

    let redc: [Field; 18] = [
        0x7adc39ba80292abd342eb5b9b4a957,
        0x8fe75a004ad5ec6dc113f442fc52a6,
        0x313d2b93cce3057f2317c738fe589a,
        0x073893ec7c90864c121c0535eb4751,
        0x318f529426d6e3f71bfd80ca288e83,
        0x4e7967013f681b7b96f9c71a79c0bf,
        0xe0dce63c5a91cf739646bc1dff4d26,
        0x85733ba36685cbfe2360251ae0829b,
        0xbfb17620e413d5ac66ebc2dc7640e0,
        0xe4e18961c63ef5d468a2b384d96d32,
        0xfbe2ce4148f3f252a4d75bcf91c9a7,
        0x3407ddee889feb31c1bdb33bd49944,
        0xdc9c2bbc6844a60dce1fd9209ba0bf,
        0xe31e18a5e369986e3b2452b1591694,
        0x72823624eb1ae6b4499d51b07a9ff1,
        0x1c5cd2688ad958075e7e5b0c782d2f,
        0x39f5da118e102e7b1d8f16c1927416,
        0x136c,
    ];

    let pub_key = RSAPubkey { modulus, redc };
    let jwt = JWT::init(header, payload, signature);

    let verified = jwt.verify(pub_key, 65537);

    assert(verified)
}
