use noir_jwt::{constants::KEY_LIMBS_2048, JWT_RS256 as JWT, RSAPubkey};

pub global MAX_HEADER_LENGTH: u32 = 32;
pub global MAX_PAYLOAD_LENGTH: u32 = 128;

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH>,
    pub_key: RSAPubkey<KEY_LIMBS_2048>,
) -> pub bool {
    jwt.verify(pub_key, 65537)
}
