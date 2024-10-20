/// Splits a JWT (JSON Web Token) into its constituent parts: header, payload, and signature.
///
/// # Arguments
///
/// * `jwt` - A vector of bytes representing the JWT.
/// * `delimitter` - A byte representing the delimiter used to separate the JWT parts.
///
/// # Returns
///
/// A tuple containing three vectors of bytes:
/// * `header` - The header part of the JWT.
/// * `payload` - The payload part of the JWT.
/// * `signature` - The signature part of the JWT.
///
/// # Panics
///
/// This function will panic if the JWT format is invalid (i.e., if there are not exactly two delimiters).
///
pub fn split_jwt_var(jwt: Vec<u8>, delimitter: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let indexes: Vec<u32> = find_delimitter_indexes_var(jwt, delimitter);
    let mut header: Vec<u8> = Vec::new();
    let mut payload: Vec<u8> = Vec::new();
    let mut signature: Vec<u8> = Vec::new();

    assert_eq(indexes.len(), 2, "Invalid JWT Format");

    for i in 0..indexes.get(0) {
        header.push(jwt.get(i as u32));
    }
    for i in indexes.get(0) + 1..indexes.get(1) {
        payload.push(jwt.get(i as u32));
    }
    for i in (indexes.get(1) + 1) as u32..jwt.len() {
        signature.push(jwt.get(i));
    }

    (header, payload, signature)
}

/// Finds the indexes of a specified delimiter in a byte vector.
///
/// # Arguments
///
/// * `data` - A vector of bytes in which to search for the delimiter.
/// * `delimitter` - The byte value of the delimiter to search for.
///
/// # Returns
///
/// A vector of `u32` values representing the indexes where the delimiter is found.
///
pub fn find_delimitter_indexes_var(data: Vec<u8>, delimitter: u8) -> Vec<u32> {
    let mut indexes: Vec<u32> = Vec::new();

    for i in 0..data.len() {
        if data.get(i) == delimitter {
            indexes.push(i as u32);
        }
    }
    indexes
}
