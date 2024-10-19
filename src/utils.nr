fn split_jwt(jwt: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let parts: Vec<&[u8]> = jwt.split(|&c| c == b'.').collect();
    if parts.len() != 3 {
        panic!("Invalid JWT format");
    }
    (parts[0], parts[1], parts[2])
}