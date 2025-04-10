use crate::{h256::verify_jwt_h256, types::JWT};

#[export]
fn bench_verify_jwt_h256_small() {
    let header: BoundedVec<u8, 64> =
        BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());

    let payload: BoundedVec<u8, 256> = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDQyNTQ3NTYsImV4cCI6MTc3NTc5MDc1NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoiamRvZUBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG4iLCJTdXJuYW1lIjoiRG9lIiwiRW1haWwiOiJqZG9lQGV4YW1wbGUuY29tIn0"
            .as_bytes(),
    );
    let signature: BoundedVec<u8, 64> =
        BoundedVec::from_array("V76__Az9KeQNpsT7cezbve34B1Mx6OriMLto3vSCeI8".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key: BoundedVec<u8, 10> = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt_h256(jwt, secret_key);
    assert(res);
}

#[export]
fn bench_verify_jwt_h256_large() {
    let header: BoundedVec<u8, 64> =
        BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());
    let payload: BoundedVec<u8, 512> = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDQyNTQ1NDMsImV4cCI6MTc3NTc5MDU0MywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXSwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZSI6Impyb2NrZXQiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbCI6ImJlZUBleGFtcGxlLmNvbSJ9"
            .as_bytes(),
    );
    let signature: BoundedVec<u8, 64> =
        BoundedVec::from_array("YKYwnHfD6tZYCVnihZN72OJrE136bbx_s07tAh87Myg".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key: BoundedVec<u8, 10> = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt_h256(jwt, secret_key);
    assert(res);
}
