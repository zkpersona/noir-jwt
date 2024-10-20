# Noir JWT

Noir JWT is a library for verifying JSON Web Tokens (JWTs) in Noir. The library provides a simple interface for verifying JWTs by comparing the JWT's signature to the computed signature using Secret Key and HMAC-256 algorithm.

Available Functions:

- `verify_jwt` - Verifies a fixed array JWT with a secret key and returns the boolean value.
- `verify_jwt_var` - Verifies a vector JWT with a secret key and returns the boolean value.

## Installation

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_jwt = { tag = "v1.0.0", git = "https://github.com/Envoy-VC/noir_jwt" }
```

## Usage

For Fixed Size Arrays:

```noir
fn main() {
    let jwt: [u8; 315] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ.Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes();

    let secret_key: [u8; 10] = "secret_key".as_bytes();

    let res: bool = verify_jwt(jwt, secret_key);

    assert(res);
}
```

For Vectors:

```noir
fn main() {
    let jwt: Vec<u8> = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ.Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes_vec();

    let secret_key: Vec<u8> = "secret_key".as_bytes_vec();

    let res: bool = verify_jwt_var(jwt, secret_key);

    assert(res);
}
```
