# Noir JWT

Noir JWT is a library for verifying JSON Web Tokens (JWTs) in Noir. The library provides a simple interface for verifying JWTs by comparing the JWT's signature to the computed signature using Secret Key and HMAC-256 algorithm.

Available Functions:

- `verify_jwt` - Verifies a JWT with a secret key and returns the boolean value.

## Installation

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_jwt = { tag = "v1.0.1", git = "https://github.com/Envoy-VC/noir_jwt", directory = "lib"  }
```

## Usage

```noir
fn main() {
    let header = BoundedVec::from_array("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".as_bytes());
    let payload = BoundedVec::from_array(
        "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjkyOTkxODYsImV4cCI6MTc2MDgzNTI1NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIiwiZW1haWwiOiJqb2huQGRvZS5jb20ifQ"
            .as_bytes(),
    );
    let signature =
        BoundedVec::from_array("Km5zQjxqq7tkHLNdGy-Rq3f05j3IqBUUNxeyvRPXXMI".as_bytes());

    let jwt = JWT::new(header, payload, signature);
    let secret_key = BoundedVec::from_array("secret_key".as_bytes());
    let res: bool = verify_jwt(jwt, secret_key);
}
```
