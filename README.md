# Noir JWT

A JWT Verification and Claims Attestation Library for Noir. This library provides a set of types and functions for verifying different JWT schemes. The current implementation supports the following JWT schemes:

- HMAC-SHA256 (HS256)
- RSA-SHA256 (RS256 with 2048-bit keys)

JWT structure is defined in JWT struct, which is generic over the signature type, header length, payload length, and signature length. Signature type is either `BoundedVec<u8, MaxSignatureLength>` for HMAC or `BoundedVec<Field, MaxSignatureLength>` for RSA.

```noir
pub type Header<let MaxHeaderLength: u32> = BoundedVec<u8, MaxHeaderLength>;
pub type Payload<let MaxPayloadLength: u32> = BoundedVec<u8, MaxPayloadLength>;
pub type Signature<T, let MaxSignatureLength: u32> = BoundedVec<T, MaxSignatureLength>;


pub struct JWT<T, let MaxHeaderLength: u32, let MaxPayloadLength: u32, let MaxSignatureLength: u32> {
    pub header: Header<MaxHeaderLength>,
    pub payload: Payload<MaxPayloadLength>,
    pub signature: Signature<T, MaxSignatureLength>,
}
```

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
LIBRARY = { tag = "v0.1.0", git = "https://github.com/zkpersona/noir-jwt", directory = "lib" }
```

## Usage

### HMAC-SHA256 (HS256) Verification

```noir
use noir_jwt::JWT_H256 as JWT;
use noir_jwt::types::SecretKey;

pub global MAX_HEADER_LENGTH: u32 = 64;
pub global MAX_PAYLOAD_LENGTH: u32 = 256;
pub global MAX_SIGNATURE_LENGTH: u32 = 43;

pub global MAX_SECRET_KEY_LENGTH: u32 = 64;

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH, MAX_SIGNATURE_LENGTH>,
    secret_key: SecretKey<MAX_SECRET_KEY_LENGTH>,
) -> pub bool {
    jwt.verify(secret_key)
}
```

### RSA-SHA256 (RS256) Verification

```noir
use noir_jwt::{constants::KEY_LIMBS_2048, JWT_RS256 as JWT, RSAPubkey};

pub global MAX_HEADER_LENGTH: u32 = 32;
pub global MAX_PAYLOAD_LENGTH: u32 = 128;

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH>,
    pub_key: RSAPubkey<KEY_LIMBS_2048>,
) -> pub bool {
    jwt.verify(pub_key, 65537)
}
```

### Claim Attestation

```noir
use base64::BASE64_URL_DECODER::decode_var;
use json_parser::JSON1kb;
use noir_jwt::JWT_H256 as JWT;
use noir_jwt::types::{Payload, SecretKey};

pub global MAX_HEADER_LENGTH: u32 = 64;
pub global MAX_PAYLOAD_LENGTH: u32 = 256;
pub global MAX_SIGNATURE_LENGTH: u32 = 43;

pub global MAX_SECRET_KEY_LENGTH: u32 = 64;

unconstrained fn parse_json(payload: Payload<MAX_PAYLOAD_LENGTH>) -> JSON1kb {
    let mut decoded: BoundedVec<u8, (MAX_PAYLOAD_LENGTH * 3) / 4> = decode_var(payload);
    for _i in decoded.len()..decoded.max_len() {
        decoded.push(32); // Whitespace character
    }
    let json: JSON1kb = JSON1kb::parse_json(decoded.storage());
    json
}

fn main(
    jwt: JWT<MAX_HEADER_LENGTH, MAX_PAYLOAD_LENGTH, MAX_SIGNATURE_LENGTH>,
    secret_key: SecretKey<MAX_SECRET_KEY_LENGTH>,
    expected_email: BoundedVec<u8, 64>,
) -> pub bool {
    let verified = jwt.verify(secret_key);

    assert(verified);

    /// Safety: Payload is already verified
    let json: JSON1kb = unsafe { parse_json(jwt.payload) };

    let email: BoundedVec<u8, 64> = json.get_string_unchecked("sub".as_bytes());

    println(expected_email);
    println(email);

    email == expected_email
}
```

### Library Usage

This library provides a set of helpers functions to generate circuit inputs. To install the library, run the following command:

```bash
npm install @zkpersona/noir-jwt
# or
yarn add @zkpersona/noir-jwt
# or
pnpm add @zkpersona/noir-jwt
# or
bun add @zkpersona/noir-jwt
```

Here is an example of how to use the library to generate inputs for H256 proof:

```typescript
import type { InputMap } from '@noir-lang/noir_js';
import { BoundedVec, U8 } from '@zkpersona/noir-helpers';
import { JWT } from '@zkpersona/noir-jwt';

const jwt = new JWT(
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzQ0MzUxOTAzLCJleHAiOjE3NDQzNTkxMDN9.lKtDhCu1-ejUIEwrXPFWaaEvaXc5qZg1jUfxFxciQJ4'
);
const jwtInputs = jwt.toCircuitInputs({
  maxHeaderLength: 64,
  maxPayloadLength: 256,
  maxSignatureLength: 43,
});

const secretKey = Uint8Array.from('secret_key');

const secretKeyArray = Array.from(secretKey).map((e) => new U8(e));
const secretKeyVec = new BoundedVec(64, () => new U8(0));
secretKeyVec.extendFromArray(secretKeyArray);

const inputs: InputMap = {
  ...jwtInputs,
  secret_key: secretKeyVec.toJSON(),
};
```

And here is an example of how to use the library to generate inputs for RS256 proof:

```typescript
import type { InputMap } from '@noir-lang/noir_js';
import { JWT, RSAPubKey } from '@zkpersona/noir-jwt';

const pubKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArlZIVMkJ+pyjixkrQiZXYd3MwbIHUzsFwSCB/rjds1FpfgXAsArG
8EtyrKfDwZxdccLUGIlmdKO6uurL/wbcJcYxiMcJON5vPXztUAMeCNc6gvmlcsRa
5V1cdpFcjOsGwJKp/n+iIV5VOODfRdiIcE/YKb7fhCsu8xv03SNgUSi/7cwA+0nZ
6rzmQuWYYQ0VNMN0YJvFZe3iacjgKtQOlM79E6lD+s3noxp0N8kW+Aefv6lVxUD3
EbXTyxPSYR8XOrud88rsQqBrKfwz8L+IEk/dx4VVC9jXQAxvJ/NMRrOs3oitq91L
3R5k630h2aroD2sJi35ooWovymjAlLv+LwIDAQAB
-----END RSA PUBLIC KEY-----`;

const jwt = new JWT(
  'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzQ0MzUyMTMyLCJleHAiOjE3NDQzNTkzMzJ9.e4wBkSuW7Xpx6oChK7dm9nZG4P6pqsibj54nqQ4Zrt5wAz0Ibeh5MRyv8YMV9TzUE5ta8n9P-EJuqwtPohL2uMuoPwnIxKWXt4qAOtxMkWFLEckHSYoHCXqvph-UyPLbGL2zTSJJP-SgTr7E9Y1bU5qM46oieDiQL0ao4CEk5pXjjH5ueAvyA5jfcNAr2kVYsZh8oFFs00VZcUPUXVyZsfjG7EvZ1O6jQ_nCgYqzpQL-kW9ZI_prSNtvDX4wK1JFMVqXHma7XNbvmZNKSvvWhKw-V-lfL3RgjcrVyZnTV-apaZTr6ihOEXlenyU-zOhRfwzAic9HdFG8DUR6_xVqHA',
  'RS256'
);

const pubKey = RSAPubKey.fromPem(pubKeyPem);

const jwtInputs = jwt.toCircuitInputs({
  maxHeaderLength: 32,
  maxPayloadLength: 128,
  maxSignatureLength: 18,
});

const inputs: InputMap = {
  ...jwtInputs,
  ...pubKey.toCircuitInputs(),
};
```

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.