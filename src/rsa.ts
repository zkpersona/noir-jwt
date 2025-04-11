import {
  bnToLimbStrArray,
  bnToRedcLimbStrArray,
} from '@mach-34/noir-bignum-paramgen';
import { Field, FixedSizeArray, toJSON } from '@zkpersona/noir-helpers';
import forge from 'node-forge';
import { bytesToBigInt } from './helpers';

/**
 * Represents an RSA public key with immutable properties.
 * Provides methods to create instances from different formats and convert to Noir circuit inputs.
 */
export class RSAPubKey {
  /**
   * Private constructor to enforce immutability and proper initialization.
   * Use factory methods `fromPem` or `fromAsn1` to create instances.
   *
   * @param modulus - The RSA modulus (n) as a bigint
   * @param exponent - The RSA public exponent (e) as a bigint
   */
  private constructor(
    // biome-ignore lint/style/noParameterProperties: private constructor
    readonly modulus: bigint,
    // biome-ignore lint/style/noParameterProperties: private constructor
    readonly exponent: bigint
  ) {}

  /**
   * Creates an RSAPubKey instance from a PEM-encoded public key.
   *
   * @param pem - The RSA public key in PEM format
   * @returns A new RSAPubKey instance
   */
  static fromPem(pem: string) {
    const key = forge.pki.publicKeyFromPem(pem);
    return new RSAPubKey(
      BigInt(key.n.toString(10)),
      BigInt(key.e.toString(10))
    );
  }

  /**
   * Creates an RSAPubKey instance from an ASN.1 encoded public key.
   *
   * @param key - The RSA public key in ASN.1 format
   * @returns A new RSAPubKey instance
   */
  static fromAsn1(key: forge.asn1.Asn1) {
    const publicKey = forge.pki.publicKeyFromAsn1(key);
    return new RSAPubKey(
      BigInt(publicKey.n.toString(10)),
      BigInt(publicKey.e.toString(10))
    );
  }

  /**
   * Converts the RSA public key into field element arrays for Noir circuit input.
   *
   * @param numBits - Optional number of bits to use for the limb representation.
   *                 If not provided, a default value will be used.
   * @returns An object containing:
   *          - modulus: Array of field elements representing the RSA modulus
   *          - redc: Array of field elements representing the Montgomery reduction parameters
   */
  toFieldArray(numBits?: number) {
    const modulus = bnToLimbStrArray(this.modulus, numBits).map(
      (e) => new Field(e)
    );
    const redc = bnToRedcLimbStrArray(this.modulus, numBits).map(
      (e) => new Field(e)
    );

    return {
      modulus: new FixedSizeArray(modulus.length, modulus),
      redc: new FixedSizeArray(redc.length, redc),
    };
  }

  /**
   * Converts the RSA public key into an object for Noir circuit input.
   */
  toCircuitInputs() {
    // biome-ignore lint/style/useNamingConvention: safe
    return toJSON({ pub_key: this.toFieldArray(2048) });
  }
}

/**
 * Represents an RSA signature with immutable properties.
 * Provides methods to create instances from different formats and convert to Noir circuit inputs.
 */
export class RSASignature {
  /**
   * Private constructor to enforce immutability and proper initialization.
   * Use factory method `fromString` to create instances.
   *
   * @param bytes - The raw bytes of the RSA signature
   */
  private constructor(
    // biome-ignore lint/style/noParameterProperties: private constructor
    readonly bytes: number[]
  ) {}

  /**
   * Creates an RSASignature instance from a string-encoded signature.
   *
   * @param signature - The RSA signature as a string
   * @param encoding - The encoding of the signature string (e.g., 'base64', 'hex')
   * @returns A new RSASignature instance
   */
  static fromString(signature: string, encoding: BufferEncoding) {
    const bytes = Buffer.from(signature, encoding);
    return new RSASignature(Array.from(bytes));
  }

  /**
   * Converts the RSA signature into an array of field elements for Noir circuit input.
   *
   * @returns An array of field elements representing the signature
   */
  toFieldArray() {
    const arr = bnToLimbStrArray(bytesToBigInt(this.bytes), 2048).map(
      (e) => new Field(e)
    );

    return new FixedSizeArray(arr.length, arr);
  }

  /**
   * Converts the RSA signature into an object for Noir circuit input.
   */
  toCircuitInputs() {
    return toJSON({ signature: this.toFieldArray() });
  }
}
