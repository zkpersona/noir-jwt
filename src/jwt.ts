import { BoundedVec, Field, U8, toJSON } from '@zkpersona/noir-helpers';
import { RSASignature } from './rsa';

/**
 * Supported JWT signature algorithms.
 *
 * @property type - The type of signature algorithm
 * @property numBits - For RSA, the number of bits in the modulus (1024 or 2048)
 */
export type JWTAlgorithm =
  | {
      type: 'H256';
    }
  | {
      type: 'R256';
      numBits: 1024 | 2048;
    };

/**
 * Class for parsing and converting JWT strings into Noir circuit inputs.
 * Handles both HMAC-SHA256 and RSA-SHA256 signatures, converting them into
 * appropriate field element representations for Noir circuit verification.
 */
// biome-ignore lint/style/useNamingConvention: convention
export class JWT {
  /** Base64-encoded JWT header */
  protected header: string;
  /** Base64-encoded JWT payload */
  protected payload: string;
  /** Base64-encoded JWT signature */
  protected signature: string;
  /** The algorithm used for signature verification */
  protected alg: JWTAlgorithm;

  /**
   * Creates a new JWT instance from a JWT string.
   *
   * @param jwt - The JWT string in the format 'header.payload.signature'
   * @param alg - The algorithm to use for signature verification (defaults to H256)
   * @throws Error if the JWT string is malformed or missing components
   */
  constructor(jwt: string, alg: JWTAlgorithm = { type: 'H256' }) {
    const [header, payload, signature] = jwt.trim().split('.');
    if (!header) throw new Error('Invalid JWT: header is missing');
    if (!payload) throw new Error('Invalid JWT: payload is missing');
    if (!signature) throw new Error('Invalid JWT: signature is missing');

    this.header = header;
    this.payload = payload;
    this.signature = signature;
    this.alg = alg;
  }

  /**
   * Converts the JWT components into Noir circuit compatible inputs.
   *
   * @param maxHeaderLength - Maximum length for the header vector
   * @param maxPayloadLength - Maximum length for the payload vector
   * @param maxSignatureLength - Maximum length for the signature vector
   * @returns InputMap containing the JWT components as Noir circuit inputs.
   * @throws Error if an unsupported algorithm is specified
   */
  toNoirInputs({
    maxHeaderLength,
    maxPayloadLength,
    maxSignatureLength,
  }: {
    maxHeaderLength: number;
    maxPayloadLength: number;
    maxSignatureLength: number;
  }) {
    let sig: BoundedVec<Field> | BoundedVec<U8>;
    if (this.alg.type === 'H256') {
      const arr = Array.from(Buffer.from(this.signature)).map((e) => new U8(e));
      sig = new BoundedVec(maxSignatureLength, () => new Field(0));
      sig.extendFromArray(arr);
    } else if (this.alg.type === 'R256') {
      const sigArr = RSASignature.fromString(
        this.signature,
        'base64'
      ).toFieldArray(this.alg.numBits);

      sig = new BoundedVec(sigArr.length, () => new Field(0));
      sig.extendFromArray(sigArr);
    } else {
      throw new Error(`Unsupported algorithm: ${this.alg}`);
    }

    const headerArr = Array.from(Buffer.from(this.header)).map(
      (e) => new U8(e)
    );
    const header = new BoundedVec(maxHeaderLength, () => new Field(0));
    header.extendFromArray(headerArr);

    const payloadArr = Array.from(Buffer.from(this.payload)).map(
      (e) => new U8(e)
    );
    const payload = new BoundedVec(maxPayloadLength, () => new Field(0));
    payload.extendFromArray(payloadArr);

    const data = {
      header,
      payload,
      signature: sig,
    };

    return toJSON(data);
  }
}
