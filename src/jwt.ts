import { BoundedVec, Field, U8, toJSON } from '@zkpersona/noir-helpers';
import { RSASignature } from './rsa';

/**
 * Supported JWT signature algorithms.
 *
 */
export type JWTAlgorithm = 'H256' | 'RS256';

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
  constructor(jwt: string, alg: JWTAlgorithm = 'H256') {
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
  toCircuitInputs({
    maxHeaderLength,
    maxPayloadLength,
    maxSignatureLength,
  }: {
    maxHeaderLength: number;
    maxPayloadLength: number;
    maxSignatureLength: number;
  }) {
    let sig: BoundedVec<Field> | BoundedVec<U8>;
    if (this.alg === 'H256') {
      const arr = Array.from(Buffer.from(this.signature)).map((e) => new U8(e));
      sig = new BoundedVec(maxSignatureLength, () => new U8(0));
      sig.extendFromArray(arr);
    } else if (this.alg === 'RS256') {
      const sigArr = RSASignature.fromString(
        this.signature,
        'base64'
      ).toFieldArray();

      sig = new BoundedVec(sigArr.len(), () => new Field(0));
      sig.extendFromArray(sigArr.toArray());
    } else {
      throw new Error(`Unsupported algorithm: ${this.alg}`);
    }

    const headerArr = Array.from(Buffer.from(this.header)).map(
      (e) => new U8(e)
    );
    const header = new BoundedVec(maxHeaderLength, () => new U8(0));
    header.extendFromArray(headerArr);

    const payloadArr = Array.from(Buffer.from(this.payload)).map(
      (e) => new U8(e)
    );
    const payload = new BoundedVec(maxPayloadLength, () => new U8(0));
    payload.extendFromArray(payloadArr);

    const data = {
      header,
      payload,
      signature: sig,
    };

    return toJSON({ jwt: data });
  }
}
