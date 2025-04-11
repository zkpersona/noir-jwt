/**
 * Converts a byte array to a bigint.
 *
 * @param bytes - The byte array to convert
 * @returns The resulting bigint
 */
export const bytesToBigInt = (bytes: number[] | Uint8Array): bigint => {
  const arr = bytes instanceof Uint8Array ? Array.from(bytes) : bytes;
  return arr.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
};
