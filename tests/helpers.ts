import { type RSAKeyPairOptions, generateKeyPairSync } from 'node:crypto';

/**
 * Generates an RSA key pair for use in tests
 * @param props - Options for key generation, defaults to secure parameters
 * @returns Generated key pair with public and private keys in PEM format
 */
export const generateRSAKeyPair = (
  props: RSAKeyPairOptions<'pem', 'pem'> = {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  }
) => {
  const keyPair = generateKeyPairSync('rsa', props);
  return keyPair;
};
