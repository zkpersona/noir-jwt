import { type RSAKeyPairOptions, generateKeyPairSync } from 'node:crypto';

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
