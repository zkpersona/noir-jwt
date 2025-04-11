import { beforeAll, describe, expect, it } from 'vitest';

import { Prover } from '@zkpersona/noir-helpers';

import type { CompiledCircuit, InputMap } from '@noir-lang/noir_js';
import { SignJWT, importPKCS8 } from 'jose';
import { JWT, RSAPubKey } from '../src';
import circuit from '../target/rs256.json' assert { type: 'json' };
import { generateRSAKeyPair } from './helpers';

describe('JWT-RS256 2048 bits Proof Verification', () => {
  let prover: Prover;

  beforeAll(() => {
    prover = new Prover(circuit as CompiledCircuit, { type: 'all' });
  });

  const generateInputs = async () => {
    const keyPair = generateRSAKeyPair();
    const pubKey = RSAPubKey.fromPem(keyPair.publicKey);
    const privateKey = await importPKCS8(keyPair.privateKey, 'RS256');
    const jwtStr = await new SignJWT({ sub: '1234567890', name: 'John Doe' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(privateKey);

    const jwt = new JWT(jwtStr, 'RS256');
    const jwtInputs = jwt.toCircuitInputs({
      maxHeaderLength: 32,
      maxPayloadLength: 128,
      maxSignatureLength: 18,
    });

    const inputs: InputMap = {
      ...jwtInputs,
      ...pubKey.toCircuitInputs(),
    };
    return inputs;
  };

  it('should prove using honk backend', async () => {
    const inputs = await generateInputs();
    const proof = await prover.fullProve(inputs, { type: 'honk' });
    const isVerified = await prover.verify(proof, { type: 'honk' });
    expect(isVerified).toBe(true);
  });

  it('should prove using plonk backend', async () => {
    const inputs = await generateInputs();
    const proof = await prover.fullProve(inputs, { type: 'plonk' });
    const isVerified = await prover.verify(proof, { type: 'plonk' });
    expect(isVerified).toBe(true);
  });
});
