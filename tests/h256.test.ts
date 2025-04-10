import { beforeAll, describe, expect, it } from 'vitest';

import { BoundedVec, Prover, U8 } from '@zkpersona/noir-helpers';

import type { CompiledCircuit, InputMap } from '@noir-lang/noir_js';
import { SignJWT } from 'jose';
import { JWT } from '../src';
import circuit from '../target/h256.json' assert { type: 'json' };

describe('JWT-H256 Proof Verification', () => {
  let prover: Prover;

  beforeAll(() => {
    prover = new Prover(circuit as CompiledCircuit, { type: 'all' });
  });

  const generateInputs = async () => {
    const secretKey = Uint8Array.from('secret_key');
    const jwtStr = await new SignJWT({ sub: '1234567890', name: 'John Doe' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(secretKey);

    const jwt = new JWT(jwtStr);
    const jwtInputs = jwt.toCircuitInputs({
      maxHeaderLength: 64,
      maxPayloadLength: 256,
      maxSignatureLength: 43,
    });

    const secretKeyArray = Array.from(secretKey).map((e) => new U8(e));
    const secretKeyVec = new BoundedVec(64, () => new U8(0));
    secretKeyVec.extendFromArray(secretKeyArray);

    const inputs: InputMap = {
      ...jwtInputs,
      // biome-ignore lint/style/useNamingConvention: safe
      secret_key: secretKeyVec.toJSON(),
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
