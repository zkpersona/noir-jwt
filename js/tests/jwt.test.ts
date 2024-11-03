import { Prover } from '../src';

import jwtVerify from '../../examples/target/jwt_verify.json';
import jwtStringVerify from '../../examples/target/jwt_string_verify.json';

import { CompiledCircuit } from '@noir-lang/backend_barretenberg';
import { toBoundedVec, toJWT } from '../src/utils';
import { InputMap } from '@noir-lang/noirc_abi';

import * as jose from 'jose';

describe('JWT Verify Circuit Unit Tests', () => {
	let jwtProver: Prover;
	let jwtStringProver: Prover;

	beforeAll(() => {
		jwtProver = new Prover(jwtVerify as CompiledCircuit, 'all');
		jwtStringProver = new Prover(jwtStringVerify as CompiledCircuit, 'all');
	});

	afterAll(async () => {
		await jwtProver.destroy();
		await jwtStringProver.destroy();
	});

	describe('Successful Cases', () => {
		it('Valid JWT', async () => {
			const secret = Buffer.from('secret_key');
			const jwt = toJWT(
				await new jose.SignJWT({ 'urn:example:claim': true })
					.setProtectedHeader({ alg: 'HS256' })
					.setIssuedAt()
					.setExpirationTime('2h')
					.sign(secret)
			);

			const secret_key = toBoundedVec('secret_key', 256);

			const inputs: InputMap = {
				jwt,
				secret_key,
			};

			const res = await jwtProver.simulateWitness(inputs);
			expect(res.returnValue).toEqual(true);
		});
		it('Valid JWT String', async () => {
			const secret = Buffer.from('secret_key');
			const jwtStr = await new jose.SignJWT({ 'urn:example:claim': true })
				.setProtectedHeader({ alg: 'HS256' })
				.setIssuedAt()
				.setExpirationTime('2h')
				.sign(secret);

			const [header, payload, signature] = jwtStr.split('.');
			const header_length = header.length;
			const payload_length = payload.length;
			const signature_length = signature.length;

			const secret_key = toBoundedVec('secret_key', 256);
			const jwt = toBoundedVec(jwtStr, 1133);

			const inputs: InputMap = {
				jwt_string: jwt,
				secret_key,
				header_length,
				payload_length,
				signature_length,
			};

			const res = await jwtStringProver.simulateWitness(inputs);
			expect(res.returnValue).toEqual(true);
		});
	});
});
