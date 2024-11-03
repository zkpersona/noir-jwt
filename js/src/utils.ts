export interface JWT {
	header: BoundedVec;
	payload: BoundedVec;
	signature: BoundedVec;
}

export type BoundedVec = {
	storage: number[];
	len: number;
};

const pad = (arr: number[], length: number, value?: number): number[] => {
	const res = arr.slice();
	while (res.length < length) {
		res.push(value || 0);
	}
	return res;
};

export const toBoundedVec = (data: string, maxLength: number): BoundedVec => {
	const storage = pad(
		data.split('').map((c) => c.charCodeAt(0)),
		maxLength
	);
	return { storage, len: data.length };
};

export const toJWT = (data: string) => {
	isValidJWT(data);
	const [h, p, s] = data.split('.');
	const header = toBoundedVec(h, 64);
	const payload = toBoundedVec(p, 256);
	const signature = toBoundedVec(s, 43);

	return { header, payload, signature };
};

const isValidJWT = (data: string) => {
	const [header, payload, signature] = data.split('.');
	if (!header || !payload || !signature) {
		throw new Error('Invalid JWT');
	}
};
