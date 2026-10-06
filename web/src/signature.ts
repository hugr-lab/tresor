// An extension's signature, checked as DuckDB checks it (duckdb src/main/extension/extension_load.cpp, and
// scripts/compute-extension-hash.sh + `openssl pkeyutl -sign -pkeyopt digest:sha256`, which sign it):
//   - the last 256 bytes are the signature;
//   - everything before them is cut into 1 MiB chunks, each hashed with SHA-256;
//   - the signature is RSA PKCS#1 v1.5 over SHA-256 of those digests, concatenated.
// WebCrypto's RSASSA-PKCS1-v1_5 with SHA-256 hashes its input itself, so it verifies over the concatenation.

export const SIGNATURE_SIZE = 256;
const CHUNK_SIZE = 1024 * 1024;
const PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
const PEM_FOOTER = "-----END PUBLIC KEY-----";

function subtleCrypto(): SubtleCrypto {
	const subtle = globalThis.crypto?.subtle;
	if (!subtle) {
		throw new Error("tresor-web: WebCrypto is not available (a secure context is needed)");
	}
	return subtle;
}

/** A public key as DuckDB compacts it: the base64 body of its PEM (SubjectPublicKeyInfo), no whitespace. */
export function compactPublicKey(key: string): string {
	let body = key;
	const header = key.indexOf(PEM_HEADER);
	if (header >= 0) {
		const footer = key.indexOf(PEM_FOOTER, header);
		if (footer < 0) {
			throw new Error(`tresor-web: a public key with '${PEM_HEADER}' but no '${PEM_FOOTER}'`);
		}
		body = key.slice(header + PEM_HEADER.length, footer);
	} else if (key.includes("-----BEGIN")) {
		throw new Error(`tresor-web: only SubjectPublicKeyInfo keys ('${PEM_HEADER}') are supported`);
	}
	body = body.replace(/\s+/g, "");
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
		throw new Error("tresor-web: a public key that is not base64");
	}
	return body;
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
	const binary = atob(text);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		out[i] = binary.charCodeAt(i);
	}
	return out;
}

/** The SHA-256 digests of the signed part's 1 MiB chunks, concatenated: what the signature is over. */
export async function signedDigests(signed: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
	const subtle = subtleCrypto();
	const chunks = Math.ceil(signed.length / CHUNK_SIZE); // none for nothing, as DuckDB counts them
	const out = new Uint8Array(chunks * 32);
	for (let i = 0; i < chunks; i++) {
		const chunk = signed.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE) as Uint8Array<ArrayBuffer>;
		const digest = await subtle.digest("SHA-256", chunk);
		out.set(new Uint8Array(digest), i * 32);
	}
	return out;
}

/**
 * Is `extension` (the file as served, signature included) signed by one of `keys` (PEM or compact)? False for a
 * file too short to carry a signature, a tampered one, or one signed by another key; a malformed key throws.
 */
export async function verifyExtension(extension: Uint8Array, keys: readonly string[]): Promise<boolean> {
	if (keys.length === 0) {
		throw new Error("tresor-web: no key to verify the extension with");
	}
	if (extension.length <= SIGNATURE_SIZE) {
		return false;
	}
	const subtle = subtleCrypto();
	const signedPart = extension.subarray(0, extension.length - SIGNATURE_SIZE);
	const signature = extension.subarray(extension.length - SIGNATURE_SIZE) as Uint8Array<ArrayBuffer>;
	const digests = await signedDigests(signedPart);
	for (const key of keys) {
		const imported = await subtle.importKey(
			"spki",
			fromBase64(compactPublicKey(key)),
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false,
			["verify"],
		);
		if (await subtle.verify("RSASSA-PKCS1-v1_5", imported, signature, digests)) {
			return true;
		}
	}
	return false;
}
