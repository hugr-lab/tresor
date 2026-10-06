import { execFileSync } from "node:child_process";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";

import { compactPublicKey, signedDigests, verifyExtension } from "../src/signature.js";

// DuckDB's own signing, from the submodule: what extension-upload-single.sh runs on every extension it publishes
const HASH_SCRIPT = new URL("../../../duckdb/scripts/compute-extension-hash.sh", import.meta.url).pathname;

function keyPair() {
	return generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
}

const work = mkdtempSync(join(tmpdir(), "tresor-web-sig-"));
after(() => rmSync(work, { recursive: true, force: true }));

const signer = keyPair();
const other = keyPair();
// more than two 1 MiB chunks, the last one short: the chunking is what a wrong implementation gets wrong
const payload = new Uint8Array(randomBytes(2 * 1024 * 1024 + 12345));

async function signedByNode(body: Uint8Array, privateKey: string): Promise<Uint8Array> {
	const signature = sign("sha256", await signedDigests(body), privateKey);
	const out = new Uint8Array(body.length + signature.length);
	out.set(body);
	out.set(signature, body.length);
	return out;
}

describe("an extension's signature, as DuckDB checks it", () => {
	it("is the same signature DuckDB's own signing makes", async (t) => {
		if (!existsSync(HASH_SCRIPT)) {
			t.skip("the duckdb submodule is not checked out");
			return;
		}
		const body = join(work, "ext.append");
		const hash = join(work, "ext.hash");
		const sig = join(work, "ext.sign");
		const key = join(work, "key.pem");
		writeFileSync(body, payload);
		writeFileSync(key, signer.privateKey);
		writeFileSync(hash, execFileSync("bash", [HASH_SCRIPT, body]));
		execFileSync("openssl", ["pkeyutl", "-sign", "-in", hash, "-inkey", key, "-pkeyopt", "digest:sha256", "-out", sig]);
		const duckdbSigned = new Uint8Array(payload.length + 256);
		duckdbSigned.set(payload);
		duckdbSigned.set(readFileSync(sig), payload.length);
		assert.equal(await verifyExtension(duckdbSigned, [signer.publicKey]), true);
		// PKCS#1 v1.5 is deterministic: the helper's notion of the signed digest is exactly DuckDB's
		assert.deepEqual(duckdbSigned, await signedByNode(payload, signer.privateKey));
	});

	it("accepts a signed file, by a PEM or a compact key, among others", async () => {
		const signed = await signedByNode(payload, signer.privateKey);
		assert.equal(await verifyExtension(signed, [signer.publicKey]), true);
		assert.equal(await verifyExtension(signed, [compactPublicKey(signer.publicKey)]), true);
		assert.equal(await verifyExtension(signed, [other.publicKey, signer.publicKey]), true);
	});

	it("refuses a tampered file, a tampered signature, another key, a file too short", async () => {
		const signed = await signedByNode(payload, signer.privateKey);
		for (const at of [0, 1024 * 1024, payload.length - 1, signed.length - 1]) {
			const tampered = signed.slice();
			tampered[at] ^= 0x01;
			assert.equal(await verifyExtension(tampered, [signer.publicKey]), false, `a byte changed at ${at}`);
		}
		assert.equal(await verifyExtension(signed, [other.publicKey]), false);
		assert.equal(await verifyExtension(signed.subarray(0, 256), [signer.publicKey]), false);
		const empty = await signedByNode(new Uint8Array(0), signer.privateKey);
		assert.equal(await verifyExtension(empty, [signer.publicKey]), false, "nothing signed is no extension");
	});

	it("refuses keys that are not SubjectPublicKeyInfo, and no key at all", async () => {
		const signed = await signedByNode(payload, signer.privateKey);
		await assert.rejects(verifyExtension(signed, []), /no key/);
		assert.throws(() => compactPublicKey("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----"));
		assert.throws(() => compactPublicKey("-----BEGIN PUBLIC KEY-----\nAAAA"), /no '-----END/);
		assert.throws(() => compactPublicKey("not a key!"), /not base64/);
	});
});
