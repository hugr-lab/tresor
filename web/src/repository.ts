// tresor loaded from an extension repository (DuckDB v2.0's external repositories), checked as DuckDB checks it.
// Until duckdb-wasm supports `CREATE EXTENSION REPOSITORY` (duckdb-wasm#2262) the helper does what it would: the
// file from <from>/<revision>/<platform>/tresor.duckdb_extension.wasm, its signature verified against the trusted
// keys, and only those verified bytes loaded.
//
// The keys. DuckDB pins a repository's keys once, at CREATE EXTENSION REPOSITORY. A page has nothing to pin them in
// but its own code: `publicKey` is that - the production mode. Without it the keys are read from the repository's
// .well-known document on every use (trust on each use: the check then guards against a file changed apart from
// its repository - a CDN, a cache - not against the repository's origin itself).

import { type Connection, type Database, literal } from "./duckdb.js";
import { type Fetch, checkTransport, readJson } from "./service.js";
import { verifyExtension } from "./signature.js";

export const REPOSITORY_METADATA = ".well-known/duckdb-extension-repo.json";

const stripSlashes = (url: string) => url.replace(/\/+$/, "");

/** The signing keys a repository publishes (`signature_keys`), from its own origin - no redirect followed. */
export async function repositoryKeys(from: string, fetchImpl: Fetch, insecureHttp = false): Promise<string[]> {
	checkTransport("extension repository", from, insecureHttp);
	const url = stripSlashes(from) + "/" + REPOSITORY_METADATA;
	const doc = (await readJson(fetchImpl, url, "the extension repository's metadata")) as {
		signature_keys?: unknown;
	};
	const keys = doc?.signature_keys;
	if (!Array.isArray(keys) || keys.length === 0 || !keys.every((key) => typeof key === "string")) {
		throw new Error(`tresor-web: ${url} lists no signature_keys`);
	}
	return keys as string[];
}

/** Pinned keys: one or several, each PEM (several PEM blocks in one string too) or compact. */
export function pinnedKeys(publicKey: string | readonly string[]): string[] {
	const out: string[] = [];
	for (const entry of typeof publicKey === "string" ? [publicKey] : publicKey) {
		const blocks = entry.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g);
		out.push(...(blocks ?? [entry]));
	}
	return out;
}

/** Where DuckDB's revision and platform put an extension in a repository; `.wasm` as duckdb-wasm asks for it. */
export function extensionUrl(from: string, revision: string, platform: string, name = "tresor"): string {
	return `${stripSlashes(from)}/${revision}/${platform}/${name}.duckdb_extension.wasm`;
}

/**
 * The running DuckDB's revision directory and platform, as DuckDB names them: a release's version (no `-dev`), else
 * its source id. A duckdb-wasm build may name its directory otherwise (DUCKDB_WASM_VERSION): `revision` overrides.
 */
export async function runningDuckDB(conn: Connection): Promise<{ revision: string; platform: string }> {
	const version = (await conn.query("SELECT library_version, source_id FROM pragma_version()")).toArray()[0];
	const platform = (await conn.query("SELECT platform FROM pragma_platform()")).toArray()[0];
	const library = String(version?.library_version ?? "");
	const release = library !== "" && !library.includes("-dev");
	return {
		revision: release ? (library.startsWith("v") ? library : "v" + library) : String(version?.source_id ?? ""),
		platform: String(platform?.platform ?? ""),
	};
}

export interface LoadOptions {
	/** The keys to trust, pinned in the page (PEM or compact; one or several) instead of the repository's. */
	publicKey?: string | readonly string[];
	revision?: string;
	platform?: string;
	insecureHttp?: boolean;
	fetch?: Fetch;
}

/** Fetch tresor from `from`, verify its signature, and LOAD exactly those bytes - or throw, having loaded nothing. */
export async function loadTresor(db: Database, conn: Connection, from: string, options: LoadOptions = {}) {
	const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
	const insecureHttp = options.insecureHttp ?? false;
	checkTransport("extension repository", from, insecureHttp);
	const keys = options.publicKey ? pinnedKeys(options.publicKey) : await repositoryKeys(from, fetchImpl, insecureHttp);
	const running = await runningDuckDB(conn);
	const url = extensionUrl(from, options.revision ?? running.revision, options.platform ?? running.platform);
	const response = await fetchImpl(url); // a CDN may serve it: the signature, not the URL, is what is trusted
	if (!response.ok) {
		throw new Error(`tresor-web: ${url} answered ${response.status}`);
	}
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (!(await verifyExtension(bytes, keys))) {
		throw new Error(`tresor-web: ${url} is not signed by the trusted keys - not loaded`);
	}
	// DuckDB-wasm's LOAD fetches the library by its name (an XMLHttpRequest in the worker) and dlopens what that
	// answers: the name is an object URL of the verified bytes, so nothing else can be answered. Its fragment ends in
	// "/tresor.duckdb_extension.wasm" - the request ignores it, and DuckDB takes the extension's name from it.
	const objectUrl = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: "application/wasm" }));
	const file = objectUrl + "#/tresor.duckdb_extension.wasm";
	try {
		await db.registerFileBuffer(file, bytes);
		try {
			await conn.query("LOAD " + literal(file));
		} finally {
			await db.dropFile?.(file);
		}
	} finally {
		URL.revokeObjectURL(objectUrl);
	}
}
