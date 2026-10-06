// tresor loaded from an extension repository (DuckDB v2.0's external repositories), checked as DuckDB checks it.
// Until duckdb-wasm supports `CREATE EXTENSION REPOSITORY` (duckdb-wasm#2262) the helper does what it would:
// the repository's keys from <from>/.well-known/duckdb-extension-repo.json (or one pinned), the file from
// <from>/<revision>/<platform>/tresor.duckdb_extension.wasm, its signature verified, and only then LOAD.

import { type Connection, type Database, literal } from "./duckdb.js";
import { type Fetch, checkTransport, readJson } from "./service.js";
import { verifyExtension } from "./signature.js";

export const REPOSITORY_METADATA = ".well-known/duckdb-extension-repo.json";

const stripSlashes = (url: string) => url.replace(/\/+$/, "");

/** The signing keys a repository publishes (`signature_keys`). */
export async function repositoryKeys(from: string, fetchImpl: Fetch, insecureHttp = false): Promise<string[]> {
	checkTransport("extension repository", from, insecureHttp);
	const url = stripSlashes(from) + "/" + REPOSITORY_METADATA;
	const doc = (await readJson(fetchImpl, url, "the extension repository's metadata", true)) as {
		signature_keys?: unknown;
	};
	const keys = doc?.signature_keys;
	if (!Array.isArray(keys) || keys.length === 0 || !keys.every((key) => typeof key === "string")) {
		throw new Error(`tresor-web: ${url} lists no signature_keys`);
	}
	return keys as string[];
}

/** Where DuckDB's revision and platform put an extension in a repository; `.wasm` as duckdb-wasm asks for it. */
export function extensionUrl(from: string, revision: string, platform: string, name = "tresor"): string {
	return `${stripSlashes(from)}/${revision}/${platform}/${name}.duckdb_extension.wasm`;
}

/** The running DuckDB's revision directory (a release's tag, else its source id) and platform. */
export async function runningDuckDB(conn: Connection): Promise<{ revision: string; platform: string }> {
	const version = (await conn.query("SELECT library_version, source_id FROM pragma_version()")).toArray()[0];
	const platform = (await conn.query("SELECT platform FROM pragma_platform()")).toArray()[0];
	const library = String(version?.library_version ?? "");
	const release = /^v?\d+\.\d+\.\d+$/.test(library);
	return {
		revision: release ? (library.startsWith("v") ? library : "v" + library) : String(version?.source_id ?? ""),
		platform: String(platform?.platform ?? ""),
	};
}

export interface LoadOptions {
	/** A key to trust instead of the repository's published ones (PEM or compact). */
	publicKey?: string;
	revision?: string;
	platform?: string;
	insecureHttp?: boolean;
	fetch?: Fetch;
}

/** Fetch tresor from `from`, verify its signature, and LOAD it - or throw, having loaded nothing. */
export async function loadTresor(db: Database, conn: Connection, from: string, options: LoadOptions = {}) {
	const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
	const insecureHttp = options.insecureHttp ?? false;
	checkTransport("extension repository", from, insecureHttp);
	const keys = options.publicKey ? [options.publicKey] : await repositoryKeys(from, fetchImpl, insecureHttp);
	const running = await runningDuckDB(conn);
	const url = extensionUrl(from, options.revision ?? running.revision, options.platform ?? running.platform);
	const response = await fetchImpl(url); // a CDN may serve it: the signature, not the URL, is the trust
	if (!response.ok) {
		throw new Error(`tresor-web: ${url} answered ${response.status}`);
	}
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (!(await verifyExtension(bytes, keys))) {
		throw new Error(`tresor-web: ${url} is not signed by the repository's keys - not loaded`);
	}
	const file = "tresor.duckdb_extension.wasm";
	await db.registerFileBuffer(file, bytes);
	try {
		await conn.query("LOAD " + literal(file));
	} finally {
		await db.dropFile?.(file);
	}
}
