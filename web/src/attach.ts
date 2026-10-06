// attachTresor (tresor specs/020): what a web page calls to have tresor attached in its DuckDB-wasm as the person
// logged in to the organisation's identity provider. After it, everything is as in the CLI - corp.secrets(),
// corp.whoami(), variables, the secrets in DuckDB's lookup - and tresor renews the login itself.

import { type Connection, type Database, identifier, literal } from "./duckdb.js";
import { type LoginOptions, type PageLogin, oidcLogin } from "./login.js";
import { type LoadOptions, loadTresor } from "./repository.js";
import { type Fetch, checkTransport, chooseIssuer, readDiscovery, serviceHost } from "./service.js";

export interface AttachOptions extends LoginOptions {
	/** The catalog's name: `ATTACH … AS <as>`. */
	as: string;
	/** The extension repository to load tresor from; without it tresor must be loaded already. */
	from?: string;
	/** Trust this key (PEM or compact) instead of the repository's published ones. */
	publicKey?: string;
	/** With several issuers in the discovery: the one to log in with (as ATTACH's ISSUER). */
	issuer?: string;
	/** A loopback service (and repository) over plain http: development only. */
	insecureHttp?: boolean;
	/** For tests and unusual hosts: the fetch, the login, the repository's revision and platform. */
	fetch?: Fetch;
	login?: PageLogin;
	revision?: string;
	platform?: string;
}

export type AttachOutcome = "attached" | "redirecting";

/**
 * Attach `path` (`tresor:host[:port][/base]`) as `options.as`. "redirecting" when the page is on its way to the IdP:
 * it comes back to the same page, which calls attachTresor again to finish.
 */
export async function attachTresor(db: Database, path: string, options: AttachOptions): Promise<AttachOutcome> {
	const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
	const insecureHttp = options.insecureHttp ?? false;
	const host = serviceHost(path);
	const conn = await db.connect();
	try {
		if (options.from) {
			const load: LoadOptions = {
				publicKey: options.publicKey,
				revision: options.revision,
				platform: options.platform,
				insecureHttp,
				fetch: fetchImpl,
			};
			await loadTresor(db, conn, options.from, load);
		}
		const discovery = await readDiscovery(path, insecureHttp, fetchImpl);
		const issuer = chooseIssuer(discovery, options.issuer, host);
		checkTransport("issuer", issuer.issuer, insecureHttp);
		const refresh = await (options.login ?? oidcLogin)(issuer, options);
		if (refresh === null) {
			return "redirecting";
		}
		await handOver(conn, path, refresh, issuer.issuer, insecureHttp);
		const attachOptions = [`ISSUER ${literal(issuer.issuer)}`];
		if (insecureHttp) {
			attachOptions.push("INSECURE_HTTP true");
		}
		await conn.query(`ATTACH ${literal("tresor:" + host)} AS ${identifier(options.as)} (${attachOptions.join(", ")})`);
		return "attached";
	} finally {
		await conn.close();
	}
}

/** The login handed to tresor: a prepared statement, the token a parameter - never in a statement's text. */
async function handOver(conn: Connection, path: string, refresh: string, issuer: string, insecureHttp: boolean) {
	const statement = await conn.prepare("FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)");
	try {
		await statement.query(path, refresh, issuer, insecureHttp);
	} finally {
		await statement.close();
	}
}
