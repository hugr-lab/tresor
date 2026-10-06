// attachTresor (tresor specs/020): what a web page calls to have tresor attached in its DuckDB-wasm as the person
// logged in to the organisation's identity provider. After it, everything is as in the CLI - corp.secrets(),
// corp.whoami(), variables, the secrets in DuckDB's lookup - and tresor renews the login itself.
//
// The order:
//   - the service's discovery (small) and its issuer;
//   - on the page's return from the IdP: the code exchanged at once (it lives for a minute) - else the page is sent
//     to the IdP, and nothing else is fetched on the way out;
//   - tresor fetched, verified and loaded: nothing reaches tresor before its signature is checked;
//   - the login handed over, and the ATTACH.

import { type Connection, type Database, identifier, literal } from "./duckdb.js";
import { type LoginOptions, type PageLogin, oidcLogin } from "./login.js";
import { type LoadOptions, loadTresor } from "./repository.js";
import { type Fetch, checkTransport, chooseIssuer, readDiscovery, serviceHost } from "./service.js";

export interface AttachOptions extends LoginOptions {
	/** The catalog's name: `ATTACH … AS <as>`. */
	as: string;
	/** The extension repository to load tresor from; without it tresor must be loaded already. */
	from?: string;
	/** The keys to trust, pinned in the page (PEM or compact): the production mode. Without it, the repository's. */
	publicKey?: string | readonly string[];
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

// one attach of a service into a catalog at a time per database: a second call (React's StrictMode, a double
// click) gets the first one's outcome instead of consuming the IdP's answer twice
const inFlight = new WeakMap<Database, Map<string, Promise<AttachOutcome>>>();

/**
 * Attach `path` (`tresor:host[:port][/base]`) as `options.as`. "redirecting" when the page is being sent to the IdP:
 * it comes back to the same page, which calls attachTresor again to finish.
 */
export async function attachTresor(db: Database, path: string, options: AttachOptions): Promise<AttachOutcome> {
	let calls = inFlight.get(db);
	if (!calls) {
		calls = new Map();
		inFlight.set(db, calls);
	}
	const key = serviceHost(path) + "\u0000" + options.as;
	const running = calls.get(key);
	if (running) {
		return running;
	}
	const call = attachOnce(db, path, options).finally(() => calls.delete(key));
	calls.set(key, call);
	return call;
}

async function attachOnce(db: Database, path: string, options: AttachOptions): Promise<AttachOutcome> {
	const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
	const insecureHttp = options.insecureHttp ?? false;
	const login = options.login ?? oidcLogin;
	const service = "tresor:" + serviceHost(path);
	const discovery = await readDiscovery(service, insecureHttp, fetchImpl);
	const issuer = chooseIssuer(discovery, options.issuer, serviceHost(path));
	checkTransport("issuer", issuer.issuer, insecureHttp);
	const refresh = await login.complete(issuer, options);
	if (refresh === null) {
		await login.start(issuer, options);
		return "redirecting";
	}
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
		await handOver(conn, service, refresh, issuer.issuer, insecureHttp);
		const attachOptions = [`ISSUER ${literal(issuer.issuer)}`];
		if (insecureHttp) {
			attachOptions.push("INSECURE_HTTP true");
		}
		await conn.query(`ATTACH ${literal(service)} AS ${identifier(options.as)} (${attachOptions.join(", ")})`);
		return "attached";
	} finally {
		await conn.close();
	}
}

/** The login handed to tresor: a prepared statement, the token a parameter - never in a statement's text. */
async function handOver(conn: Connection, service: string, refresh: string, issuer: string, insecureHttp: boolean) {
	const statement = await conn.prepare("FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)");
	try {
		await statement.query(service, refresh, issuer, insecureHttp);
	} finally {
		await statement.close();
	}
}
