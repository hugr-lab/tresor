// The service an ATTACH names, read as tresor reads it (src/tresor_login.cpp: ParseAttach, Discover, ChooseIssuer):
// `tresor:host[:port][/base]`, https implied - http only for a loopback host, when asked for (`insecureHttp`).

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export interface Issuer {
	issuer: string;
	client_id?: string;
	scopes?: string[];
	audience?: string;
	audience_parameter?: boolean;
	human_flows?: string[];
}

export interface Discovery {
	protocol?: string;
	api: string;
	issuers: Issuer[];
	capabilities?: Record<string, boolean>;
}

const MAX_DOCUMENT = 65536;

/** The `host[:port][/base]` of `tresor:host[:port][/base]`; refused as tresor refuses it. */
export function serviceHost(path: string): string {
	let host = path.toLowerCase().startsWith("tresor:") ? path.slice(7) : path;
	host = host.replace(/\/+$/, "");
	if (!host) {
		throw new Error("tresor: ATTACH needs the service - 'tresor:<host>[:port][/base]'");
	}
	if (host.includes("://")) {
		throw new Error("tresor: name the service without a scheme - 'tresor:<host>[:port][/base]', https is implied");
	}
	if (/[@?#\\\s\x00-\x1f']/.test(host)) {
		throw new Error(`tresor: '${host}' is not a service name - 'tresor:<host>[:port][/base]'`);
	}
	return host;
}

/** Is the host part of `host[:port][/base]` (or of a URL's host) a loopback name. */
export function isLoopback(host: string): boolean {
	let name = host.split("/")[0];
	if (name.startsWith("[")) {
		name = name.slice(1, name.indexOf("]"));
	} else {
		name = name.split(":")[0];
	}
	name = name.toLowerCase();
	// exactly tresor's (IsLoopbackName): a page must not log in for a service tresor then refuses
	return name === "localhost" || name === "::1" || name === "127.0.0.1";
}

/** https, or http on loopback when asked for: the rule for every URL a login sends something to. */
export function checkTransport(what: string, url: string, insecureHttp: boolean): void {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`tresor: the ${what} '${url}' is not a URL`);
	}
	if (parsed.protocol === "https:") {
		return;
	}
	if (parsed.protocol === "http:" && insecureHttp && isLoopback(parsed.host)) {
		return;
	}
	throw new Error(`tresor: the ${what} '${url}' is not https (http only for a loopback host, with insecureHttp)`);
}

/** A small JSON document; `follow` lets a redirect through (an extension repository served from a CDN). */
async function readJson(fetchImpl: Fetch, url: string, what: string, follow = false): Promise<unknown> {
	const response = await fetchImpl(url, { headers: { Accept: "application/json" }, redirect: follow ? "follow" : "error" });
	if (!response.ok) {
		throw new Error(`tresor: ${what} at ${url} answered ${response.status}`);
	}
	const text = await response.text();
	if (text.length > MAX_DOCUMENT) {
		throw new Error(`tresor: ${what} at ${url} is too large`);
	}
	try {
		return JSON.parse(text);
	} catch {
		throw new Error(`tresor: ${what} at ${url} is not JSON`);
	}
}

/** The service's discovery (protocol, Discovery), with the protocol's checks on `api` and the issuers. */
export async function readDiscovery(path: string, insecureHttp: boolean, fetchImpl: Fetch): Promise<Discovery> {
	const host = serviceHost(path);
	if (insecureHttp && !isLoopback(host)) {
		throw new Error(`tresor: insecureHttp is for a loopback service only, not ${host}`);
	}
	const base = (insecureHttp ? "http://" : "https://") + host;
	const doc = (await readJson(fetchImpl, base + "/.well-known/duckdb-secrets", "the discovery")) as Discovery;
	if (doc?.protocol !== "duckdb-secrets/1") {
		throw new Error(`tresor: ${host} speaks "${doc?.protocol ?? ""}", this client speaks duckdb-secrets/1`);
	}
	if (typeof doc.api !== "string" || !Array.isArray(doc.issuers) || doc.issuers.length === 0) {
		throw new Error(`tresor: the discovery of ${host} names no api or no issuer`);
	}
	checkTransport("api", doc.api, insecureHttp);
	return doc;
}

const stripSlashes = (url: string) => url.replace(/\/+$/, "");

/** The issuer a person logs in with: the one asked for, or the only one there is. */
export function chooseIssuer(discovery: Discovery, asked: string | undefined, host: string): Issuer {
	if (asked) {
		const found = discovery.issuers.find((issuer) => stripSlashes(issuer.issuer) === stripSlashes(asked));
		if (!found) {
			throw new Error(`tresor: ${host} does not accept the issuer ${asked}`);
		}
		return found;
	}
	if (discovery.issuers.length > 1) {
		throw new Error(
			`tresor: ${host} accepts several issuers - name one (issuer): ` +
				discovery.issuers.map((issuer) => issuer.issuer).join(", "),
		);
	}
	return discovery.issuers[0];
}

export { readJson };
