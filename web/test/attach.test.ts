import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { attachTresor, type AttachOptions } from "../src/attach.js";
import type { Connection, Database, QueryResult, Statement } from "../src/duckdb.js";
import { runningDuckDB } from "../src/repository.js";
import type { Issuer } from "../src/service.js";
import { signedDigests } from "../src/signature.js";

const REPO = "https://ext.example";
const SERVICE = "tresor:secrets.example";
const ISSUER = "https://idp.example/realms/main";
const TOKEN = "rt-the-refresh-token-of-the-page";

const keys = generateKeyPairSync("rsa", {
	modulusLength: 2048,
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

async function signed(body: Uint8Array): Promise<Uint8Array> {
	const signature = sign("sha256", await signedDigests(body), keys.privateKey);
	const out = new Uint8Array(body.length + 256);
	out.set(body);
	out.set(signature, body.length);
	return out;
}

const extension = await signed(new Uint8Array(randomBytes(300_000)));

interface World {
	events: string[]; // the order things happened in: fetches, queries, the login's halves
	files: Record<string, unknown>;
	fetched: string[];
	queries: string[];
	prepared: Array<{ sql: string; params: unknown[] }>;
	registered: string[];
	dropped: string[];
	closed: number;
	logins: Issuer[];
}

function world(overrides: Record<string, unknown> = {}): { w: World; db: Database; options: AttachOptions } {
	const w: World = {
		files: {
			[REPO + "/.well-known/duckdb-extension-repo.json"]: { signature_keys: [keys.publicKey] },
			[REPO + "/v2.0.0/wasm_eh/tresor.duckdb_extension.wasm"]: extension,
			"https://secrets.example/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/1",
				api: "https://secrets.example",
				issuers: [{ issuer: ISSUER, client_id: "duckdb", scopes: ["openid", "offline_access"] }],
			},
			...overrides,
		},
		events: [],
		fetched: [],
		queries: [],
		prepared: [],
		registered: [],
		dropped: [],
		closed: 0,
		logins: [],
	};
	const result = (rows: Array<Record<string, unknown>>): QueryResult => ({ toArray: () => rows });
	const conn: Connection = {
		async query(sql) {
			w.queries.push(sql);
			w.events.push("query " + sql.split(" ")[0]);
			if (sql.includes("pragma_version")) {
				return result([{ library_version: "v2.0.0", source_id: "eb0d9df" }]);
			}
			if (sql.includes("pragma_platform")) {
				return result([{ platform: "wasm_eh" }]);
			}
			return result([]);
		},
		async prepare(sql) {
			const statement: Statement = {
				async query(...params) {
					w.prepared.push({ sql, params });
					w.events.push("hand over");
					return result([]);
				},
				async close() {},
			};
			return statement;
		},
		async close() {
			w.closed++;
		},
	};
	const db: Database = {
		connect: async () => conn,
		registerFileBuffer: async (name, buffer) => {
			w.registered.push(name);
			// what LOAD will fetch is the name itself: it must answer exactly the registered (verified) bytes
			const fetched = new Uint8Array(await (await fetch(name)).arrayBuffer());
			assert.deepEqual(fetched, buffer);
		},
		dropFile: async (name) => {
			w.dropped.push(name);
		},
	};
	const fetchStub = async (url: string) => {
		w.fetched.push(url);
		w.events.push("fetch " + url);
		const body = w.files[url];
		if (body === undefined) {
			return new Response("", { status: 404 });
		}
		return body instanceof Uint8Array ? new Response(body as BodyInit) : new Response(JSON.stringify(body));
	};
	const options: AttachOptions = {
		as: "corp",
		from: REPO,
		fetch: fetchStub,
		login: {
			complete: async (issuer) => {
				w.logins.push(issuer);
				w.events.push("login complete");
				return TOKEN;
			},
			start: async () => {
				w.events.push("login start");
			},
		},
	};
	return { w, db, options };
}

describe("attachTresor", () => {
	it("loads the verified extension, hands the login over as a parameter, and attaches", async () => {
		const { w, db, options } = world();
		assert.equal(await attachTresor(db, SERVICE, options), "attached");
		assert.equal(w.registered.length, 1);
		assert.match(w.registered[0], /^blob:.*#\/tresor\.duckdb_extension\.wasm$/);
		assert.deepEqual(w.dropped, w.registered);
		assert.ok(w.queries.includes(`LOAD '${w.registered[0]}'`));
		await assert.rejects(fetch(w.registered[0]), "the object URL is revoked after the LOAD");
		assert.equal(w.logins[0].issuer, ISSUER);
		assert.deepEqual(w.prepared, [
			{ sql: "FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)", params: [SERVICE, TOKEN, ISSUER, false] },
		]);
		assert.equal(w.queries.at(-1), `ATTACH 'tresor:secrets.example' AS "corp" (ISSUER '${ISSUER}')`);
		assert.ok(!w.queries.some((sql) => sql.includes(TOKEN)), "the token is in no statement's text");
		assert.equal(w.closed, 1);
		// the order: the discovery, the code exchanged at once, then tresor verified and loaded, then the hand-over
		const order = w.events.map((event) => event.replace(/^fetch https:\/\/ext\.example.*/, "fetch repository"));
		const at = (event: string) => order.indexOf(event);
		assert.ok(at("fetch https://secrets.example/.well-known/duckdb-secrets") < at("login complete"));
		assert.ok(at("login complete") < at("fetch repository"), "the code is exchanged before the slow download");
		assert.ok(at("fetch repository") < at("query LOAD"));
		assert.ok(at("query LOAD") < at("hand over"), "nothing reaches tresor before it is verified and loaded");
		assert.ok(at("hand over") < at("query ATTACH"));
	});

	it("loads nothing, and logs nobody in, when the extension is not the repository's", async () => {
		const tampered = extension.slice();
		tampered[10] ^= 1;
		const { w, db, options } = world({ [REPO + "/v2.0.0/wasm_eh/tresor.duckdb_extension.wasm"]: tampered });
		await assert.rejects(attachTresor(db, SERVICE, options), /not signed by the trusted keys/);
		assert.deepEqual(w.registered, []);
		assert.ok(!w.queries.some((sql) => sql.startsWith("LOAD")));
		assert.deepEqual(w.prepared, [], "nothing handed over");
		assert.equal(w.closed, 1, "the connection is closed whatever fails");
	});

	it("trusts a pinned key instead of the repository's, and only it", async () => {
		const { w, db, options } = world();
		const other = generateKeyPairSync("rsa", {
			modulusLength: 2048,
			publicKeyEncoding: { type: "spki", format: "pem" },
			privateKeyEncoding: { type: "pkcs8", format: "pem" },
		});
		await assert.rejects(attachTresor(db, SERVICE, { ...options, publicKey: other.publicKey }), /not signed/);
		assert.ok(!w.fetched.some((url) => url.endsWith("duckdb-extension-repo.json")), "the pinned key replaces them");
		assert.equal(await attachTresor(db, SERVICE, { ...options, publicKey: keys.publicKey }), "attached");
	});

	it("without `from`, loads nothing: tresor is loaded already", async () => {
		const { w, db, options } = world();
		assert.equal(await attachTresor(db, SERVICE, { ...options, from: undefined }), "attached");
		assert.deepEqual(w.registered, []);
		assert.ok(!w.fetched.some((url) => url.startsWith(REPO)));
	});

	it("is 'redirecting' while the page goes to the IdP: nothing downloaded, nothing handed over", async () => {
		const { w, db, options } = world();
		let started = 0;
		const login = { complete: async () => null, start: async () => void started++ };
		assert.equal(await attachTresor(db, SERVICE, { ...options, login }), "redirecting");
		assert.equal(started, 1);
		assert.ok(!w.fetched.some((url) => url.startsWith(REPO)), "the extension is not fetched on the way out");
		assert.deepEqual(w.prepared, []);
		assert.ok(!w.queries.some((sql) => sql.startsWith("ATTACH")));
	});

	it("runs one attach of a service at a time: a second call shares the first's outcome", async () => {
		const { w, db, options } = world();
		const [first, second] = await Promise.all([attachTresor(db, SERVICE, options), attachTresor(db, SERVICE, options)]);
		assert.deepEqual([first, second], ["attached", "attached"]);
		assert.equal(w.logins.length, 1, "the IdP's answer is consumed once");
		assert.equal(await attachTresor(db, SERVICE, options), "attached", "and a later call runs anew");
		assert.equal(w.logins.length, 2);
	});

	it("trusts several pinned keys, in one PEM string", async () => {
		const { db, options } = world();
		const other = generateKeyPairSync("rsa", {
			modulusLength: 2048,
			publicKeyEncoding: { type: "spki", format: "pem" },
			privateKeyEncoding: { type: "pkcs8", format: "pem" },
		});
		assert.equal(await attachTresor(db, SERVICE, { ...options, publicKey: other.publicKey + keys.publicKey }), "attached");
	});

	it("refuses a service that speaks another protocol, before any login", async () => {
		const { w, db, options } = world({
			"https://secrets.example/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/2",
				api: "https://secrets.example",
				issuers: [{ issuer: ISSUER, client_id: "duckdb" }],
			},
		});
		await assert.rejects(attachTresor(db, SERVICE, options), /speaks "duckdb-secrets\/2"/);
		assert.deepEqual(w.logins, []);
	});

	it("asks which issuer when the service accepts several, as ATTACH does", async () => {
		const several = {
			"https://secrets.example/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/1",
				api: "https://secrets.example",
				issuers: [
					{ issuer: ISSUER, client_id: "duckdb" },
					{ issuer: "https://login.example/tenant/v2.0", client_id: "spa" },
				],
			},
		};
		const first = world(several);
		await assert.rejects(attachTresor(first.db, SERVICE, first.options), /several issuers - name one/);
		assert.deepEqual(first.w.logins, []);
		const second = world(several);
		await attachTresor(second.db, SERVICE, { ...second.options, issuer: "https://login.example/tenant/v2.0/" });
		assert.equal(second.w.logins[0].client_id, "spa");
		assert.match(second.w.queries.at(-1) ?? "", /ISSUER 'https:\/\/login.example\/tenant\/v2.0'/);
	});

	it("keeps ATTACH's transport rules: https, http only for loopback when asked", async () => {
		const { db, options } = world();
		await assert.rejects(attachTresor(db, "https://secrets.example", options), /without a scheme/);
		await assert.rejects(attachTresor(db, "tresor:secrets.example", { ...options, insecureHttp: true }), /loopback/);
		// loopback is tresor's: 127.0.0.1, ::1, localhost - not the rest of 127/8, which tresor would refuse after a login
		await assert.rejects(attachTresor(db, "tresor:127.0.0.2:8443", { ...options, insecureHttp: true }), /loopback/);
		await assert.rejects(attachTresor(db, SERVICE, { ...options, from: "http://ext.example" }), /not https/);
		const plainApi = world({
			"https://secrets.example/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/1",
				api: "http://secrets.example",
				issuers: [{ issuer: ISSUER, client_id: "duckdb" }],
			},
		});
		await assert.rejects(attachTresor(plainApi.db, SERVICE, plainApi.options), /api 'http:\/\/secrets.example' is not https/);
		const plainIssuer = world({
			"https://secrets.example/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/1",
				api: "https://secrets.example",
				issuers: [{ issuer: "http://idp.example", client_id: "duckdb" }],
			},
		});
		await assert.rejects(attachTresor(plainIssuer.db, SERVICE, plainIssuer.options), /issuer 'http:\/\/idp.example'/);
		assert.deepEqual(plainIssuer.w.logins, []);
	});

	it("speaks http to a loopback service when asked, and says so to tresor", async () => {
		const { w, db, options } = world({
			"http://127.0.0.1:8443/.well-known/duckdb-secrets": {
				protocol: "duckdb-secrets/1",
				api: "http://127.0.0.1:8443",
				issuers: [{ issuer: "http://127.0.0.1:18080/realms/tresor", client_id: "duckdb" }],
			},
		});
		const outcome = await attachTresor(db, "tresor:127.0.0.1:8443", { ...options, from: undefined, insecureHttp: true });
		assert.equal(outcome, "attached");
		assert.equal(w.prepared[0].params[3], true);
		assert.match(w.queries.at(-1) ?? "", /INSECURE_HTTP true\)$/);
	});

	it("quotes the catalog's name and refuses a service name that could break out of the statement", async () => {
		const { w, db, options } = world();
		await attachTresor(db, SERVICE, { ...options, as: 'my "corp"' });
		assert.match(w.queries.at(-1) ?? "", / AS "my ""corp""" /);
		await assert.rejects(attachTresor(db, "tresor:secrets.example'; DROP TABLE x; --", options), /not a service name/);
	});
});

describe("the running DuckDB's place in a repository", () => {
	const conn = (library: string) =>
		({
			query: async (sql: string) => ({
				toArray: () =>
					sql.includes("pragma_version")
						? [{ library_version: library, source_id: "eb0d9df" }]
						: [{ platform: "wasm_mvp" }],
			}),
		}) as unknown as Connection;
	it("is a release's tag, or a development build's source id", async () => {
		assert.deepEqual(await runningDuckDB(conn("v2.0.0")), { revision: "v2.0.0", platform: "wasm_mvp" });
		assert.deepEqual(await runningDuckDB(conn("2.0.1")), { revision: "v2.0.1", platform: "wasm_mvp" });
		assert.deepEqual(await runningDuckDB(conn("v2.0.0-dev123")), { revision: "eb0d9df", platform: "wasm_mvp" });
		// DuckDB's rule: a release is a version without "-dev" - a release candidate's tag is its directory
		assert.deepEqual(await runningDuckDB(conn("v2.0.0-rc1")), { revision: "v2.0.0-rc1", platform: "wasm_mvp" });
	});
});
