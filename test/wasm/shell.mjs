// specs/042: tresor's wasm build, LOADed by DuckDB-wasm (its shell, at the commit test_wasm.sh pins) in Chromium,
// against the fake service on the same origin: the page's login handed over (tresor_web_login), ATTACH, whoami,
// the secrets, a variable. Run by scripts/ci/test_wasm.sh; the base URL is the fake's.
import { chromium } from 'playwright';

const base = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();
const logs = [];
page.on('console', (m) => logs.push(`[${m.type()}] ${m.text()}`));
page.on('pageerror', (e) => logs.push(`[pageerror] ${e.message}`));
let failures = 0;

try {
	await page.goto(`${base}/web/index.html?allowUnsignedExtensions=true`);
	// the engine (the worker) and the shell's own wasm, which reads a value out of an answer
	await page.waitForFunction(() => workerReady && wasmModule && initDone, null, { timeout: 120000 });

	// One statement, through the shell's worker; its answer is the worker's wire format: a first byte of 1 is an error
	// (a u32 length, then the message), else a result. A value is asked for wrapped in markers and found in the
	// result's bytes as text, which needs no decoding of the format.
	const query = (sql) =>
		page.evaluate(async (sql) => {
			const data = await sendToWorkerAsync('query', { sql, castMode: 0 });
			const bytes = new Uint8Array(data || []);
			if (bytes.length >= 5 && bytes[0] === 1) {
				const length = new DataView(bytes.buffer, bytes.byteOffset + 1, 4).getUint32(0, true);
				return { ok: false, error: new TextDecoder().decode(bytes.subarray(5, 5 + length)) };
			}
			return { ok: true, text: new TextDecoder().decode(bytes) };
		}, sql);
	const run = async (sql) => {
		const answer = await query(sql);
		return answer.ok ? { ok: true } : answer;
	};
	const value = async (sql) => {
		// aliased: the answer carries the column's name too, which must not hold the marker
		const answer = await query(`SELECT 'VALUE<' || coalesce((${sql})::VARCHAR, 'NULL') || '>' AS v`);
		if (!answer.ok) {
			return answer;
		}
		const found = /VALUE<([^>]*)>/.exec(answer.text);
		return found ? { ok: true, value: found[1] } : { ok: false, error: 'no value in the answer' };
	};
	const check = (ok, what, detail) => {
		console.log(`${ok ? '  ok  ' : '  FAIL'} ${what}${detail ? ': ' + detail : ''}`);
		if (!ok) failures++;
	};

	const host = new URL(base).host;
	const loaded = await run(`LOAD '${base}/web/tresor.duckdb_extension.wasm'`);
	check(loaded.ok, 'LOAD tresor in DuckDB-wasm', loaded.error);
	const version = await value('SELECT tresor_version()');
	check(version.ok && !!version.value, 'tresor_version()', version.error || version.value);
	const client = await value("SELECT current_setting('tresor_http_client')");
	check(client.ok && client.value === 'duckdb', "the HTTP client is DuckDB's (the browser's)", client.error || client.value);
	const keychain = await value("SELECT current_setting('tresor_keychain')");
	check(keychain.ok && keychain.value === 'memory', 'the keychain is memory', keychain.error || keychain.value);

	// the page's login: a refresh token the fake IdP issued for the person (as oidc-client-ts would have it)
	const refresh = await page.evaluate(async () => (await (await fetch('/_page_login')).json()).refresh_token);
	const handed = await value(
		`SELECT count(*) FROM tresor_web_login('tresor:${host}', '${refresh}', insecure_http := true)`,
	);
	check(handed.ok && handed.value === '1', 'tresor_web_login hands the login over', handed.error);
	const attached = await run(`ATTACH 'tresor:${host}' AS corp (INSECURE_HTTP true)`);
	check(attached.ok, 'ATTACH with no browser of its own', attached.error);
	const login = await value('SELECT login FROM corp.whoami()');
	check(login.ok && login.value === 'remembered', 'whoami: the handed-over login, renewed by tresor', login.error || login.value);
	const subject = await value('SELECT subject FROM corp.whoami()');
	check(subject.ok && !!subject.value, 'whoami names the person', subject.error || subject.value);
	const secrets = await value('SELECT count(*) FROM corp.secrets()');
	check(secrets.ok && Number(secrets.value) > 0, 'the secrets the role may use', secrets.error || secrets.value);
	const lookup = await value("SELECT count(*) FROM duckdb_secrets() WHERE storage = 'corp'");
	check(lookup.ok && Number(lookup.value) > 0, "the service's secrets in DuckDB's lookup", lookup.error || lookup.value);
	const variable = await value("SELECT corp.variable('lake_bucket')");
	check(variable.ok && variable.value !== 'NULL', 'a variable', variable.error || variable.value);
	const refused = await value("SELECT count(*) FROM tresor_login('tresor:" + host + "', insecure_http := true)");
	check(!refused.ok, "a person's login of tresor's own is refused in wasm (the page logs in)", refused.error);
	const detached = await run('DETACH corp');
	check(detached.ok, 'DETACH', detached.error);
} catch (e) {
	console.log('  FAIL ' + e.message);
	failures++;
} finally {
	if (failures) {
		console.log('the page said:\n' + logs.slice(-40).join('\n'));
	}
	await browser.close();
}
console.log(failures ? `FAILED: ${failures}` : 'all passed');
process.exit(failures ? 1 : 0);
