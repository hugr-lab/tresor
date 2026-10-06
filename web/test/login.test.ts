import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isAuthorizationResponse, oidcLogin } from "../src/login.js";

const PAGE = "https://app.example/analytics";

describe("the page's login", () => {
	it("knows the IdP's answer: at the redirect URI, with state and a code or an error", () => {
		assert.equal(isAuthorizationResponse(PAGE + "?code=c&state=s", PAGE), true);
		assert.equal(isAuthorizationResponse(PAGE + "?error=access_denied&state=s", PAGE), true);
		assert.equal(isAuthorizationResponse(PAGE + "?code=c", PAGE), false, "no state");
		assert.equal(isAuthorizationResponse(PAGE + "?state=s&tab=2", PAGE), false, "neither a code nor an error");
		// an app's own parameters on another page are not the IdP's answer
		assert.equal(isAuthorizationResponse("https://app.example/other?code=c&state=s", PAGE), false);
		assert.equal(isAuthorizationResponse("https://evil.example/analytics?code=c&state=s", PAGE), false);
	});

	it("uses an answer once: the URL is cleaned whatever came of it, so a reload starts a new login", async () => {
		const replaced: string[] = [];
		const original = (globalThis as { window?: unknown }).window;
		(globalThis as { window?: unknown }).window = {
			location: { href: PAGE + "?code=c&state=s&session_state=x&tab=2" },
			history: { state: null, replaceState: (_: unknown, __: string, url: string) => replaced.push(url) },
		};
		try {
			// no stored state for this answer: the exchange fails - and the answer is gone from the URL anyway
			await assert.rejects(oidcLogin.complete({ issuer: "https://idp.example", client_id: "spa" }, {}));
			assert.deepEqual(replaced, [PAGE + "?tab=2"]);
		} finally {
			(globalThis as { window?: unknown }).window = original;
		}
	});

	it("is not a return when the page carries no answer", async () => {
		const original = (globalThis as { window?: unknown }).window;
		(globalThis as { window?: unknown }).window = { location: { href: PAGE }, history: { state: null } };
		try {
			assert.equal(await oidcLogin.complete({ issuer: "https://idp.example", client_id: "spa" }, {}), null);
		} finally {
			(globalThis as { window?: unknown }).window = original;
		}
	});

	it("refuses an issuer without a people's client, or without the code flow", async () => {
		const original = (globalThis as { window?: unknown }).window;
		(globalThis as { window?: unknown }).window = { location: { href: PAGE }, history: { state: null } };
		try {
			await assert.rejects(oidcLogin.start({ issuer: "https://idp.example" }, {}), /no client_id/);
			await assert.rejects(
				oidcLogin.start({ issuer: "https://idp.example", client_id: "spa", human_flows: ["device_code"] }, {}),
				/no authorization_code/,
			);
		} finally {
			(globalThis as { window?: unknown }).window = original;
		}
	});
});
