// The page's login, with the identity provider directly (never through the secrets service): authorization code
// with PKCE (oidc-client-ts), back to the page. With the IdP's session alive the round trip asks nothing.
//
// Two halves, because a redirect leaves the page: `start` sends it to the IdP; `complete`, on the page's return,
// exchanges the code - first thing, before anything slow, as a code lives for a minute. The tokens are never
// stored: only the PKCE state is (in the page's storage, as oidc-client-ts keeps it), and the refresh token goes
// straight to tresor.

import { ErrorResponse, OidcClient, type OidcClientSettings } from "oidc-client-ts";

import type { Issuer } from "./service.js";

export interface LoginOptions {
	/** Where the IdP sends the person back: the page itself by default. */
	redirectUri?: string;
}

export interface PageLogin {
	/** On the page's return from the IdP: the refresh token; null when this load is no such return. */
	complete(issuer: Issuer, options: LoginOptions): Promise<string | null>;
	/** Send the page to the IdP (it comes back to `redirectUri`, and `complete` finishes). */
	start(issuer: Issuer, options: LoginOptions): Promise<void>;
}

const RESPONSE_PARAMETERS = ["code", "state", "session_state", "iss", "error", "error_description", "error_uri"];

function redirectUriOf(options: LoginOptions): string {
	const here = new URL(window.location.href);
	return options.redirectUri ?? here.origin + here.pathname;
}

function clientFor(issuer: Issuer, options: LoginOptions): OidcClient {
	if (!issuer.client_id) {
		throw new Error(`tresor: ${issuer.issuer} names no client_id for people to log in with`);
	}
	if (issuer.human_flows && !issuer.human_flows.includes("authorization_code")) {
		throw new Error(`tresor: ${issuer.issuer} offers no authorization_code login for people`);
	}
	const settings: OidcClientSettings = {
		authority: issuer.issuer,
		client_id: issuer.client_id,
		redirect_uri: redirectUriOf(options),
		response_type: "code",
		scope: (issuer.scopes ?? ["openid", "offline_access"]).join(" "),
		extraQueryParams: issuer.audience_parameter && issuer.audience ? { audience: issuer.audience } : undefined,
	};
	return new OidcClient(settings);
}

/** Is this page load the IdP's answer: at the redirect URI, with its `state` and a `code` or an `error`. */
export function isAuthorizationResponse(href: string, redirectUri: string): boolean {
	const here = new URL(href);
	const back = new URL(redirectUri, href);
	return (
		here.origin === back.origin &&
		here.pathname === back.pathname &&
		here.searchParams.has("state") &&
		(here.searchParams.has("code") || here.searchParams.has("error"))
	);
}

/** The default login: oidc-client-ts against the discovery's issuer and people's client. */
export const oidcLogin: PageLogin = {
	async complete(issuer, options) {
		const href = window.location.href;
		if (!isAuthorizationResponse(href, redirectUriOf(options))) {
			return null;
		}
		try {
			const response = await clientFor(issuer, options).processSigninResponse(href);
			if (!response.refresh_token) {
				throw new Error(
					`tresor: ${issuer.issuer} issued no refresh token - its client must allow them (offline_access, a ` +
						"SPA client)",
				);
			}
			return response.refresh_token;
		} catch (error) {
			if (error instanceof ErrorResponse) {
				const detail = error.error_description ? ` (${error.error_description})` : "";
				throw new Error(`tresor: the identity provider ended the login: ${error.error}${detail}`);
			}
			throw error;
		} finally {
			// the answer is used once, whatever came of it: a reload must start a login, not replay this one
			const clean = new URL(href);
			for (const name of RESPONSE_PARAMETERS) {
				clean.searchParams.delete(name);
			}
			window.history.replaceState(window.history.state, "", clean.href);
		}
	},
	async start(issuer, options) {
		const request = await clientFor(issuer, options).createSigninRequest({});
		window.location.assign(request.url);
	},
};
