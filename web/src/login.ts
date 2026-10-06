// The page's login, with the identity provider directly (never through the secrets service): authorization code
// with PKCE (oidc-client-ts), back to the page. With the IdP's session alive the redirect asks nothing. Tokens are
// kept in memory only - never in the page's storage - and handed to tresor; the page keeps none of them.

import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";

import type { Issuer } from "./service.js";

export interface LoginOptions {
	/** Where the IdP sends the person back: the page itself by default. */
	redirectUri?: string;
	/** A page that completes a silent (iframe) login; without it the login is a redirect. */
	silentRedirectUri?: string;
}

/** The refresh token of a login, or null when the page is on its way to the IdP (it comes back to finish). */
export type PageLogin = (issuer: Issuer, options: LoginOptions) => Promise<string | null>;

function hasAuthorizationResponse(url: URL): boolean {
	return url.searchParams.has("state") && (url.searchParams.has("code") || url.searchParams.has("error"));
}

/** The default login: oidc-client-ts against the discovery's issuer and people's client. */
export const oidcLogin: PageLogin = async (issuer, options) => {
	if (!issuer.client_id) {
		throw new Error(`tresor: ${issuer.issuer} names no client_id for people to log in with`);
	}
	if (issuer.human_flows && !issuer.human_flows.includes("authorization_code")) {
		throw new Error(`tresor: ${issuer.issuer} offers no authorization_code login for people`);
	}
	const here = new URL(window.location.href);
	const redirectUri = options.redirectUri ?? here.origin + here.pathname;
	const manager = new UserManager({
		authority: issuer.issuer,
		client_id: issuer.client_id,
		redirect_uri: redirectUri,
		silent_redirect_uri: options.silentRedirectUri,
		response_type: "code",
		scope: (issuer.scopes ?? ["openid", "offline_access"]).join(" "),
		extraQueryParams: issuer.audience_parameter && issuer.audience ? { audience: issuer.audience } : undefined,
		automaticSilentRenew: false,
		loadUserInfo: false,
		// the tokens live in this tab's memory until handed over: a page's storage keeps none
		userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
	});
	let user = null;
	if (hasAuthorizationResponse(here)) {
		// back from the IdP: the code (PKCE) is exchanged, and the URL loses it
		user = await manager.signinRedirectCallback(here.href);
		for (const name of ["code", "state", "session_state", "iss", "error", "error_description"]) {
			here.searchParams.delete(name);
		}
		window.history.replaceState(window.history.state, "", here.href);
	} else if (options.silentRedirectUri) {
		try {
			user = await manager.signinSilent();
		} catch {
			user = null; // no IdP session reachable silently: the redirect below
		}
	}
	if (!user) {
		await manager.signinRedirect();
		return null;
	}
	const refresh = user.refresh_token;
	await manager.removeUser();
	if (!refresh) {
		throw new Error(
			`tresor: ${issuer.issuer} issued no refresh token - the client must allow them (offline_access, a SPA client)`,
		);
	}
	return refresh;
};
