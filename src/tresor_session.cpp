#include "tresor_session.hpp"
#include "tresor_remember.hpp"

#include "duckdb/common/exception.hpp"

#include <algorithm>
#include <chrono>

namespace duckdb {
namespace tresor {

namespace {

//! A token with less life than this is renewed before a call rather than sent to die on the way.
constexpr int64_t RENEW_MARGIN_SECONDS = 60;

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

} // namespace

string LoginFlowName(LoginFlow flow) {
	switch (flow) {
	case LoginFlow::BROWSER:
		return "browser";
	case LoginFlow::DEVICE:
		return "device";
	case LoginFlow::CLIENT_CREDENTIALS:
		return "client_credentials";
	case LoginFlow::TOKEN:
		return "token";
	case LoginFlow::REMEMBERED:
		return "remembered";
	}
	return "unknown";
}

TresorSession::TresorSession(ServiceInfo info_p, LoginFlow flow_p, oidc::TokenSet tokens_p, string client_secret_p)
    : info(std::move(info_p)), flow(flow_p), tokens(std::move(tokens_p)), issued_at(NowSeconds()),
      client_secret(std::move(client_secret_p)) {
}

string TresorSession::AccessToken(bool force) {
	if (closed) {
		throw InvalidInputException("tresor: the session to %s is closed (DETACHed)", info.host);
	}
	if (logged_out) {
		throw InvalidInputException("tresor: the login to %s is over - log in again: DETACH and ATTACH", info.host);
	}
	// renew a minute ahead - or at half-life, for tokens that live two minutes or less
	auto margin = MinValue<int64_t>(RENEW_MARGIN_SECONDS, MaxValue<int64_t>(0, (tokens.expires_at - issued_at) / 2));
	auto fresh = tokens.expires_at == 0 || tokens.expires_at - margin > NowSeconds();
	if (fresh && !force) {
		return tokens.access_token;
	}
	oidc::TokenSet renewed;
	switch (flow) {
	case LoginFlow::BROWSER:
	case LoginFlow::DEVICE:
	case LoginFlow::REMEMBERED:
		if (tokens.refresh_token.empty()) {
			throw InvalidInputException("tresor: the login to %s has expired and the identity provider issued no "
			                            "refresh token - log in again: DETACH and ATTACH",
			                            info.host);
		}
		{
			// a remembered login's chain is renewed by one caller at a time, from the token stored now: another
			// session (or process) may have rotated it since this one read it (specs/012)
			auto store = remember.lock();
			unique_lock<mutex> chain;
			if (store) {
				chain = unique_lock<mutex>(store->KeyLock(Key()));
				string current;
				if (store->Load(Key(), current) && current != tokens.refresh_token) {
					tokens.refresh_token.swap(current);
				}
				std::fill(current.begin(), current.end(), '\0');
			}
			// this service's scope: a remembered token was first minted for this service's login, and the IdP is asked
			// for what this service needs, never what an earlier grant happened to hold
			renewed = oidc::RefreshGrant(info.endpoints, info.client_id, "", tokens.refresh_token, info.scope);
			if (renewed.Ok() && renewed.refresh_token.empty()) {
				renewed.refresh_token = tokens.refresh_token; // RFC 6749 §6: a refresh may keep the old one
			}
			if (store && renewed.Ok() && renewed.refresh_token != tokens.refresh_token) {
				store->Store(Key(), renewed.refresh_token, remember_mode);
			}
			if (store && !renewed.Ok() && renewed.error_code == "invalid_grant") {
				store->Remove(Key(),
				              tokens.refresh_token); // only the dead one: never what another session stored since
			}
			break;
		}
	case LoginFlow::CLIENT_CREDENTIALS:
		renewed = oidc::ClientCredentials(info.endpoints, info.client_id, client_secret, info.scope);
		break;
	case LoginFlow::TOKEN:
		throw InvalidInputException("tresor: the token of the tresor secret for %s has expired or was refused - "
		                            "replace the secret and ATTACH again",
		                            info.host);
	}
	if (!renewed.Ok()) {
		if (renewed.error_code == "invalid_grant") {
			// the refresh chain is dead (revoked, expired, rotated elsewhere): only a new login helps - and a
			// remembered one is forgotten
			tokens = oidc::TokenSet();
			logged_out = true;
			throw InvalidInputException("tresor: the login to %s is over (%s) - log in again: DETACH and ATTACH",
			                            info.host, renewed.error);
		}
		throw IOException("tresor: renewing the login to %s failed: %s", info.host, renewed.error);
	}
	tokens = std::move(renewed);
	issued_at = NowSeconds();
	return tokens.access_token;
}

ServiceResponse TresorSession::Call(const string &method, const string &path, const string &body,
                                    const std::map<std::string, std::string> &extra_headers, int timeout_seconds) {
	string used;
	for (int attempt = 0; attempt < 2; attempt++) {
		string token;
		{
			// the lock covers the token and its renewal only, never the request: a node serves many users'
			// sessions through one login, and one slow call must not hold up the others
			lock_guard<mutex> guard(lock);
			// after a 401, renew - unless another call already did while this one was on the wire
			token = AccessToken(attempt > 0 && tokens.access_token == used);
		}
		used = token;
		std::map<std::string, std::string> headers {{"Authorization", "Bearer " + token},
		                                            {"Accept", "application/json"}};
		for (auto &header : extra_headers) {
			headers[header.first] = header.second;
		}
		auto result = oidc::HttpSend(method, info.api + path, headers, body, body.empty() ? "" : "application/json",
		                             timeout_seconds);
		if (!result.error.empty()) {
			throw IOException("tresor: %s %s failed: %s", method, info.api + path, result.error);
		}
		if (result.status == 401 && attempt == 0) {
			continue; // the protocol's rule: refresh and retry once
		}
		if (result.status == 401 && extra_headers.count("Delegation")) {
			// the login was just renewed: the grant is what the service refuses - the caller's to handle
			ServiceResponse refused;
			refused.status = result.status;
			refused.body = std::move(result.body);
			return refused;
		}
		if (result.status == 401) {
			break;
		}
		ServiceResponse out;
		out.status = result.status;
		out.body = std::move(result.body);
		return out;
	}
	throw InvalidInputException("tresor: %s refused the renewed login (401) - log in again: DETACH and ATTACH",
	                            info.host);
}

oidc::TokenSet TresorSession::ExchangeForService(const string &subject_token, bool on_behalf_of, const string &scope) {
	string secret;
	{
		lock_guard<mutex> guard(lock);
		if (closed || flow != LoginFlow::CLIENT_CREDENTIALS) {
			oidc::TokenSet refused;
			refused.error = closed ? "the session is closed" : "only a client_credentials login exchanges tokens";
			return refused;
		}
		secret = client_secret;
	}
	oidc::TokenSet out;
	if (on_behalf_of) {
		out = oidc::OnBehalfOf(info.endpoints, info.client_id, secret, subject_token, scope);
	} else {
		// asked with a refresh token (specs/010): Keycloak binds the exchanged token to the user's SSO session
		// only then, and the service's own exchange for a downstream audience (a token for the user) needs that
		// session. The refresh token itself is dropped at once - the node never renews a user's token
		out =
		    oidc::TokenExchange(info.endpoints, info.client_id, secret, subject_token, info.audience, scope, "", true);
		if (!out.Ok() && out.error_code != "invalid_client" && out.error_code != "invalid_grant") {
			// an IdP that issues no refresh token by exchange, whatever it answers (its wording and code vary, and
			// a strict RFC 8693 answer is refused as invalid_token_type): the plain exchange. A bad client or a
			// dead subject token would fail that the same way
			out = oidc::TokenExchange(info.endpoints, info.client_id, secret, subject_token, info.audience, scope);
		}
	}
	std::fill(out.refresh_token.begin(), out.refresh_token.end(), '\0');
	out.refresh_token.clear();
	std::fill(secret.begin(), secret.end(), '\0');
	return out;
}

LoginKey TresorSession::Key() const {
	LoginKey key;
	key.issuer = info.issuer;
	while (!key.issuer.empty() && key.issuer.back() == '/') {
		key.issuer.pop_back();
	}
	key.client_id = info.client_id;
	key.service = info.host;
	return key;
}

void TresorSession::Remember(const shared_ptr<RememberedLogins> &store) {
	lock_guard<mutex> guard(lock);
	remember = store;
	remember_mode = store->Mode();
	// what the session holds now - rotated by a renew-and-retry since the login, perhaps
	store->Store(Key(), tokens.refresh_token, remember_mode);
}

bool TresorSession::Remembers(const LoginKey &key) {
	lock_guard<mutex> guard(lock);
	auto mine = Key();
	return !remember.expired() && mine.issuer == key.issuer && mine.client_id == key.client_id &&
	       mine.service == key.service;
}

string TresorSession::LogOff() {
	lock_guard<mutex> guard(lock);
	auto refresh = tokens.refresh_token;
	tokens = oidc::TokenSet();
	logged_out = true;
	remember.reset();
	return refresh;
}

void TresorSession::Close() {
	lock_guard<mutex> guard(lock);
	closed = true;
	tokens = oidc::TokenSet();
	client_secret.clear();
}

} // namespace tresor
} // namespace duckdb
