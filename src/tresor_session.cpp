#include "tresor_session.hpp"
#include "tresor_actor.hpp"
#include "tresor_login.hpp"
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
	case LoginFlow::FEDERATED:
		return "federated";
	case LoginFlow::MANAGED_IDENTITY:
		return "managed_identity";
	}
	return "unknown";
}

TresorSession::TresorSession(ServiceInfo info_p, LoginFlow flow_p, oidc::TokenSet tokens_p,
                             ServiceCredential credential_p)
    : info(std::move(info_p)), flow(flow_p), tokens(std::move(tokens_p)), issued_at(NowSeconds()),
      credential(std::move(credential_p)) {
}

string TresorSession::AccessToken(bool force) {
	if (closed) {
		throw InvalidInputException("tresor: the session to %s is closed (DETACHed)", info.host);
	}
	if (logged_off && !taken_up && !TakeUpLogin()) {
		throw InvalidInputException("tresor: logged off from %s - log in: FROM tresor_login('%s')", info.host,
		                            catalog_name.empty() ? "tresor:" + info.host : catalog_name);
	}
	if (logged_out) {
		throw InvalidInputException("tresor: the login to %s is over - log in again: DETACH and ATTACH", info.host);
	}
	if (taken_up) {
		force = true; // the remembered refresh token taken up: renewed before anything else (again, after a failure)
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
			// the token stored now, when it is this person's (a logoff and another person's login elsewhere is not
			// this session's to adopt)
			auto adopt = [&]() {
				string subject;
				string current;
				auto newer = store->Load(Key(), remember_mode, subject, current) && subject == remember_subject &&
				             current != tokens.refresh_token;
				if (newer) {
					tokens.refresh_token.swap(current);
				}
				std::fill(current.begin(), current.end(), '\0');
				return newer;
			};
			if (store) {
				chain = unique_lock<mutex>(store->KeyLock(Key()));
				adopt();
			}
			// this service's scope: the IdP is asked for what this service needs, never what an earlier grant held
			renewed = oidc::RefreshGrant(info.endpoints, info.client_id, "", tokens.refresh_token, info.scope);
			if (store && !renewed.Ok() && renewed.error_code == "invalid_grant") {
				// only the dead one is forgotten - and another process may have stored a newer one meanwhile: once
				store->Remove(Key(), remember_mode, tokens.refresh_token);
				if (adopt()) {
					renewed = oidc::RefreshGrant(info.endpoints, info.client_id, "", tokens.refresh_token, info.scope);
				}
			}
			if (renewed.Ok() && renewed.refresh_token.empty()) {
				renewed.refresh_token = tokens.refresh_token; // RFC 6749 §6: a refresh may keep the old one
			}
			if (store && renewed.Ok() && renewed.refresh_token != tokens.refresh_token) {
				// the rotated token replaces this person's entry, or a missing one - never another's stored since
				// (a login handed over by a page for someone else, specs/020)
				string subject;
				string current;
				if (!store->Load(Key(), remember_mode, subject, current) || subject == remember_subject) {
					store->Store(Key(), remember_subject, renewed.refresh_token, remember_mode);
				}
				std::fill(current.begin(), current.end(), '\0');
			}
			break;
		}
	case LoginFlow::CLIENT_CREDENTIALS:
	case LoginFlow::FEDERATED:
	case LoginFlow::MANAGED_IDENTITY: {
		// minted again from what the secret names: a key's or a token's file read now (a rotated one included)
		std::map<std::string, std::string> extra;
		if (info.audience_parameter && !info.audience.empty()) {
			extra["audience"] = info.audience;
		}
		renewed = credential.Mint(info.endpoints, info.scope, extra);
		break;
	}
	case LoginFlow::TOKEN:
		throw InvalidInputException("tresor: the token of the tresor secret for %s has expired or was refused - "
		                            "replace the secret and ATTACH again",
		                            info.host);
	}
	if (!renewed.Ok()) {
#ifdef __EMSCRIPTEN__
		// duckdb-wasm's client drops the body of the IdP's 400: a dead refresh token's invalid_grant comes without
		// its code. A page's login is a person's, and any failed renewal ends it the same way (specs/020)
		if (renewed.error_code.empty() && flow == LoginFlow::REMEMBERED) {
			renewed.error_code = "invalid_grant";
		}
#endif
		if (renewed.error_code == "invalid_grant") {
			// the refresh chain is dead (revoked, expired, rotated elsewhere): only a new login helps - and a
			// remembered one is forgotten
			tokens = oidc::TokenSet();
			logged_out = true;
			// a login taken up after a logoff that is dead already: still logged off, the next call looks again
			taken_up = false;
#ifdef __EMSCRIPTEN__
			throw InvalidInputException("tresor: the login to %s is over (%s) - a new login is needed: DETACH, and "
			                            "the page logs in and hands it over again (attachTresor)",
			                            info.host, renewed.error);
#else
			throw InvalidInputException("tresor: the login to %s is over (%s) - log in again: DETACH and ATTACH",
			                            info.host, renewed.error);
#endif
		}
		throw IOException("tresor: renewing the login to %s failed: %s", info.host, renewed.error);
	}
	tokens = std::move(renewed);
	issued_at = NowSeconds();
	if (taken_up) {
		// the login taken up works: no longer logged off, and the next call asks whoami who it is (specs/025) - until
		// then nobody is named (the audit's principal), never the previous person
		taken_up = false;
		logged_off = false;
		logged_off_seen = false;
		resumed = true;
		previous_subject = subject;
		subject.clear();
	}
	return tokens.access_token;
}

ServiceResponse TresorSession::Call(const string &method, const string &path, const string &body,
                                    const std::map<std::string, std::string> &extra_headers, int timeout_seconds,
                                    const std::function<bool()> &interrupted) {
	HttpScope http(http_client);
	if (wait_pending) {
		// logged off: a login tresor_login started for this key is waited for first (specs/025) - never under the
		// lock, so other calls, a DETACH and the logoff that cancels it go on meanwhile
		LoginKey key;
		bool waiting;
		{
			lock_guard<mutex> guard(lock);
			waiting = logged_off && !taken_up && !closed;
			key = Key();
		}
		if (waiting) {
			wait_pending(key, [this, &interrupted] { return closing.load() || (interrupted && interrupted()); });
			if (interrupted && interrupted()) {
				throw InterruptException();
			}
		}
	}
	string used;
	for (int attempt = 0; attempt < 2; attempt++) {
		string token;
		bool take_up;
		{
			// the lock covers the token and its renewal only, never the request: a node serves many users'
			// sessions through one login, and one slow call must not hold up the others
			lock_guard<mutex> guard(lock);
			// after a 401, renew - unless another call already did while this one was on the wire
			token = AccessToken(attempt > 0 && tokens.access_token == used);
			take_up = resumed;
		}
		if (take_up) {
			TakeUpWhoami(token);
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

oidc::TokenSet TresorSession::ExchangeForService(const string &subject_token, bool on_behalf_of, const string &scope,
                                                 const string &audience) {
	HttpScope http(http_client);
	ServiceCredential proof; // paths and ids: copied under the lock - the files are read and the IdP called outside it
	{
		lock_guard<mutex> guard(lock);
		if (closed || (flow != LoginFlow::CLIENT_CREDENTIALS && flow != LoginFlow::FEDERATED)) {
			oidc::TokenSet refused;
			refused.error =
			    closed ? "the session is closed" : "only a client_credentials or federated login exchanges tokens";
			return refused;
		}
		proof = credential;
	}
	oidc::ClientAuth auth;
	oidc::TokenSet out;
	string why;
	if (!proof.Auth(auth, why)) {
		proof.Wipe();
		out.error = why;
		out.error_code = "invalid_client";
		return out;
	}
	if (on_behalf_of) {
		out = oidc::OnBehalfOf(info.endpoints, auth, subject_token, scope);
	} else {
		// asked with a refresh token (specs/010): Keycloak binds the exchanged token to the user's SSO session
		// only then, and the service's own exchange for a downstream audience (a token for the user) needs that
		// session. The refresh token itself is dropped at once - the node never renews a user's token
		out = oidc::TokenExchange(info.endpoints, auth, subject_token, audience, scope, "", true);
		if (!out.Ok() && out.error_code != "invalid_client" && out.error_code != "invalid_grant") {
			// an IdP that issues no refresh token by exchange, whatever it answers (its wording and code vary, and
			// a strict RFC 8693 answer is refused as invalid_token_type): the plain exchange. A bad client or a
			// dead subject token would fail that the same way. The proof afresh: a federated assertion may be
			// single-use at the IdP (a key signs anew anyway)
			WipeAuth(auth);
			if (proof.Auth(auth, why)) {
				out = oidc::TokenExchange(info.endpoints, auth, subject_token, audience, scope);
			} else {
				out = oidc::TokenSet();
				out.error = why;
				out.error_code = "invalid_client";
			}
		}
	}
	std::fill(out.refresh_token.begin(), out.refresh_token.end(), '\0');
	out.refresh_token.clear();
	WipeAuth(auth);
	proof.Wipe();
	return out;
}

vector<string> TresorSession::OwnAudiences(bool &is_jwt) {
	HttpScope http(http_client);
	lock_guard<mutex> guard(lock);
	auto token = AccessToken(false);
	auto audiences = JwtAudiences(token, is_jwt);
	std::fill(token.begin(), token.end(), '\0');
	return audiences;
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

void TresorSession::Remember(const shared_ptr<RememberedLogins> &store, const string &started_from) {
	lock_guard<mutex> guard(lock);
	remember = store;
	remember_mode = store->Mode();
	remember_subject = subject;
	lock_guard<mutex> chain(store->KeyLock(Key()));
	// a fresh login replaces what was there; a remembered one stores what it holds now (rotated by a renew-and-
	// retry since, perhaps) - unless another attachment rotated the stored token past it meanwhile
	if (!started_from.empty()) {
		string stored_subject;
		string stored;
		auto found = store->Load(Key(), remember_mode, stored_subject, stored);
		auto moved_on = found && stored != started_from;
		std::fill(stored.begin(), stored.end(), '\0');
		if (moved_on) {
			return;
		}
	}
	store->Store(Key(), remember_subject, tokens.refresh_token, remember_mode);
}

bool TresorSession::Remembers(const LoginKey &key) {
	lock_guard<mutex> guard(lock);
	auto mine = Key();
	return !remember.expired() && mine.issuer == key.issuer && mine.client_id == key.client_id &&
	       mine.service == key.service;
}

void TresorSession::TakeUpWhoami(string &token) {
	string before;
	uint64_t take_up;
	string placeholder; // whose the stored entry taken up was (tresor_login's placeholder, or a person)
	{
		lock_guard<mutex> guard(lock);
		if (!resumed) {
			return; // another call did it
		}
		resumed = false;
		before = previous_subject;
		placeholder = remember_subject;
		take_up = take_ups;
	}
	auto again = [&]() {
		lock_guard<mutex> guard(lock);
		resumed = true; // asked again by the next call
	};
	// who logged in: the same person goes on, another one's catalog is emptied of the previous one's first
	oidc::HttpResult probe;
	for (int attempt = 0; attempt < 2; attempt++) {
		probe = oidc::HttpSend("GET", info.api + "/v1/whoami",
		                       {{"Authorization", "Bearer " + token}, {"Accept", "application/json"}}, "", "", 30);
		if (probe.error.empty() && probe.status == 401 && attempt == 0) {
			// the protocol's rule here too: renew once and ask again
			try {
				lock_guard<mutex> guard(lock);
				token = AccessToken(true);
			} catch (...) {
				again();
				throw;
			}
			continue;
		}
		break;
	}
	if (!probe.error.empty() || probe.status != 200) {
		again();
		throw IOException("tresor: %s did not say who logged in: %s", info.host,
		                  probe.error.empty() ? DescribeProblem(probe.status, probe.body) : probe.error);
	}
	auto now = WhoamiSubject(probe.body);
	{
		lock_guard<mutex> guard(lock);
		if (logged_off || closed || take_ups != take_up) {
			return; // logged off (or detached, or another login taken up) meanwhile: not this whoami's to name
		}
		subject = now;
		remember_subject = now;
		auto store = remember.lock();
		if (store && !tokens.refresh_token.empty()) {
			// the entry now names the person, as an ATTACH's does (the placeholder no session adopts) - only while it
			// is still the one taken up: a login stored since (another tresor_login, another process) stays as it is
			lock_guard<mutex> chain(store->KeyLock(Key()));
			string stored_subject;
			string stored;
			if (store->Load(Key(), remember_mode, stored_subject, stored) && stored_subject == placeholder &&
			    stored == tokens.refresh_token) {
				store->Store(Key(), remember_subject, tokens.refresh_token, remember_mode);
			}
			std::fill(stored.begin(), stored.end(), '\0');
		}
	}
	if (on_resumed) {
		on_resumed(before, now);
	}
}

bool TresorSession::TakeUpLogin() {
	auto store = resume_store.lock();
	if (!store) {
		return false;
	}
	auto mode = store->Mode();
	string stored_subject;
	string refresh;
	{
		lock_guard<mutex> chain(store->KeyLock(Key()));
		if (!store->Load(Key(), mode, stored_subject, refresh)) {
			return false;
		}
	}
	// only the refresh token: renewed by the caller (AccessToken) before anything is sent - and again by the next
	// call when that fails; logged off until it works
	tokens = oidc::TokenSet();
	tokens.refresh_token = std::move(refresh);
	issued_at = 0;
	logged_out = false;
	taken_up = true;
	take_ups++;
	remember = store;
	remember_mode = mode;
	remember_subject = stored_subject; // a placeholder until whoami names the person (TakeUpWhoami)
	return true;
}

string TresorSession::LogOff() {
	string refresh;
	{
		lock_guard<mutex> guard(lock);
		refresh.swap(tokens.refresh_token);
		Wipe(tokens.access_token);
		tokens = oidc::TokenSet();
		logged_out = true;
		logged_off = true;
		logged_off_seen = true;
		taken_up = false;
		resumed = false;
		take_ups++;
		// no take-up until the logoff removed this login from the store (AllowResume): it is still stored now, and a
		// lookup meanwhile would take it up again
		if (!remember.expired()) {
			logged_off_store = remember;
		}
		resume_store.reset();
		remember.reset();
		remember_subject.clear();
	}
	// outside the lock: the catalog drops everything held for this login (the storage's lock is its own)
	if (on_logged_off) {
		on_logged_off();
	}
	return refresh;
}

void TresorSession::AllowResume() {
	lock_guard<mutex> guard(lock);
	if (logged_off && !logged_off_store.expired()) {
		resume_store = logged_off_store;
	}
}

void TresorSession::Close() {
	closing = true; // a call waiting for a login in progress stops waiting
	lock_guard<mutex> guard(lock);
	closed = true;
	tokens = oidc::TokenSet();
	credential.Wipe();
}

} // namespace tresor
} // namespace duckdb
