//===----------------------------------------------------------------------===//
// tresor_session.hpp - one attached service: where it is, who logged in, and the tokens (specs/002)
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "oidc_core.hpp"
#include "tresor_credentials.hpp"
#include "tresor_http.hpp"
#include "tresor_page_tokens.hpp"
#include "tresor_remember.hpp"

#include <atomic>
#include <functional>

namespace duckdb {
namespace tresor {

//! SESSION_GRANT_WAIT's default, at ATTACH and at act_for_sessions() alike (specs/008, 015).
constexpr int64_t DEFAULT_GRANT_WAIT_SECONDS = 10;

//! How the session logged in; `browser` and `device` are people, the rest services.
//! `page`: a web page's access token, handed over (specs/043).
enum class LoginFlow : uint8_t {
	BROWSER,
	DEVICE,
	CLIENT_CREDENTIALS,
	TOKEN,
	REMEMBERED,
	FEDERATED,
	MANAGED_IDENTITY,
	PAGE
};

string LoginFlowName(LoginFlow flow);

//! What the attach resolved: the service's discovery and the issuer chosen from it.
struct ServiceInfo {
	string host;      // host[:port][/base], as the ATTACH named it
	string discovery; // the discovery URL asked
	string api;       // the `api` URL of the discovery document, no trailing slash
	string issuer;    // the chosen issuer
	string client_id; // the public client of people, or the service's own
	string scope;     // what the login asked for
	string audience;  // the chosen issuer's `audience` in the discovery: what an exchange asks for (specs/008)
	bool audience_parameter = false; // the discovery asks for `audience=` on the IdP's requests (Auth0; specs/013)
	bool insecure_http = false;
	unordered_map<string, bool> capabilities; // discovery's `capabilities` (write, annotate, dynamic, delegation)
	oidc::Endpoints endpoints;
};

//! One service call's outcome. The body is the service's JSON (or problem+json on an error).
struct ServiceResponse {
	int status = 0;
	string body;
};

//! The logged-in session behind an attached catalog. Tokens live here and nowhere else: never on disk,
//! never in a message. Shared by every connection using the catalog: the tokens are under one lock, held
//! for a renewal (which must not race another) but never across a call to the service - a node serves
//! many users' sessions through one login (specs/008).
class TresorSession {
public:
	TresorSession(ServiceInfo info, LoginFlow flow, oidc::TokenSet tokens, ServiceCredential credential);

	const ServiceInfo &Info() const {
		return info;
	}
	LoginFlow Flow() const {
		return flow;
	}
	//! What whoami and the audit call this login (a key login is private_key_jwt, not client_credentials).
	string LoginName() const {
		return flow == LoginFlow::CLIENT_CREDENTIALS ? credential.LoginName() : LoginFlowName(flow);
	}
	//! Who logged in, as the service named it at the login's whoami (`subject:<issuer>|<sub>`). Set by the ATTACH,
	//! and again when a kept catalog takes up another person's login (specs/025): a copy, read under the lock.
	string Subject() const {
		lock_guard<mutex> guard(lock);
		return subject;
	}
	void SetSubject(string subject_p) {
		lock_guard<mutex> guard(lock);
		subject = std::move(subject_p);
	}
	//! The attached catalog's name, for what a logged-off call tells the person to run (specs/025).
	void SetCatalogName(string name) {
		lock_guard<mutex> guard(lock);
		catalog_name = std::move(name);
	}
	//! Logged off (tresor_logoff, specs/025) and no new login taken up yet: nothing held for the previous login may
	//! be served. Lock-free: every secret lookup asks, and the lock is held across a renewal.
	bool LoggedOff() const {
		return logged_off_seen.load();
	}
	//! A login tresor_login started for this session's key is in progress (or done, not yet taken up).
	bool LoginInProgress() {
		return pending_probe && pending_probe(Key());
	}

	//! A call to the service's API (`path` is relative to `api`, starting with '/'). A token about to
	//! expire is renewed first; a 401 renews once and retries once (protocol, Errors). Throws when the
	//! session is closed or cannot be renewed.
	//! `interrupted`: the caller's query was interrupted - ends a logged-off session's wait for a login in progress.
	ServiceResponse Call(const string &method, const string &path, const string &body = "",
	                     const std::map<std::string, std::string> &extra_headers = {}, int timeout_seconds = 30,
	                     const std::function<bool()> &interrupted = std::function<bool()>());

	//! Exchange a token someone presented to this node for one meant for the service (specs/008): at the
	//! session's own IdP, as its own client. Only a client_credentials login can. No lock held across the
	//! network. The subject token never reaches an error.
	oidc::TokenSet ExchangeForService(const string &subject_token, bool on_behalf_of, const string &scope,
	                                  const string &audience);
	//! The `aud` of the session's own access token (renewed first if due); `is_jwt` false for an opaque one.
	//! The token itself never leaves the session.
	vector<string> OwnAudiences(bool &is_jwt);

	//! The HTTP client of this session's requests and renewals (specs/020) and the built-in client's CA bundle
	//! (specs/030), as the ATTACH found them. Set once, before the session is shared.
	void SetHttpClient(HttpClient client) {
		http_client = std::move(client);
	}

	//! A page's login (specs/043): where the page's next token is, read at every call. Set once, before the session
	//! is shared.
	void UsePageTokens(const shared_ptr<PageTokens> &store) {
		page_tokens = store;
	}

	//! DETACH: drop the tokens. Calls after this fail.
	void Close();
	//! A DETACH begins: a call waiting for a login in progress stops waiting (before the actor is stopped).
	void StopWaiting() {
		closing = true;
	}

	//! Keep this person's login remembered (specs/012), in `store`'s current mode: the refresh token the session
	//! holds now is stored, every rotation after it too, and a dead one (invalid_grant) removed. Its key is this
	//! service's: (issuer, client id, host).
	//! `started_from`: the token a remembered login began with (what RememberedLogin stored); empty for a fresh
	//! login, which replaces the entry.
	void Remember(const shared_ptr<RememberedLogins> &store, const string &started_from);
	//! Is this login remembered under `key`?
	bool Remembers(const LoginKey &key);
	//! The key this session's login would be remembered under.
	LoginKey Key() const;
	//! tresor_logoff: the login is over here too - the tokens go. The refresh token, for revocation, is handed out
	//! once (empty when there is none). A catalog kept (`detach := false`, specs/025) takes up the next login
	//! remembered under its key; until then a call says how to log in. on_logged_off is told (outside the lock).
	string LogOff();
	//! After the logoff removed the login from the store: from now on a kept catalog may take up the next login (not
	//! before - the one being logged off is still stored until then).
	void AllowResume();
	//! Told when a kept catalog took up a new login (specs/025): the subject before and now - another person means
	//! everything held for the previous one goes. Set once, before the session is shared.
	void OnResumed(std::function<void(const string &before, const string &now)> callback) {
		on_resumed = std::move(callback);
	}
	//! Told when the login was logged off (specs/025): nothing held for it may be served from now on. Set once,
	//! before the session is shared.
	void OnLoggedOff(std::function<void()> callback) {
		on_logged_off = std::move(callback);
	}
	//! How a kept catalog waits for a login in progress for its key (tresor_login's, specs/025): never under the
	//! session's lock, until the login ends or `stop` says so (a DETACH). Set once, before the session is shared.
	void OnPendingLogin(std::function<void(const LoginKey &key, const std::function<bool()> &stop)> wait,
	                    std::function<bool(const LoginKey &key)> probe) {
		wait_pending = std::move(wait);
		pending_probe = std::move(probe);
	}

private:
	//! A usable access token, renewing it when it has less than a minute left; `force` renews anyway
	//! (after a 401). Called with the lock held.
	string AccessToken(bool force);
	//! A page's login (specs/043): its newest token; `refused` after a 401 - a token the service refused is not
	//! sent again. Called with the lock held.
	string PageAccessToken(bool refused);
	//! After a logoff: a login remembered under this session's key since, taken up (specs/025) - its refresh token,
	//! renewed by AccessToken before anything else. With the lock held.
	bool TakeUpLogin();
	//! After a login was taken up and renewed: whoami names who it is (another person: on_resumed empties the
	//! catalog). `token` is the access token to call with - renewed here after a 401.
	void TakeUpWhoami(string &token);

	ServiceInfo info;
	LoginFlow flow;
	string subject;
	string catalog_name;
	HttpClient http_client;
	//! The client set at ATTACH (SetHttpClient). Never the bare built-in one: an empty transport would skip
	//! DuckDB's sandbox (specs/036), so a session without its client fails closed - that call only (an internal
	//! error would invalidate the instance, every connection of a node).
	const HttpClient &Client() const {
		if (!http_client.transport) {
			throw IOException("tresor: a session's HTTP client was not set");
		}
		return http_client;
	}
	mutable mutex lock;
	oidc::TokenSet tokens;
	int64_t issued_at = 0;        // when `tokens` arrived: the renewal margin is at most half their life
	ServiceCredential credential; // a service's login: what re-mints it (a secret, or paths - never read content)
	bool closed = false;
	std::atomic<bool> closing {false};           // Close: a wait for a login in progress (outside the lock) stops
	bool logged_out = false;                     // the IdP ended the login (invalid_grant): only a new ATTACH helps
	weak_ptr<RememberedLogins> remember;         // specs/012: where a rotated refresh token goes
	bool logged_off = false;                     // tresor_logoff ended it, until a new login is taken up (specs/025)
	std::atomic<bool> logged_off_seen {false};   // logged_off, for lock-free readers (LoggedOff)
	uint64_t take_ups = 0;                       // every take-up and logoff: a whoami answers for its own take-up only
	string previous_subject;                     // who it was before the take-up (resumed or resumed_other)
	weak_ptr<RememberedLogins> logged_off_store; // what AllowResume makes resume_store
	bool taken_up = false;                       // a stored login was taken up: renewed by the next AccessToken
	weak_ptr<RememberedLogins> resume_store;     // where a new login would be remembered
	bool resumed = false;                        // a new login was taken up and renewed: the next call asks whoami
	std::function<void(const string &before, const string &now)> on_resumed;
	std::function<void()> on_logged_off;
	std::function<void(const LoginKey &key, const std::function<bool()> &stop)> wait_pending;
	std::function<bool(const LoginKey &key)> pending_probe;
	KeychainMode remember_mode = KeychainMode::OFF; // the mode it was remembered in: stored only while it holds
	string remember_subject;                        // whose login it is: another person's stored since is not adopted
	weak_ptr<PageTokens> page_tokens;               // specs/043: the page's tokens, the newest read at every call
};

} // namespace tresor
} // namespace duckdb
