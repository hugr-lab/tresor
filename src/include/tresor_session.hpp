//===----------------------------------------------------------------------===//
// tresor_session.hpp - one attached service: where it is, who logged in, and the tokens (specs/002)
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "oidc_core.hpp"
#include "tresor_credentials.hpp"
#include "tresor_remember.hpp"

#include <functional>

namespace duckdb {
namespace tresor {

//! How the session logged in; `browser` and `device` are people, the rest services.
enum class LoginFlow : uint8_t { BROWSER, DEVICE, CLIENT_CREDENTIALS, TOKEN, REMEMBERED, FEDERATED, MANAGED_IDENTITY };

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
	//! Who logged in, as the service named it at the login's whoami (`subject:<issuer>|<sub>`); set once,
	//! before the session is shared.
	const string &Subject() const {
		return subject;
	}
	void SetSubject(string subject_p) {
		subject = std::move(subject_p);
	}

	//! A call to the service's API (`path` is relative to `api`, starting with '/'). A token about to
	//! expire is renewed first; a 401 renews once and retries once (protocol, Errors). Throws when the
	//! session is closed or cannot be renewed.
	ServiceResponse Call(const string &method, const string &path, const string &body = "",
	                     const std::map<std::string, std::string> &extra_headers = {}, int timeout_seconds = 30);

	//! Exchange a token someone presented to this node for one meant for the service (specs/008): at the
	//! session's own IdP, as its own client. Only a client_credentials login can. No lock held across the
	//! network. The subject token never reaches an error.
	oidc::TokenSet ExchangeForService(const string &subject_token, bool on_behalf_of, const string &scope);

	//! DETACH: drop the tokens. Calls after this fail.
	void Close();

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
	//! tresor_logoff: the login is over here too - the tokens go, the next call asks for a new ATTACH. The
	//! refresh token, for revocation, is handed out once (empty when there is none).
	string LogOff();

private:
	//! A usable access token, renewing it when it has less than a minute left; `force` renews anyway
	//! (after a 401). Called with the lock held.
	string AccessToken(bool force);

	ServiceInfo info;
	LoginFlow flow;
	string subject;
	mutex lock;
	oidc::TokenSet tokens;
	int64_t issued_at = 0;        // when `tokens` arrived: the renewal margin is at most half their life
	ServiceCredential credential; // a service's login: what re-mints it (a secret, or paths - never read content)
	bool closed = false;
	bool logged_out = false;                        // the IdP ended the login (invalid_grant): only a new ATTACH helps
	weak_ptr<RememberedLogins> remember;            // specs/012: where a rotated refresh token goes
	KeychainMode remember_mode = KeychainMode::OFF; // the mode it was remembered in: stored only while it holds
	string remember_subject;                        // whose login it is: another person's stored since is not adopted
};

} // namespace tresor
} // namespace duckdb
