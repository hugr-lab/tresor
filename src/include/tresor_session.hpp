//===----------------------------------------------------------------------===//
// tresor_session.hpp - one attached service: where it is, who logged in, and the tokens (specs/002)
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "oidc_core.hpp"

#include <functional>

namespace duckdb {
namespace tresor {

//! How the session logged in; `browser` and `device` are people, the rest services.
enum class LoginFlow : uint8_t { BROWSER, DEVICE, CLIENT_CREDENTIALS, TOKEN };

string LoginFlowName(LoginFlow flow);

//! What the attach resolved: the service's discovery and the issuer chosen from it.
struct ServiceInfo {
	string host;      // host[:port][/base], as the ATTACH named it
	string discovery; // the discovery URL asked
	string api;       // the `api` URL of the discovery document, no trailing slash
	string issuer;    // the chosen issuer
	string client_id; // the public client of people, or the service's own
	string scope;     // what the login asked for
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
//! never in a message. Shared by every connection using the catalog, so everything is under one lock -
//! held across the network call too (a renewal must not race another), so a slow service or IdP holds
//! the other connections' calls for up to the transport's timeout.
class TresorSession {
public:
	TresorSession(ServiceInfo info, LoginFlow flow, oidc::TokenSet tokens, string client_secret);

	const ServiceInfo &Info() const {
		return info;
	}
	LoginFlow Flow() const {
		return flow;
	}

	//! A call to the service's API (`path` is relative to `api`, starting with '/'). A token about to
	//! expire is renewed first; a 401 renews once and retries once (protocol, Errors). Throws when the
	//! session is closed or cannot be renewed.
	ServiceResponse Call(const string &method, const string &path, const string &body = "",
	                     const std::map<std::string, std::string> &extra_headers = {});

	//! DETACH: drop the tokens. Calls after this fail.
	void Close();

private:
	//! A usable access token, renewing it when it has less than a minute left; `force` renews anyway
	//! (after a 401). Called with the lock held.
	string AccessToken(bool force);

	ServiceInfo info;
	LoginFlow flow;
	mutex lock;
	oidc::TokenSet tokens;
	int64_t issued_at = 0; // when `tokens` arrived: the renewal margin is at most half their life
	string client_secret;  // client_credentials only: the re-mint needs it
	bool closed = false;
	bool logged_out = false; // the IdP ended the login (invalid_grant): only a new ATTACH helps
};

} // namespace tresor
} // namespace duckdb
