//===----------------------------------------------------------------------===//
// tresor_login.hpp - what ATTACH asks for, discovery, and the login itself (specs/002)
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"

#include "duckdb/common/types/value.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "yyjson.hpp"

namespace duckdb {
class ClientContext;

namespace tresor {

//! How a person logs in; a service's flow comes from its `tresor` secret instead.
enum class LoginMode : uint8_t { AUTO, BROWSER, DEVICE };

//! The ATTACH, parsed: the path and the options tresor understands. Anything else is refused.
struct AttachRequest {
	string host; // host[:port][/base], the prefix and any trailing '/' removed
	LoginMode mode = LoginMode::AUTO;
	bool mode_given = false; // LOGIN named: a person logs in, no secret is looked up
	string issuer;
	string secret_name;
	bool insecure_http = false;
	int64_t timeout_seconds = 300;
	// acting for duckdb-acl's sessions (specs/008)
	bool act_for_sessions = false;
	bool on_behalf_of = false; // EXCHANGE 'on_behalf_of' (Entra); else RFC 8693 token exchange
	string exchange_scope;
	string exchange_audience; // EXCHANGE_AUDIENCE: pinned on the node, not taken from the service
	int64_t grant_wait_seconds = DEFAULT_GRANT_WAIT_SECONDS;
	// a person's login remembered in the OS keychain (specs/012)
	bool remember = true;
	bool remember_given = false;
};

AttachRequest ParseAttach(const string &path, const unordered_map<string, Value> &options);

//! EXCHANGE's value: true for 'on_behalf_of', false for 'token_exchange'; anything else is refused.
bool ParseExchange(const string &value);
//! SESSION_GRANT_WAIT, checked: 0 to 600 seconds.
int64_t ParseGrantWait(int64_t seconds);

//! Is `host` (host[:port][/base]) a loopback name: 127.0.0.1, ::1, localhost.
bool IsLoopbackHost(const string &host);

//! Discovery, the issuer's endpoints, the login, and the service's whoami. Every failure throws, and
//! nothing is left behind.
shared_ptr<TresorSession> Login(ClientContext &context, const AttachRequest &request);

//! tresor_web_login (specs/020): a person's login the page made, handed over. Discovery and the issuer as the ATTACH
//! of `request` would choose them; the refresh token is remembered (in memory only) under the key that ATTACH looks
//! up, so the ATTACH renews it and nothing else. Returns that key.
LoginKey HandOverLogin(ClientContext &context, const AttachRequest &request, const string &refresh_token);

//! tresor_web_token (specs/043): the page's access token for `request`'s service, kept (memory only) for the ATTACH and
//! every call of a session attached on it. Discovery and the issuer as the ATTACH would choose them; a JWT for another
//! audience or issuer, or expired, is refused.
struct PageTokenHandOver {
	string issuer;
	string service;
	int64_t expires_at = 0;
};
PageTokenHandOver HandOverPageToken(ClientContext &context, const AttachRequest &request, const string &access_token);

//! tresor_login (specs/025): a person's login answered at once and completed in the background.
struct PersonLoginStatus {
	LoginKey key;
	string flow;   // browser, device
	string status; // pending, done, failed: <why>
	string url;
	string user_code;
	int64_t expires_at = 0; // epoch seconds; 0 when nothing waits
};
//! Report the login for `request`'s service (remembered: done; in progress: its state) or start one. `prompt`:
//! the IdP's authorization prompt (browser only); `remember` false keeps the tokens for one ATTACH, in memory.
PersonLoginStatus StartPersonLogin(ClientContext &context, const AttachRequest &request, const string &prompt,
                                   bool remember);

//! The principal whoami's answer names (`subject:<issuer>|<sub>`); empty when it names none.
string WhoamiSubject(const string &body);

//! The browser for the login URL (tresor_browser.cpp).
bool CanOpenBrowser();
bool OpenBrowser(const std::string &url);

//! The `aud` of a JWT (payload only - no signature check; for checking where a token is meant to go);
//! `is_jwt` false for an opaque token.
vector<string> JwtAudiences(const string &token, bool &is_jwt);
//! What a JWT's payload says of where it goes and how long it lives - unverified: for refusing to send a token where
//! it is not meant to go, never for trusting it. `is_jwt` false (and nothing else set) for an opaque token.
struct JwtClaims {
	bool is_jwt = false;
	vector<string> audiences;
	string issuer;
	string subject;         // `sub`
	int64_t expires_at = 0; // `exp`; 0 when absent
};
JwtClaims ReadJwtClaims(const string &token);

//! The service's error body (RFC 9457) in a line fit for a message: `type: detail`.
string DescribeProblem(int status, const string &body);

//! One parsed JSON document, freed with its scope whatever throws in between.
struct JsonDoc {
	duckdb_yyjson::yyjson_doc *doc = nullptr;
	explicit JsonDoc(const string &body, duckdb_yyjson::yyjson_read_flag flags = 0);
	~JsonDoc();
	JsonDoc(const JsonDoc &) = delete;
	JsonDoc &operator=(const JsonDoc &) = delete;
	duckdb_yyjson::yyjson_val *Root() const;
};

} // namespace tresor
} // namespace duckdb
