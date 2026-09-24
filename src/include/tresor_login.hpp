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
	int64_t grant_wait_seconds = 10;
	// a person's login remembered in the OS keychain (specs/012)
	bool remember = true;
	bool remember_given = false;
};

AttachRequest ParseAttach(const string &path, const unordered_map<string, Value> &options);

//! Is `host` (host[:port][/base]) a loopback name: 127.0.0.1, ::1, localhost.
bool IsLoopbackHost(const string &host);

//! Discovery, the issuer's endpoints, the login, and the service's whoami. Every failure throws, and
//! nothing is left behind.
shared_ptr<TresorSession> Login(ClientContext &context, const AttachRequest &request);

//! The browser for the login URL (tresor_browser.cpp).
bool CanOpenBrowser();
bool OpenBrowser(const std::string &url);

//! The `aud` of a JWT (payload only - no signature check; for checking where a token is meant to go);
//! `is_jwt` false for an opaque token.
vector<string> JwtAudiences(const string &token, bool &is_jwt);

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
