//===----------------------------------------------------------------------===//
// tresor_login.hpp - what ATTACH asks for, discovery, and the login itself (specs/002)
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"

#include "duckdb/common/types/value.hpp"
#include "duckdb/common/unordered_map.hpp"

namespace duckdb {
class ClientContext;

namespace tresor {

//! How a person logs in; a service's flow comes from its `tresor` secret instead.
enum class LoginMode : uint8_t { AUTO, BROWSER, DEVICE };

//! The ATTACH, parsed: the path and the options tresor understands. Anything else is refused.
struct AttachRequest {
	string host; // host[:port][/base], the prefix and any trailing '/' removed
	LoginMode mode = LoginMode::AUTO;
	string issuer;
	string secret_name;
	bool insecure_http = false;
	int64_t timeout_seconds = 300;
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

//! The service's error body (RFC 9457) in a line fit for a message: `type: detail`.
string DescribeProblem(int status, const string &body);

} // namespace tresor
} // namespace duckdb
