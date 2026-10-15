//===----------------------------------------------------------------------===//
// tresor_http.hpp - which HTTP client carries tresor's requests (specs/020)
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "oidc_core.hpp"

namespace duckdb {
class ClientContext;
class DatabaseInstance;

namespace tresor {

//! `tresor_http_client`: `builtin` (the OIDC core's own client, with tresor's OpenSSL - the native default) or
//! `duckdb` (DuckDB's HTTPUtil: httpfs where it is loaded; in wasm the browser's, and the only one there).
void RegisterHttpClient(DatabaseInstance &db);

//! The transport the setting names for this context: empty for `builtin`. It refers to the instance without owning
//! it: a session holding it lives in one of the instance's catalogs.
oidc::Transport TransportFor(ClientContext &context);

//! DuckDB's HTTPUtil as an OIDC transport (duckdb-ext-common spec 013's contract): no redirect followed, no
//! retry, no request logged, no `http` secret or extra header of DuckDB's mixed in, certificates verified (against
//! `ca_cert_file` when set); DuckDB's `http_proxy` is not used - as by the built-in client. A failure is an error.
oidc::Transport DuckDBTransport(DatabaseInstance &db);

//! The CA bundle of the built-in client for this context (specs/030): DuckDB's `ca_cert_file`, trusted beside the
//! system's roots. It is httpfs's setting: without httpfs loaded there is none, and the system's roots alone count.
//! DuckDB's own client reads the same setting, so the one setting covers tresor's trust on either client.
string CaBundleFor(ClientContext &context);

//! What carries tresor's requests: the transport `tresor_http_client` names and the built-in client's CA bundle,
//! both taken from a context once - a session keeps them for its renewals and calls, a login's thread for its own.
struct HttpClient {
	oidc::Transport transport;
	string ca_bundle;
};
HttpClient HttpClientFor(ClientContext &context);

//! Both in force on the calling thread while this lives (the OIDC core's two scopes): a local variable only.
class HttpScope {
public:
	explicit HttpScope(const HttpClient &client) : transport(client.transport), trust(client.ca_bundle) {
	}

private:
	oidc::TransportScope transport;
	oidc::CaBundleScope trust;
};

} // namespace tresor
} // namespace duckdb
