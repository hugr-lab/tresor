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

//! The transport the setting names for this context: empty for `builtin`. It holds the database weakly: a
//! request after the database is gone fails, it does not keep the database alive.
oidc::Transport TransportFor(ClientContext &context);

//! DuckDB's HTTPUtil as an OIDC transport (duckdb-ext-common spec 013's contract): no redirect followed, no
//! retry, no request logged, no `http` secret or extra header of DuckDB's mixed in; a failure is an error.
oidc::Transport DuckDBTransport(const shared_ptr<DatabaseInstance> &db);

} // namespace tresor
} // namespace duckdb
