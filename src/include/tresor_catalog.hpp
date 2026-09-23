//===----------------------------------------------------------------------===//
// tresor_catalog.hpp - the attached service as a catalog (specs/002)
//
// An in-memory DuckCatalog switched to a read-only database once initialized: duckdb's own function
// lookup finds `corp.whoami()` in its `main` schema, and duckdb's own read-only check refuses tables,
// views and writes in it. The functions reach the session through their TableFunctionInfo.
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"

#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/function/table_function.hpp"

namespace duckdb {
namespace tresor {

//! What a catalog function carries: the session of the catalog it lives in.
struct TresorFunctionInfo : public TableFunctionInfo {
	explicit TresorFunctionInfo(shared_ptr<TresorSession> session_p) : session(std::move(session_p)) {
	}
	shared_ptr<TresorSession> session;
};

class TresorCatalog : public DuckCatalog {
public:
	TresorCatalog(AttachedDatabase &db, shared_ptr<TresorSession> session);

	void Initialize(bool load_builtin) override;
	string GetCatalogType() override {
		return "tresor";
	}
	//! DETACH is the logout: the session's tokens are dropped.
	void OnDetach(ClientContext &context) override;

	TresorSession &Session() {
		return *session;
	}

private:
	shared_ptr<TresorSession> session;
};

//! The catalog's table functions (tresor_whoami.cpp).
TableFunction WhoamiFunction(shared_ptr<TresorSession> session);

} // namespace tresor
} // namespace duckdb
