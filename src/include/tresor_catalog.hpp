//===----------------------------------------------------------------------===//
// tresor_catalog.hpp - the attached service as a catalog (specs/002)
//
// An in-memory DuckCatalog switched to a read-only database once initialized: duckdb's own function
// lookup finds `corp.whoami()` in its `main` schema, and duckdb's own read-only check refuses tables,
// views and writes in it. The functions reach the session through their TableFunctionInfo.
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"
#include "tresor_storage.hpp"

#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/function/table_function.hpp"

namespace duckdb {
namespace tresor {

//! What a catalog function carries: the session of the catalog it lives in.
struct TresorFunctionInfo : public TableFunctionInfo {
	explicit TresorFunctionInfo(shared_ptr<TresorSession> session_p,
	                            optional_ptr<TresorSecretStorage> storage_p = nullptr)
	    : session(std::move(session_p)), storage(storage_p) {
	}
	shared_ptr<TresorSession> session;
	optional_ptr<TresorSecretStorage> storage;
};

class TresorCatalog : public DuckCatalog {
public:
	TresorCatalog(AttachedDatabase &db, shared_ptr<TresorSession> session, TresorSecretStorage &storage,
	              vector<Descriptor> initial, shared_ptr<TresorActor> actor);
	//! A catalog that goes without a DETACH (a rolled-back ATTACH, a failure after the storage callback)
	//! takes its secrets out of the lookup too.
	~TresorCatalog() override;

	void Initialize(bool load_builtin) override;
	string GetCatalogType() override {
		return "tresor";
	}
	//! DETACH is the logout: the session's tokens are dropped and the secrets leave the lookup.
	void OnDetach(ClientContext &context) override;

	TresorSession &Session() {
		return *session;
	}

private:
	shared_ptr<TresorSession> session;
	TresorSecretStorage &storage;  // owned by the SecretManager, for the instance's lifetime
	vector<Descriptor> initial;    // the list the ATTACH fetched: the storage starts from it
	shared_ptr<TresorActor> actor; // ACT_FOR_SESSIONS (specs/008), else null

	//! The end of the catalog, by DETACH or otherwise: out of the lookup, the grants revoked, the login gone.
	void Shutdown();
};

//! The catalog's table functions (tresor_whoami.cpp, tresor_secrets.cpp).
TableFunction WhoamiFunction(shared_ptr<TresorSession> session, TresorSecretStorage &storage);
TableFunction SecretsFunction(shared_ptr<TresorSession> session, TresorSecretStorage &storage);
//! annotate_secret, grants, grant_secret, revoke_secret (tresor_manage.cpp, specs/005).
vector<TableFunction> ManagementFunctions(shared_ptr<TresorSession> session, TresorSecretStorage &storage);

} // namespace tresor
} // namespace duckdb
