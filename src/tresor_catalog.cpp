#include "tresor_catalog.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {
namespace tresor {

TresorCatalog::TresorCatalog(AttachedDatabase &db, shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p,
                             vector<Descriptor> initial_p, shared_ptr<TresorActor> actor_p)
    : DuckCatalog(db), session(std::move(session_p)), storage(storage_p), initial(std::move(initial_p)),
      actor(std::move(actor_p)) {
}

TresorCatalog::~TresorCatalog() {
	Shutdown();
}

void TresorCatalog::Shutdown() {
	storage.Deactivate(*session);
	if (actor) {
		actor->Stop(); // the grants still held are revoked with the login, before it goes
	}
	session->Close();
}

void TresorCatalog::Initialize(bool load_builtin) {
	DuckCatalog::Initialize(false);
	auto transaction = CatalogTransaction::GetSystemTransaction(GetDatabase());
	// the info's constructor marks it `internal`, which duckdb allows only in the system catalog; DROP
	// FUNCTION is refused anyway, by the read-only switch below
	CreateTableFunctionInfo whoami(WhoamiFunction(session, storage));
	whoami.internal = false;
	CreateTableFunction(transaction, whoami);
	CreateTableFunctionInfo secrets(SecretsFunction(session, storage));
	secrets.internal = false;
	CreateTableFunction(transaction, secrets);
	for (auto &function : ManagementFunctions(session, storage)) {
		CreateTableFunctionInfo manage(std::move(function));
		manage.internal = false;
		CreateTableFunction(transaction, manage);
	}
	// the secrets join the lookup only now, with the catalog that serves them: an ATTACH failing before
	// this point leaves nothing behind (specs/004)
	storage.Activate(session, std::move(initial), actor);
	if (actor) {
		// acl's sessions are observed from here on (specs/008); a session's caches go with it
		auto &served = storage;
		actor->OnSessionGone([&served](const string &acl_session) { served.ForgetSession(acl_session); });
		actor->Start(GetDatabase());
	}
	// from here on the database is read-only: its storage stays an ordinary in-memory one (duckdb refuses
	// an in-memory storage opened read-only), and every statement that would modify `corp` is refused by
	// duckdb's own check before it runs
	GetAttached().SetReadOnlyDatabase();
}

void TresorCatalog::OnDetach(ClientContext &context) {
	Shutdown();
	DuckCatalog::OnDetach(context);
}

} // namespace tresor
} // namespace duckdb
