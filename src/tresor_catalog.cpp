#include "tresor_catalog.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {
namespace tresor {

TresorCatalog::TresorCatalog(AttachedDatabase &db, shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p)
    : DuckCatalog(db), session(std::move(session_p)), storage(storage_p) {
}

void TresorCatalog::Initialize(bool load_builtin) {
	DuckCatalog::Initialize(false);
	auto transaction = CatalogTransaction::GetSystemTransaction(GetDatabase());
	// the info's constructor marks it `internal`, which duckdb allows only in the system catalog; DROP
	// FUNCTION is refused anyway, by the read-only switch below
	CreateTableFunctionInfo whoami(WhoamiFunction(session));
	whoami.internal = false;
	CreateTableFunction(transaction, whoami);
	CreateTableFunctionInfo secrets(SecretsFunction(session, storage));
	secrets.internal = false;
	CreateTableFunction(transaction, secrets);
	// from here on the database is read-only: its storage stays an ordinary in-memory one (duckdb refuses
	// an in-memory storage opened read-only), and every statement that would modify `corp` is refused by
	// duckdb's own check before it runs
	GetAttached().SetReadOnlyDatabase();
}

void TresorCatalog::OnDetach(ClientContext &context) {
	storage.Deactivate();
	session->Close();
	DuckCatalog::OnDetach(context);
}

} // namespace tresor
} // namespace duckdb
