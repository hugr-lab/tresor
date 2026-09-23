#define DUCKDB_EXTENSION_MAIN

#include "tresor_extension.hpp"
#include "tresor_catalog.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/storage/storage_extension.hpp"

// tresor: the client of an external secrets service (specs/001). A service is ATTACHed -
// `ATTACH 'tresor:secrets.corp' AS corp` - and the attached catalog is at once a secret
// storage (CREATE PERSISTENT SECRET ... IN corp), a view of what the caller's role may use
// (corp.secrets()), and the management surface (grants, delegation). The ATTACH prefix is the
// extension's name on purpose: duckdb loads an installed extension by the prefix of the path it is
// asked to attach, so the ATTACH is the only statement a user needs.

namespace duckdb {
namespace {

void TresorVersionFun(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value(TresorExtension().Version()), count_t(args.size()));
}

// ATTACH (specs/002): discovery and the login run here, before any catalog exists - a failed login
// leaves nothing attached. The catalog is an in-memory DuckCatalog, so the path handed back to duckdb
// is `:memory:` (a DuckCatalog's storage opens `info.path`).
unique_ptr<Catalog> TresorAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                 AttachedDatabase &db, const string &name, AttachInfo &info, AttachOptions &options) {
	auto request = tresor::ParseAttach(info.path, options.options);
	options.options.clear(); // all of them are tresor's, and consumed
	// duckdb refuses a taken name only after this callback: without this, a person would complete a whole
	// browser login only to read "already exists"
	if (DatabaseManager::Get(context).GetDatabase(context, Identifier(name))) {
		throw BinderException("Failed to attach database: database with name \"%s\" already exists", name);
	}
	// the secret storage of this name, registered (inactive) before any login: a name duckdb's secret
	// manager already uses (memory, local_file, ...) is refused up front (specs/004)
	auto &storage = tresor::StorageFor(context, name);
	auto session = tresor::Login(context, request);
	// the list the storage starts from: a service that cannot list its secrets is not attached
	tresor::Caller node;
	node.session = session;
	auto initial = tresor::FetchDescriptors(node);
	shared_ptr<tresor::TresorActor> actor;
	if (request.act_for_sessions) {
		// acting for duckdb-acl's sessions (specs/008): refused now if acl speaks another contract
		tresor::TresorActor::CheckHooks(db.GetDatabase());
		tresor::ActorOptions actor_options;
		actor_options.on_behalf_of = request.on_behalf_of;
		actor_options.scope = request.exchange_scope;
		actor_options.grant_wait_seconds = request.grant_wait_seconds;
		actor = make_shared_ptr<tresor::TresorActor>(session, std::move(actor_options));
	}
	info.path = IN_MEMORY_PATH;
	return make_uniq<tresor::TresorCatalog>(db, std::move(session), storage, std::move(initial), std::move(actor));
}

unique_ptr<TransactionManager> TresorCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                              AttachedDatabase &db, Catalog &catalog) {
	return make_uniq<DuckTransactionManager>(db);
}

void LoadInternal(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = TresorAttach;
	storage->create_transaction_manager = TresorCreateTransactionManager;
	StorageExtension::Register(config, "tresor", std::move(storage));

	RegisterTresorSecret(loader);
	RegisterTresorSecretParam(loader);

	loader.SetDescription("Client for an external secrets service: one OIDC login, role-based secrets");
	loader.RegisterFunction(ScalarFunction(Identifier("tresor_version"), {}, LogicalType::VARCHAR, TresorVersionFun));
}

} // namespace

void TresorExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string TresorExtension::Name() {
	return "tresor";
}

std::string TresorExtension::Version() const {
#ifdef EXT_VERSION_TRESOR
	return EXT_VERSION_TRESOR;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(tresor, loader) {
	duckdb::LoadInternal(loader);
}
}
