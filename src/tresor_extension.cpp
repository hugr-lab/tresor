#define DUCKDB_EXTENSION_MAIN

#include "tresor_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/storage/storage_extension.hpp"

// tresor: the client of an external secrets service (specs/001). A service is ATTACHed -
// `ATTACH 'tresor:https://secrets.corp' AS corp` - and the attached catalog is at once a secret
// storage (CREATE PERSISTENT SECRET ... IN corp), a view of what the caller's role may use
// (corp.secrets()), and the management surface (grants, delegation). The ATTACH prefix is the
// extension's name on purpose: duckdb loads an installed extension by the prefix of the path it is
// asked to attach, so the ATTACH is the only statement a user needs.

namespace duckdb {
namespace {

void TresorVersionFun(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value(TresorExtension().Version()), count_t(args.size()));
}

unique_ptr<Catalog> TresorAttach(optional_ptr<StorageExtensionInfo> storage_info, ClientContext &context,
                                 AttachedDatabase &db, const string &name, AttachInfo &info, AttachOptions &options) {
	throw NotImplementedException("tresor: attaching a secrets service is not implemented yet (specs/002)");
}

unique_ptr<TransactionManager> TresorCreateTransactionManager(optional_ptr<StorageExtensionInfo> storage_info,
                                                              AttachedDatabase &db, Catalog &catalog) {
	throw NotImplementedException("tresor: attaching a secrets service is not implemented yet (specs/002)");
}

void LoadInternal(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto storage = make_shared_ptr<StorageExtension>();
	storage->attach = TresorAttach;
	storage->create_transaction_manager = TresorCreateTransactionManager;
	StorageExtension::Register(config, "tresor", std::move(storage));

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
