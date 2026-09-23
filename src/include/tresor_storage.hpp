//===----------------------------------------------------------------------===//
// tresor_storage.hpp - the service's secrets in DuckDB's secret lookup (specs/004)
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"

#include "duckdb/common/mutex.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_storage.hpp"
#include "yyjson.hpp"

namespace duckdb {
class ClientContext;

namespace tresor {

//! One entry of GET /v1/secrets: what the caller may see, never material.
struct Descriptor {
	string name;
	string type;
	string provider;
	vector<string> scope;
	string comment;
	string owner;
	vector<string> permissions;
	bool dynamic = false;
	string updated_at;
	string version;

	bool May(const string &verb) const {
		return std::find(permissions.begin(), permissions.end(), verb) != permissions.end();
	}
};

//! The secret storage of one attached service, named after its catalog. duckdb cannot remove a storage,
//! so DETACH deactivates it and a later ATTACH of the same name reactivates it with the new session.
class TresorSecretStorage : public SecretStorage {
public:
	TresorSecretStorage(const string &name, int64_t offset);

	//! ATTACH: serve this session. DETACH: Deactivate - no session, no caches, empty answers.
	void Activate(shared_ptr<TresorSession> session);
	void Deactivate();

	//! A fresh descriptor list (corp.secrets()); refreshes the cache.
	vector<Descriptor> Refresh();

	unique_ptr<SecretEntry> StoreSecret(unique_ptr<const BaseSecret> secret, OnCreateConflict on_conflict,
	                                    optional_ptr<CatalogTransaction> transaction = nullptr) override;
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction = nullptr) override;
	void DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction = nullptr) override;
	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction = nullptr) override;
	unique_ptr<SecretEntry> GetSecretByName(const string &name,
	                                        optional_ptr<CatalogTransaction> transaction = nullptr) override;
	bool IncludeInLookups() override;

private:
	struct Material {
		string version;
		int64_t valid_until = 0;
		unique_ptr<const BaseSecret> secret;
	};

	//! The cached list, refreshed when stale (30 s); throws when the service never answered. Lock held.
	const vector<Descriptor> &Descriptors();
	vector<Descriptor> FetchDescriptors();
	//! The material of a listed secret, from the cache or the service. Lock held.
	unique_ptr<const BaseSecret> MaterialOf(const Descriptor &descriptor, optional_ptr<CatalogTransaction> transaction);
	SecretEntry EntryOf(unique_ptr<const BaseSecret> secret);

	mutex lock;
	shared_ptr<TresorSession> session;
	vector<Descriptor> descriptors;
	int64_t listed_at = 0;
	bool listed = false;
	unordered_map<string, Material> materials;
};

//! The storage for `name` in this instance: registered at the first ATTACH of the name, reused after.
TresorSecretStorage &StorageFor(ClientContext &context, const string &name);

//! A typed protocol value ({type, value} or a bare string) as a DuckDB Value; throws naming secret and key.
Value ProtocolValue(const string &secret, const string &key, const string &type, duckdb_yyjson::yyjson_val *value,
                    optional_ptr<ClientContext> context);

} // namespace tresor
} // namespace duckdb
