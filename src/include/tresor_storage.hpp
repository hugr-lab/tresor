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

//! GET /v1/secrets, parsed; throws when the service does not answer with a list.
vector<Descriptor> FetchDescriptors(TresorSession &session);

//! The secret storage of one attached service, named after its catalog. duckdb cannot remove a storage:
//! it is registered once per name and instance, activated by the catalog of each ATTACH that commits
//! (TresorCatalog::Initialize) and deactivated when that catalog goes (DETACH, or a rolled-back ATTACH).
class TresorSecretStorage : public SecretStorage {
public:
	TresorSecretStorage(const string &name, int64_t offset);

	//! Serve this session, starting from the list the ATTACH fetched.
	void Activate(shared_ptr<TresorSession> session, vector<Descriptor> initial);
	//! Stop serving - only if `session` is still the one served (a later ATTACH may have taken over).
	void Deactivate(const TresorSession &session);

	//! A fresh descriptor list (corp.secrets()); refreshes the cache. Service secrets of type tresor
	//! included - they are shown, never looked up.
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

	//! The session served now (null: inactive).
	shared_ptr<TresorSession> Current();
	//! After a write: the list is stale, the name's material gone (and a refresh already under way
	//! cannot store the list it fetched before the write).
	void Invalidate(const string &name);
	//! Fresh material for a listed secret, bypassing the cache (the tresor provider: httpfs's REFRESH auto).
	unique_ptr<const BaseSecret> RefreshMaterial(const string &name, optional_ptr<CatalogTransaction> transaction);

	//! The service's own spelling of a secret's name: DuckDB compares names case-insensitively, the
	//! service exactly - a listed secret is addressed as the service lists it, a new one in lower case.
	string ServiceName(const string &name);

private:
	struct Material {
		string version;
		int64_t refreshed_at = 0; // minted by a refresh (RefreshMaterial): parallel refreshes share it
		int64_t valid_until = 0;
		unique_ptr<const BaseSecret> secret;
	};

	//! The descriptors to decide with, and the session to fetch with (null: inactive). The list is
	//! refreshed when stale; a failed refresh keeps the last list authoritative and backs off.
	vector<Descriptor> Snapshot(shared_ptr<TresorSession> &session_out);
	//! The material of a listed secret, from the cache or the service; null when the service no longer
	//! has it for this caller (404/403). No lock held across the network.
	unique_ptr<const BaseSecret> MaterialOf(const shared_ptr<TresorSession> &session, const Descriptor &descriptor,
	                                        optional_ptr<CatalogTransaction> transaction);
	SecretEntry EntryOf(unique_ptr<const BaseSecret> secret);

	mutex lock;       // the state below
	mutex fetch_lock; // one list refresh at a time; others go on with the list they have
	shared_ptr<TresorSession> session;
	vector<Descriptor> descriptors;
	int64_t listed_at = 0;
	int64_t failed_at = 0;
	uint64_t generation = 0; // bumped by every write: a refresh started before it does not land
	unordered_map<string, Material> materials;
};

//! The tresor storage registered under `name` in this instance, if any (never registers one).
optional_ptr<TresorSecretStorage> FindStorage(ClientContext &context, const string &name);

//! The storage for `name` in this instance: registered (inactive) at the first ATTACH of the name,
//! before any login - a name duckdb's secret manager already uses is refused up front.
TresorSecretStorage &StorageFor(ClientContext &context, const string &name);

//! A secret as the protocol's PUT body: {type, provider, scope, params, redact_keys}; VARCHAR params are
//! bare strings, the rest {type, value} - the inverse of the reading, so a secret round-trips.
string SecretBody(const KeyValueSecret &secret);

//! The service's name for a secret: DuckDB compares secret names case-insensitively, the protocol asks for
//! one canonical form - lower case.
string CanonicalName(const string &name);

//! A string as JSON text.
string JsonString(const string &text);

//! A path segment, percent-encoded.
string EncodePathSegment(const string &segment);

//! A typed protocol value ({type, value} or a bare string) as a DuckDB Value; throws naming secret and
//! key, never the value. Numbers are expected as raw text (read with YYJSON_READ_NUMBER_AS_RAW).
Value ProtocolValue(const string &secret, const string &key, const string &type, duckdb_yyjson::yyjson_val *value,
                    optional_ptr<ClientContext> context);

} // namespace tresor
} // namespace duckdb
