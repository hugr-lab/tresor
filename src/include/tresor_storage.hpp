//===----------------------------------------------------------------------===//
// tresor_storage.hpp - the service's secrets in DuckDB's secret lookup (specs/004)
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_actor.hpp"
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
vector<Descriptor> FetchDescriptors(const Caller &caller);

//! The secret storage of one attached service, named after its catalog. duckdb cannot remove a storage:
//! it is registered once per name and instance, activated by the catalog of each ATTACH that commits
//! (TresorCatalog::Initialize) and deactivated when that catalog goes (DETACH, or a rolled-back ATTACH).
class TresorSecretStorage : public SecretStorage {
public:
	TresorSecretStorage(const string &name, int64_t offset);

	//! Serve this session, starting from the list the ATTACH fetched; `actor` (may be null) acts for
	//! duckdb-acl's sessions (specs/008).
	void Activate(shared_ptr<TresorSession> session, vector<Descriptor> initial, shared_ptr<TresorActor> actor);
	//! Stop serving - only if `session` is still the one served (a later ATTACH may have taken over).
	void Deactivate(const TresorSession &session);

	//! Whom a call made for the statement running on `context` goes as (specs/008): the node, when no
	//! duckdb-acl session runs there (or there is no connection); the session's user through its grant;
	//! or nobody, with the reason. A lookup waits here for a pending grant, up to SESSION_GRANT_WAIT.
	Caller CallerFor(optional_ptr<ClientContext> context);
	//! The service refused a caller's grant (401): the acl session gets nothing more.
	void GrantRejected(const Caller &caller);

	//! A fresh descriptor list (corp.secrets()); refreshes the caller's cache. Service secrets of type
	//! tresor included - they are shown, never looked up.
	vector<Descriptor> Refresh(const Caller &caller);

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
	//! After a write: every view's list is stale, the name's material gone (and a refresh already under
	//! way cannot store the list it fetched before the write).
	void Invalidate(const string &name);
	//! An acl session is over: its list and material go.
	void ForgetSession(const string &acl_session);
	//! Fresh material for a listed secret, bypassing the cache (the tresor provider: httpfs's REFRESH auto).
	unique_ptr<const BaseSecret> RefreshMaterial(const string &name, optional_ptr<CatalogTransaction> transaction);

	//! The service's own spelling of a secret's name: DuckDB compares names case-insensitively, the
	//! service exactly - a listed secret is addressed as the service lists it, a new one in lower case.
	string ServiceName(const Caller &caller, const string &name);

private:
	struct Material {
		string version;
		int64_t refreshed_at = 0; // minted by a refresh (RefreshMaterial): parallel refreshes share it
		int64_t valid_until = 0;
		unique_ptr<const BaseSecret> secret;
	};
	//! What one caller sees: the node, or one acl session (never shared between them).
	struct View {
		mutex fetch_lock; // one list refresh at a time; others go on with the list they have
		vector<Descriptor> descriptors;
		int64_t listed_at = 0;
		int64_t failed_at = 0;
		bool listed = false; // a view never listed waits for its first list instead of matching nothing
		unordered_map<string, Material> materials;
	};

	//! The view of a caller (created for a new acl session); null when the caller cannot be served.
	shared_ptr<View> ViewOf(const Caller &caller);
	//! The descriptors to decide with. The list is refreshed when stale; a failed refresh keeps the last
	//! list authoritative and backs off.
	vector<Descriptor> Snapshot(const Caller &caller, shared_ptr<View> &view_out);
	//! The material of a listed secret, from the view's cache or the service; null when the service no
	//! longer has it for this caller (404/403). No lock held across the network.
	unique_ptr<const BaseSecret> MaterialOf(const Caller &caller, View &view, const Descriptor &descriptor,
	                                        optional_ptr<CatalogTransaction> transaction);
	SecretEntry EntryOf(unique_ptr<const BaseSecret> secret);
	//! The node itself, for the same session: the view lookups fall back to under an acl session (specs/009).
	static Caller NodeOf(const Caller &caller);
	//! The best match of one view (a caller's), with its material; no match when the caller has none.
	SecretMatch MatchIn(const Caller &caller, const string &path, const string &type,
	                    optional_ptr<CatalogTransaction> transaction);
	unique_ptr<SecretEntry> ByNameIn(const Caller &caller, const string &name,
	                                 optional_ptr<CatalogTransaction> transaction);
	Caller CallerOf(optional_ptr<CatalogTransaction> transaction);

	mutex lock; // the state below, and every view's list and materials
	shared_ptr<TresorSession> session;
	shared_ptr<TresorActor> actor;
	shared_ptr<View> node;
	unordered_map<string, shared_ptr<View>> acl_views;
	uint64_t generation = 0; // bumped by every write: a refresh started before it does not land
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
