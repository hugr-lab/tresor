#include "tresor_storage.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <chrono>

// The service's secrets in DuckDB's secret lookup (specs/004): descriptors listed without material and
// cached briefly, scopes matched locally by duckdb's own rule, material fetched only for the secret a
// lookup picks and kept in memory for a bounded time. Nothing here writes or logs material.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

constexpr int64_t LIST_TTL_SECONDS = 30;   // a descriptor list is refreshed after this
constexpr int64_t RETRY_AFTER_SECONDS = 5; // a failed refresh is not retried sooner
constexpr int64_t STATIC_MATERIAL_SECONDS = 300;
constexpr int64_t DYNAMIC_MARGIN_SECONDS = 30; // a dynamic secret is refetched this long before it expires

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

string Str(yyjson_val *obj, const char *key) {
	auto value = obj && yyjson_is_obj(obj) ? yyjson_obj_get(obj, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : "";
}

vector<string> StrList(yyjson_val *value) {
	vector<string> out;
	if (value && yyjson_is_arr(value)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(value, idx, max, item) {
			if (yyjson_is_str(item)) {
				out.emplace_back(yyjson_get_str(item));
			}
		}
	}
	return out;
}

//! A path segment: everything but the unreserved characters percent-encoded.
string Encode(const string &segment) {
	static const char *hex = "0123456789ABCDEF";
	string out;
	for (unsigned char c : segment) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out.push_back(char(c));
		} else {
			out.push_back('%');
			out.push_back(hex[c >> 4]);
			out.push_back(hex[c & 15]);
		}
	}
	return out;
}

//! Keys redacted whatever the service says: a conservative net under a service that forgets to.
const vector<string> &AlwaysRedacted() {
	static const vector<string> keys {"secret",      "password",         "token",        "session_token",
	                                  "private_key", "client_secret",    "bearer_token", "access_token",
	                                  "account_key", "connection_string"};
	return keys;
}

//! A service's secret of type tresor is a login for DuckDB to use, never one a service may plant: it
//! takes no part in the lookup (tresor's own login search walks every storage).
bool Lookupable(const Descriptor &d) {
	return d.type != "tresor";
}

//! The instance's tresor storages, by catalog name: kept in the instance's object cache, so the raw
//! pointers (the SecretManager owns the storages, for the instance's lifetime) never outlive them.
struct StorageRegistry : public ObjectCacheEntry {
	static string ObjectType() {
		return "tresor_secret_storages";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx(); // never evicted
	}
	mutex lock;
	unordered_map<string, optional_ptr<TresorSecretStorage>> storages;
	int64_t next_offset = 40;
};

LogicalType ParseType(const string &type, optional_ptr<ClientContext> context) {
	if (context) {
		return TransformStringToLogicalType(type, *context);
	}
	// no connection to parse with (a background lookup): the simple types only
	auto id = TransformStringToLogicalTypeId(type);
	if (id == LogicalTypeId::UNBOUND || id == LogicalTypeId::INVALID) {
		throw InvalidInputException("a composite type needs a connection to parse");
	}
	return LogicalType(id);
}

//! JSON (numbers as raw text) to a Value of `type`. Messages thrown here never carry the value.
Value FromJson(const LogicalType &type, yyjson_val *value) {
	if (!value || yyjson_is_null(value)) {
		return Value(type);
	}
	switch (type.id()) {
	case LogicalTypeId::LIST:
	case LogicalTypeId::ARRAY: {
		if (!yyjson_is_arr(value)) {
			throw InvalidInputException("needs a JSON array");
		}
		auto &child = type.id() == LogicalTypeId::LIST ? ListType::GetChildType(type) : ArrayType::GetChildType(type);
		vector<Value> items;
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(value, idx, max, item) {
			items.push_back(FromJson(child, item));
		}
		if (type.id() == LogicalTypeId::LIST) {
			return Value::LIST(child, std::move(items));
		}
		if (items.size() != ArrayType::GetSize(type)) {
			throw InvalidInputException("needs %d elements", ArrayType::GetSize(type));
		}
		return Value::ARRAY(child, std::move(items));
	}
	case LogicalTypeId::STRUCT: {
		if (!yyjson_is_obj(value)) {
			throw InvalidInputException("needs a JSON object");
		}
		auto &children = StructType::GetChildTypes(type);
		vector<Value> fields(children.size());
		vector<bool> seen(children.size(), false);
		size_t idx, max;
		yyjson_val *key, *item;
		yyjson_obj_foreach(value, idx, max, key, item) {
			// field names compare like DuckDB identifiers: case-insensitively; an unknown one is an error
			bool matched = false;
			for (idx_t i = 0; i < children.size(); i++) {
				if (StringUtil::CIEquals(children[i].first.GetIdentifierName(), yyjson_get_str(key))) {
					fields[i] = FromJson(children[i].second, item);
					seen[i] = matched = true;
					break;
				}
			}
			if (!matched) {
				throw InvalidInputException("has a field its STRUCT does not");
			}
		}
		for (idx_t i = 0; i < children.size(); i++) {
			if (!seen[i]) {
				fields[i] = Value(children[i].second); // a missing field is NULL
			}
		}
		return Value::STRUCT(type, std::move(fields));
	}
	case LogicalTypeId::MAP: {
		if (!yyjson_is_obj(value)) {
			throw InvalidInputException("needs a JSON object");
		}
		auto &key_type = MapType::KeyType(type);
		auto &value_type = MapType::ValueType(type);
		vector<Value> keys, values;
		size_t idx, max;
		yyjson_val *key, *item;
		yyjson_obj_foreach(value, idx, max, key, item) {
			keys.push_back(Value(yyjson_get_str(key)).DefaultCastAs(key_type));
			values.push_back(FromJson(value_type, item));
		}
		return Value::MAP(key_type, value_type, std::move(keys), std::move(values));
	}
	default:
		break;
	}
	// scalars are cast from their JSON text: a raw number keeps every digit (HUGEINT, DECIMAL)
	if (yyjson_is_str(value)) {
		return Value(yyjson_get_str(value)).DefaultCastAs(type);
	}
	if (yyjson_is_raw(value)) {
		return Value(string(yyjson_get_raw(value), yyjson_get_len(value))).DefaultCastAs(type);
	}
	if (yyjson_is_bool(value)) {
		return Value::BOOLEAN(yyjson_get_bool(value)).DefaultCastAs(type);
	}
	throw InvalidInputException("needs a JSON scalar");
}

} // namespace

Value ProtocolValue(const string &secret, const string &key, const string &type, yyjson_val *value,
                    optional_ptr<ClientContext> context) {
	try {
		return FromJson(type.empty() ? LogicalType::VARCHAR : ParseType(type, context), value);
	} catch (std::exception &) {
		// the secret, the key and the type - never the value, nor a cast message that would quote it
		throw InvalidInputException("tresor: the parameter %s of the secret %s is not a valid %s", key, secret,
		                            type.empty() ? "VARCHAR" : type);
	}
}

vector<Descriptor> FetchDescriptors(TresorSession &session) {
	auto response = session.Call("GET", "/v1/secrets");
	if (response.status != 200) {
		throw IOException("tresor: listing the secrets of %s: %s", session.Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	if (!root || !yyjson_is_arr(root)) {
		throw IOException("tresor: %s answered the secrets list with no JSON array", session.Info().host);
	}
	vector<Descriptor> out;
	size_t idx, max;
	yyjson_val *item;
	yyjson_arr_foreach(root, idx, max, item) {
		Descriptor d;
		d.name = Str(item, "name");
		d.type = StringUtil::Lower(Str(item, "type"));
		d.provider = Str(item, "provider");
		d.scope = StrList(yyjson_obj_get(item, "scope"));
		d.comment = Str(item, "comment");
		d.owner = Str(item, "owner");
		d.permissions = StrList(yyjson_obj_get(item, "permissions"));
		auto dynamic = yyjson_obj_get(item, "dynamic");
		d.dynamic = dynamic && yyjson_is_true(dynamic);
		d.updated_at = Str(item, "updated_at");
		d.version = Str(item, "version");
		if (d.provider.empty()) {
			d.provider = "config";
		}
		if (!d.name.empty() && !d.type.empty()) {
			out.push_back(std::move(d));
		}
	}
	return out;
}

TresorSecretStorage::TresorSecretStorage(const string &name, int64_t offset) : SecretStorage(name, offset) {
	persistent = true; // the secrets live in the service (writes: specs/005)
}

void TresorSecretStorage::Activate(shared_ptr<TresorSession> session_p, vector<Descriptor> initial) {
	lock_guard<mutex> guard(lock);
	session = std::move(session_p);
	descriptors = std::move(initial);
	listed_at = NowSeconds();
	failed_at = 0;
	materials.clear();
}

void TresorSecretStorage::Deactivate(const TresorSession &which) {
	lock_guard<mutex> guard(lock);
	if (session.get() != &which) {
		return; // another ATTACH of this name serves now
	}
	session.reset();
	descriptors.clear();
	materials.clear();
}

bool TresorSecretStorage::IncludeInLookups() {
	lock_guard<mutex> guard(lock);
	return session != nullptr;
}

vector<Descriptor> TresorSecretStorage::Snapshot(shared_ptr<TresorSession> &session_out) {
	{
		lock_guard<mutex> guard(lock);
		session_out = session;
		auto now = NowSeconds();
		if (!session || now - listed_at < LIST_TTL_SECONDS || now - failed_at < RETRY_AFTER_SECONDS) {
			return descriptors;
		}
	}
	// stale: one refresh at a time, outside the state lock; a lookup arriving meanwhile goes on with the
	// list it has rather than queueing behind the network
	unique_lock<mutex> fetching(fetch_lock, std::try_to_lock);
	if (!fetching.owns_lock()) {
		lock_guard<mutex> guard(lock);
		return descriptors;
	}
	try {
		auto fresh = FetchDescriptors(*session_out);
		lock_guard<mutex> guard(lock);
		if (session == session_out) {
			descriptors = std::move(fresh);
			listed_at = NowSeconds();
		}
		return descriptors;
	} catch (std::exception &) {
		// the service is unreachable: the last list stays authoritative for matching (a secret it covers
		// fails at its material fetch - closed; a path it does not cover is not this storage's business)
		lock_guard<mutex> guard(lock);
		failed_at = NowSeconds();
		return descriptors;
	}
}

vector<Descriptor> TresorSecretStorage::Refresh() {
	shared_ptr<TresorSession> current;
	{
		lock_guard<mutex> guard(lock);
		current = session;
	}
	if (!current) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	auto fresh = FetchDescriptors(*current);
	lock_guard<mutex> guard(lock);
	if (session == current) {
		descriptors = fresh;
		listed_at = NowSeconds();
		failed_at = 0;
	}
	return fresh;
}

unique_ptr<const BaseSecret> TresorSecretStorage::MaterialOf(const shared_ptr<TresorSession> &current,
                                                             const Descriptor &d,
                                                             optional_ptr<CatalogTransaction> transaction) {
	auto now = NowSeconds();
	{
		lock_guard<mutex> guard(lock);
		auto cached = materials.find(d.name);
		if (cached != materials.end() && cached->second.version == d.version && cached->second.valid_until > now) {
			return cached->second.secret->Clone();
		}
	}
	auto response = current->Call("GET", "/v1/secrets/" + Encode(d.name));
	if (response.status == 404 || response.status == 403) {
		// gone, or no longer ours to use, since the list was fetched: not a match - and the list is stale
		lock_guard<mutex> guard(lock);
		listed_at = 0;
		return nullptr;
	}
	if (response.status != 200) {
		throw IOException("tresor: the secret %s of %s: %s", d.name, current->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	// numbers as raw text: a HUGEINT or DECIMAL keeps every digit
	JsonDoc doc(response.body, YYJSON_READ_NUMBER_AS_RAW);
	auto root = doc.Root();
	auto params = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "params") : nullptr;
	if (!params || !yyjson_is_obj(params)) {
		throw IOException("tresor: the secret %s of %s came without params", d.name, current->Info().host);
	}
	optional_ptr<ClientContext> context = transaction ? transaction->context : nullptr;
	auto secret = make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(d.provider), Identifier(d.name));
	size_t idx, max;
	yyjson_val *key, *item;
	yyjson_obj_foreach(params, idx, max, key, item) {
		string name = yyjson_get_str(key);
		auto lowered = StringUtil::Lower(name);
		if (yyjson_is_str(item)) {
			secret->secret_map[Identifier(lowered)] = Value(yyjson_get_str(item)); // shorthand for VARCHAR
		} else if (yyjson_is_obj(item) && !Str(item, "type").empty()) {
			secret->secret_map[Identifier(lowered)] =
			    ProtocolValue(d.name, name, Str(item, "type"), yyjson_obj_get(item, "value"), context);
		} else {
			throw InvalidInputException("tresor: the parameter %s of the secret %s is neither a string nor "
			                            "{type, value}",
			                            name, d.name);
		}
	}
	for (auto &redact : StrList(yyjson_obj_get(root, "redact_keys"))) {
		secret->redact_keys.insert(Identifier(StringUtil::Lower(redact)));
	}
	for (auto &redact : AlwaysRedacted()) {
		if (secret->secret_map.find(Identifier(redact)) != secret->secret_map.end()) {
			secret->redact_keys.insert(Identifier(redact));
		}
	}
	// how long this material may be served: a static secret a few minutes (or until its version changes),
	// a dynamic one until shortly before it expires - with a margin of at most half its life, so a
	// short-lived credential is not minted anew for every file of a scan
	int64_t valid_until = now + STATIC_MATERIAL_SECONDS;
	auto expires = Str(root, "expires_at");
	timestamp_t parsed;
	if (!expires.empty() &&
	    Timestamp::TryConvertTimestamp(expires.c_str(), expires.size(), parsed, true) == TimestampCastResult::SUCCESS) {
		auto expires_at = Timestamp::GetEpochSeconds(parsed);
		auto margin = MinValue<int64_t>(DYNAMIC_MARGIN_SECONDS, MaxValue<int64_t>(0, (expires_at - now) / 2));
		valid_until = MinValue<int64_t>(valid_until, expires_at - margin);
	} else if (d.dynamic) {
		valid_until = now; // a dynamic secret without a readable expiry is never reused
	}
	lock_guard<mutex> guard(lock);
	if (session != current) {
		return std::move(secret); // detached meanwhile: served once, never cached
	}
	// expired entries go now: material is kept for a bounded time, not until DETACH
	for (auto it = materials.begin(); it != materials.end();) {
		it = it->second.valid_until <= now ? materials.erase(it) : std::next(it);
	}
	if (valid_until > now) {
		Material material;
		material.version = d.version;
		material.valid_until = valid_until;
		material.secret = secret->Clone();
		materials[d.name] = std::move(material);
	}
	return std::move(secret);
}

SecretEntry TresorSecretStorage::EntryOf(unique_ptr<const BaseSecret> secret) {
	SecretEntry entry(std::move(secret));
	entry.persist_type = SecretPersistType::PERSISTENT;
	entry.storage_mode = storage_name;
	return entry;
}

SecretMatch TresorSecretStorage::LookupSecret(const string &path, const string &type,
                                              optional_ptr<CatalogTransaction> transaction) {
	shared_ptr<TresorSession> current;
	auto list = Snapshot(current);
	if (!current) {
		return SecretMatch();
	}
	// score the usable descriptors by duckdb's own rule, on placeholders without material
	SecretMatch best;
	optional_ptr<const Descriptor> best_descriptor;
	for (auto &d : list) {
		if (!Lookupable(d) || !StringUtil::CIEquals(d.type, type) || !d.May("use")) {
			continue; // a secret the caller may not use never matches: its material would be refused
		}
		auto entry =
		    EntryOf(make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(d.provider), Identifier(d.name)));
		best = SelectBestMatch(entry, path, tie_break_offset, best);
		if (best.HasMatch() && best.GetSecret().GetName().GetIdentifierName() == d.name) {
			best_descriptor = &d; // this descriptor is the best so far
		}
	}
	if (!best_descriptor) {
		return SecretMatch();
	}
	auto material = MaterialOf(current, *best_descriptor, transaction);
	if (!material) {
		return SecretMatch();
	}
	auto entry = EntryOf(std::move(material));
	return SecretMatch(entry, best.score);
}

unique_ptr<SecretEntry> TresorSecretStorage::GetSecretByName(const string &name,
                                                             optional_ptr<CatalogTransaction> transaction) {
	shared_ptr<TresorSession> current;
	auto list = Snapshot(current);
	if (!current) {
		return nullptr;
	}
	for (auto &d : list) {
		// a secret the caller may see but not use is not one it can have by name: not found here, so a
		// local secret of that name is not shadowed by an error
		if (d.name == name && Lookupable(d) && d.May("use")) {
			auto material = MaterialOf(current, d, transaction);
			return material ? make_uniq<SecretEntry>(EntryOf(std::move(material))) : nullptr;
		}
	}
	return nullptr;
}

vector<SecretEntry> TresorSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	shared_ptr<TresorSession> current;
	auto list = Snapshot(current); // never throws: duckdb_secrets() must work while a service is down
	vector<SecretEntry> out;
	if (!current) {
		return out;
	}
	// descriptors only: listing never fetches material
	for (auto &d : list) {
		if (Lookupable(d)) {
			out.push_back(EntryOf(
			    make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(d.provider), Identifier(d.name))));
		}
	}
	return out;
}

unique_ptr<SecretEntry> TresorSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                         OnCreateConflict on_conflict,
                                                         optional_ptr<CatalogTransaction> transaction) {
	throw NotImplementedException("tresor: storing secrets in %s is not supported yet (specs/005)", storage_name);
}

void TresorSecretStorage::DropSecretByName(const Identifier &name, OnEntryNotFound on_entry_not_found,
                                           optional_ptr<CatalogTransaction> transaction) {
	throw NotImplementedException("tresor: dropping secrets from %s is not supported yet (specs/005)", storage_name);
}

TresorSecretStorage &StorageFor(ClientContext &context, const string &name) {
	auto &manager = SecretManager::Get(context);
	// duckdb loads its own storages (memory, local_file) lazily, at the first secret operation: have it do
	// so now, or a tresor storage registered first under one of their names would break its initialization
	(void)manager.AllSecrets(CatalogTransaction::GetSystemCatalogTransaction(context));
	auto registry = ObjectCache::GetObjectCache(context).GetOrCreate<StorageRegistry>(StorageRegistry::ObjectType());
	if (!registry) {
		throw InternalException("tresor: the storage registry's cache key is taken by another object");
	}
	lock_guard<mutex> guard(registry->lock);
	auto key = StringUtil::Lower(name);
	auto existing = registry->storages.find(key);
	if (existing != registry->storages.end()) {
		return *existing->second;
	}
	// the offset must be unique among the instance's storages (duckdb's tie-break rule) and stay below 100,
	// where it would start to outweigh one character of scope: skip the taken ones
	while (registry->next_offset < 100) {
		auto storage = make_uniq<TresorSecretStorage>(name, registry->next_offset++);
		auto &ref = *storage;
		try {
			manager.LoadSecretStorage(std::move(storage));
		} catch (InvalidConfigurationException &ex) {
			if (StringUtil::Contains(ex.what(), "tie break score collides")) {
				continue;
			}
			throw InvalidInputException("tresor: cannot attach as \"%s\": %s", name, ErrorData(ex).RawMessage());
		}
		registry->storages[key] = &ref;
		return ref;
	}
	throw InvalidInputException("tresor: too many distinct names attached in this process - reuse a name");
}

} // namespace tresor
} // namespace duckdb
