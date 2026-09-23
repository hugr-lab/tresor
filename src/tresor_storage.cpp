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

constexpr int64_t LIST_TTL_SECONDS = 30;     // a descriptor list is refreshed after this
constexpr int64_t STALE_GRACE_SECONDS = 300; // an old list serves this long past its TTL when the service is down
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
	static const vector<string> keys {"secret",      "password",      "token",        "session_token",
	                                  "private_key", "client_secret", "bearer_token", "access_token"};
	return keys;
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
		throw InvalidInputException("cannot parse the type \"%s\" without a connection", type);
	}
	return LogicalType(id);
}

Value FromJson(const LogicalType &type, yyjson_val *value) {
	if (!value || yyjson_is_null(value)) {
		return Value(type);
	}
	switch (type.id()) {
	case LogicalTypeId::LIST: {
		if (!yyjson_is_arr(value)) {
			throw InvalidInputException("a LIST needs a JSON array");
		}
		auto &child = ListType::GetChildType(type);
		vector<Value> items;
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(value, idx, max, item) {
			items.push_back(FromJson(child, item));
		}
		return Value::LIST(child, std::move(items));
	}
	case LogicalTypeId::STRUCT: {
		if (!yyjson_is_obj(value)) {
			throw InvalidInputException("a STRUCT needs a JSON object");
		}
		vector<Value> fields;
		for (auto &child : StructType::GetChildTypes(type)) {
			fields.push_back(FromJson(child.second, yyjson_obj_get(value, child.first.GetIdentifierName().c_str())));
		}
		return Value::STRUCT(type, std::move(fields));
	}
	case LogicalTypeId::MAP: {
		if (!yyjson_is_obj(value)) {
			throw InvalidInputException("a MAP needs a JSON object");
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
	Value scalar;
	if (yyjson_is_str(value)) {
		scalar = Value(yyjson_get_str(value));
	} else if (yyjson_is_bool(value)) {
		scalar = Value::BOOLEAN(yyjson_get_bool(value));
	} else if (yyjson_is_uint(value)) {
		scalar = Value::UBIGINT(yyjson_get_uint(value));
	} else if (yyjson_is_int(value)) {
		scalar = Value::BIGINT(yyjson_get_sint(value));
	} else if (yyjson_is_real(value)) {
		scalar = Value::DOUBLE(yyjson_get_real(value));
	} else {
		throw InvalidInputException("a %s needs a JSON scalar", type.ToString());
	}
	return scalar.DefaultCastAs(type);
}

} // namespace

Value ProtocolValue(const string &secret, const string &key, const string &type, yyjson_val *value,
                    optional_ptr<ClientContext> context) {
	try {
		return FromJson(type.empty() ? LogicalType::VARCHAR : ParseType(type, context), value);
	} catch (std::exception &ex) {
		// the message names the secret, the key and the type - never the value
		ErrorData error(ex);
		throw InvalidInputException("tresor: the parameter %s of the secret %s is not a valid %s: %s", key, secret,
		                            type.empty() ? "VARCHAR" : type, error.RawMessage());
	}
}

TresorSecretStorage::TresorSecretStorage(const string &name, int64_t offset) : SecretStorage(name, offset) {
	persistent = true; // the secrets live in the service (writes: specs/005)
}

void TresorSecretStorage::Activate(shared_ptr<TresorSession> session_p) {
	lock_guard<mutex> guard(lock);
	session = std::move(session_p);
	descriptors.clear();
	materials.clear();
	listed = false;
	listed_at = 0;
}

void TresorSecretStorage::Deactivate() {
	lock_guard<mutex> guard(lock);
	session.reset();
	descriptors.clear();
	materials.clear();
	listed = false;
}

bool TresorSecretStorage::IncludeInLookups() {
	lock_guard<mutex> guard(lock);
	return session != nullptr;
}

vector<Descriptor> TresorSecretStorage::FetchDescriptors() {
	auto response = session->Call("GET", "/v1/secrets");
	if (response.status != 200) {
		throw IOException("tresor: listing the secrets of %s: %s", session->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	if (!root || !yyjson_is_arr(root)) {
		throw IOException("tresor: %s answered the secrets list with no JSON array", session->Info().host);
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

const vector<Descriptor> &TresorSecretStorage::Descriptors() {
	auto now = NowSeconds();
	if (listed && now - listed_at < LIST_TTL_SECONDS) {
		return descriptors;
	}
	try {
		descriptors = FetchDescriptors();
		listed = true;
		listed_at = now;
	} catch (std::exception &) {
		// a service that never answered: fail closed - a missing credential must not quietly become an
		// anonymous request. An old list serves a while longer.
		if (!listed || now - listed_at > LIST_TTL_SECONDS + STALE_GRACE_SECONDS) {
			throw;
		}
	}
	return descriptors;
}

vector<Descriptor> TresorSecretStorage::Refresh() {
	lock_guard<mutex> guard(lock);
	if (!session) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	descriptors = FetchDescriptors();
	listed = true;
	listed_at = NowSeconds();
	return descriptors;
}

unique_ptr<const BaseSecret> TresorSecretStorage::MaterialOf(const Descriptor &d,
                                                             optional_ptr<CatalogTransaction> transaction) {
	auto now = NowSeconds();
	auto cached = materials.find(d.name);
	if (cached != materials.end() && cached->second.version == d.version && cached->second.valid_until > now) {
		return cached->second.secret->Clone();
	}
	auto response = session->Call("GET", "/v1/secrets/" + Encode(d.name));
	if (response.status != 200) {
		throw InvalidInputException("tresor: the secret %s of %s: %s", d.name, session->Info().host,
		                            DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	auto params = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "params") : nullptr;
	if (!params || !yyjson_is_obj(params)) {
		throw IOException("tresor: the secret %s of %s came without params", d.name, session->Info().host);
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
		} else {
			secret->secret_map[Identifier(lowered)] =
			    ProtocolValue(d.name, name, Str(item, "type"), yyjson_obj_get(item, "value"), context);
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
	// how long this material may be served: a dynamic secret until shortly before it expires, a static one
	// a few minutes (or until its version changes)
	Material material;
	material.version = d.version;
	material.valid_until = now + STATIC_MATERIAL_SECONDS;
	auto expires = Str(root, "expires_at");
	if (!expires.empty()) {
		timestamp_t parsed;
		if (Timestamp::TryConvertTimestamp(expires.c_str(), expires.size(), parsed, true) ==
		    TimestampCastResult::SUCCESS) {
			auto expires_at = Timestamp::GetEpochSeconds(parsed);
			material.valid_until = MinValue<int64_t>(material.valid_until, expires_at - DYNAMIC_MARGIN_SECONDS);
		}
	} else if (d.dynamic) {
		material.valid_until = now; // a dynamic secret without an expiry is never reused
	}
	material.secret = secret->Clone();
	materials[d.name] = std::move(material);
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
	lock_guard<mutex> guard(lock);
	if (!session) {
		return SecretMatch();
	}
	// score the usable descriptors by duckdb's own rule, on placeholders without material
	SecretMatch best;
	optional_ptr<const Descriptor> best_descriptor;
	for (auto &d : Descriptors()) {
		if (!StringUtil::CIEquals(d.type, type) || !d.May("use")) {
			continue; // a secret the caller may not use never matches: its material would be refused
		}
		auto entry =
		    EntryOf(make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(d.provider), Identifier(d.name)));
		best = SelectBestMatch(entry, path, tie_break_offset, best);
		if (best.HasMatch() && best.GetSecret().GetName() == Identifier(d.name)) {
			best_descriptor = &d; // this descriptor is the best so far (names are unique in a list)
		}
	}
	if (!best_descriptor) {
		return SecretMatch();
	}
	auto entry = EntryOf(MaterialOf(*best_descriptor, transaction));
	return SecretMatch(entry, best.score);
}

unique_ptr<SecretEntry> TresorSecretStorage::GetSecretByName(const string &name,
                                                             optional_ptr<CatalogTransaction> transaction) {
	lock_guard<mutex> guard(lock);
	if (!session) {
		return nullptr;
	}
	for (auto &d : Descriptors()) {
		if (!StringUtil::CIEquals(d.name, name)) {
			continue;
		}
		if (!d.May("use")) {
			throw InvalidInputException("tresor: you may see the secret %s of %s, but not use it", d.name,
			                            session->Info().host);
		}
		return make_uniq<SecretEntry>(EntryOf(MaterialOf(d, transaction)));
	}
	return nullptr;
}

vector<SecretEntry> TresorSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	lock_guard<mutex> guard(lock);
	vector<SecretEntry> out;
	if (!session) {
		return out;
	}
	// descriptors only: listing never fetches material
	for (auto &d : Descriptors()) {
		out.push_back(EntryOf(
		    make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(d.provider), Identifier(d.name))));
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
	auto &manager = SecretManager::Get(context);
	// the offset must be unique among the instance's storages (duckdb's tie-break rule): skip the taken ones
	for (int attempt = 0; attempt < 100; attempt++) {
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
	throw InternalException("tresor: no free secret storage offset");
}

} // namespace tresor
} // namespace duckdb
