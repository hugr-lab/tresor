#include "tresor_storage.hpp"
#include "tresor_login.hpp"

#include "acl_connection.hpp"

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
constexpr int64_t FRESH_MINT_SECONDS = 2;      // a mint this young satisfies a refresh (parallel 403s: one mint)

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

//! JSON text of a string.
string JsonText(const string &text) {
	string out = "\"";
	for (unsigned char c : text) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (c < 0x20) {
				out += StringUtil::Format("\\u%04x", c);
			} else {
				out.push_back(char(c));
			}
		}
	}
	return out + "\"";
}

//! A Value as the JSON the reading accepts back (FromJson): numbers as their exact text, nested types as
//! arrays and objects, everything else as its text.
string ValueJson(const Value &value) {
	if (value.IsNull()) {
		return "null";
	}
	auto &type = value.type();
	switch (type.id()) {
	case LogicalTypeId::BOOLEAN:
		return BooleanValue::Get(value) ? "true" : "false";
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::HUGEINT:
	case LogicalTypeId::UTINYINT:
	case LogicalTypeId::USMALLINT:
	case LogicalTypeId::UINTEGER:
	case LogicalTypeId::UBIGINT:
	case LogicalTypeId::UHUGEINT:
	case LogicalTypeId::DECIMAL:
		return value.ToString();
	case LogicalTypeId::FLOAT:
	case LogicalTypeId::DOUBLE: {
		auto text = value.ToString();
		// inf / nan are not JSON numbers: their text casts back
		return (text.find_first_not_of("0123456789.-+eE") == string::npos) ? text : JsonText(text);
	}
	case LogicalTypeId::LIST:
	case LogicalTypeId::ARRAY: {
		auto &children =
		    type.id() == LogicalTypeId::LIST ? ListValue::GetChildren(value) : ArrayValue::GetChildren(value);
		string out = "[";
		for (idx_t i = 0; i < children.size(); i++) {
			out += (i ? "," : "") + ValueJson(children[i]);
		}
		return out + "]";
	}
	case LogicalTypeId::STRUCT: {
		auto &children = StructValue::GetChildren(value);
		string out = "{";
		for (idx_t i = 0; i < children.size(); i++) {
			out += (i ? "," : "") + JsonText(StructType::GetChildName(type, i).GetIdentifierName()) + ":" +
			       ValueJson(children[i]);
		}
		return out + "}";
	}
	case LogicalTypeId::MAP: {
		auto &entries = ListValue::GetChildren(value);
		string out = "{";
		for (idx_t i = 0; i < entries.size(); i++) {
			auto &pair = StructValue::GetChildren(entries[i]);
			out += (i ? "," : "") + JsonText(pair[0].ToString()) + ":" + ValueJson(pair[1]);
		}
		return out + "}";
	}
	default:
		return JsonText(value.ToString());
	}
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

//! httpfs's refresh recipe: never taken from a service secret (it would refresh through the reader's own
//! provider and environment, and write back), never written to one (specs/006)
bool IsRefreshKey(const string &key) {
	return key == "refresh" || key == "refresh_info";
}

//! The secret types whose refresh httpfs drives (REFRESH auto): a dynamic service secret of these types is
//! refreshed through the tresor provider
bool RefreshableType(const string &type) {
	return type == "s3" || type == "r2" || type == "gcs" || type == "aws"; // httpfs's S3SecretConfig::SecretTypes()
}

//! The provider a descriptor's secret carries in DuckDB: tresor for a refreshable dynamic one
string ProviderOf(const Descriptor &d) {
	return d.dynamic && RefreshableType(d.type) ? string("tresor") : d.provider;
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

//! The `type` of a problem+json body, or "".
string ProblemType(const string &body) {
	JsonDoc doc(body);
	return Str(doc.Root(), "type");
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

string SecretBody(const KeyValueSecret &secret) {
	string params;
	for (auto &entry : secret.secret_map) {
		auto &value = entry.second;
		if (value.IsNull()) {
			continue; // not a value: the protocol has no NULL param (the reference server refuses one)
		}
		if (IsRefreshKey(StringUtil::Lower(entry.first.GetIdentifierName()))) {
			continue; // a refresh recipe of the writer's process means nothing in the service (specs/006)
		}
		auto key = JsonText(StringUtil::Lower(entry.first.GetIdentifierName()));
		string json;
		if (value.type().id() == LogicalTypeId::VARCHAR) {
			json = JsonText(StringValue::Get(value)); // shorthand for VARCHAR
		} else {
			json = "{\"type\":" + JsonText(value.type().ToString()) + ",\"value\":" + ValueJson(value) + "}";
		}
		params += (params.empty() ? "" : ",") + key + ":" + json;
	}
	string scope;
	for (auto &prefix : secret.GetScope()) {
		scope += (scope.empty() ? "" : ",") + JsonText(prefix);
	}
	// only keys the secret has: a DuckDB secret type may list redact keys a given secret does not carry
	// (a tresor token secret has no client_secret), and the protocol requires them to be params
	string redact;
	for (auto &key : secret.redact_keys) {
		auto param = secret.secret_map.find(key);
		if (param == secret.secret_map.end() || param->second.IsNull() ||
		    IsRefreshKey(StringUtil::Lower(key.GetIdentifierName()))) {
			continue; // only keys that are params of the body
		}
		redact += (redact.empty() ? "" : ",") + JsonText(StringUtil::Lower(key.GetIdentifierName()));
	}
	return "{\"type\":" + JsonText(StringUtil::Lower(secret.GetType().GetIdentifierName())) +
	       ",\"provider\":" + JsonText(secret.GetProvider().GetIdentifierName()) + ",\"scope\":[" + scope +
	       "],\"params\":{" + params + "},\"redact_keys\":[" + redact + "]}";
}

string JsonString(const string &text) {
	return JsonText(text);
}

string CanonicalName(const string &name) {
	return StringUtil::Lower(name);
}

string EncodePathSegment(const string &segment) {
	return Encode(segment);
}

vector<Descriptor> FetchDescriptors(const Caller &caller) {
	auto response = caller.Call("GET", "/v1/secrets"); // a refused grant throws (PermissionException)
	if (response.status != 200) {
		throw IOException("tresor: listing the secrets of %s: %s", caller.session->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	if (!root || !yyjson_is_arr(root)) {
		throw IOException("tresor: %s answered the secrets list with no JSON array", caller.session->Info().host);
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
	persistent = true; // the secrets live in the service
}

void TresorSecretStorage::Activate(shared_ptr<TresorSession> session_p, vector<Descriptor> initial,
                                   shared_ptr<TresorActor> actor_p) {
	lock_guard<mutex> guard(lock);
	session = std::move(session_p);
	actor = std::move(actor_p);
	node = make_shared_ptr<View>();
	node->descriptors = std::move(initial);
	node->listed_at = NowSeconds();
	node->listed = true;
	acl_views.clear();
}

void TresorSecretStorage::Deactivate(const TresorSession &which) {
	lock_guard<mutex> guard(lock);
	if (session.get() != &which) {
		return; // another ATTACH of this name serves now
	}
	session.reset();
	actor.reset();
	node.reset();
	acl_views.clear();
}

bool TresorSecretStorage::IncludeInLookups() {
	lock_guard<mutex> guard(lock);
	return session != nullptr;
}

Caller TresorSecretStorage::CallerFor(optional_ptr<ClientContext> context) {
	Caller caller;
	shared_ptr<TresorActor> acting;
	{
		lock_guard<mutex> guard(lock);
		caller.session = session;
		acting = actor;
	}
	if (!caller.session || !context) {
		return caller; // detached; or no connection to ask - the node's own work
	}
	// whose statement is this: duckdb-acl publishes the session a statement runs under on its connection
	string why;
	auto state = acl::AclConnection::Reach(*context, why);
	if (!state) {
		// another acl_connection contract: it cannot be told whose statement this is - nobody's
		caller.acl_session = "?";
		caller.refused = "cannot tell whose statement this is: " + why;
		return caller;
	}
	acl::AclSessionView view;
	if (!state->Current(view)) {
		return caller; // not under an acl session: the node itself
	}
	caller.acl_session = view.session_id.empty() ? "?" : view.session_id;
	if (!acting) {
		caller.refused = storage_name + " does not act for duckdb-acl sessions (ATTACH it with ACT_FOR_SESSIONS)";
		return caller;
	}
	caller.grant = acting->GrantFor(view.session_id, context, why);
	if (caller.grant.empty()) {
		caller.refused = why.empty() ? "this acl session has no delegation grant" : why;
		return caller;
	}
	// a 401 on the grant, wherever it surfaces (a lookup, a write, a management call): the session's
	// view goes, and the session gets nothing more
	auto rejected = caller;
	caller.rejected = [this, rejected]() {
		GrantRejected(rejected);
	};
	return caller;
}

Caller TresorSecretStorage::CallerOf(optional_ptr<CatalogTransaction> transaction) {
	return CallerFor(transaction ? transaction->context : nullptr);
}

void TresorSecretStorage::GrantRejected(const Caller &caller) {
	shared_ptr<TresorActor> acting;
	{
		lock_guard<mutex> guard(lock);
		acting = actor;
		acl_views.erase(caller.acl_session);
	}
	if (acting && !caller.IsNode()) {
		acting->Rejected(caller.acl_session);
	}
}

void TresorSecretStorage::ForgetSession(const string &acl_session) {
	lock_guard<mutex> guard(lock);
	acl_views.erase(acl_session);
}

shared_ptr<TresorSecretStorage::View> TresorSecretStorage::ViewOf(const Caller &caller) {
	lock_guard<mutex> guard(lock);
	if (!caller.Usable() || session != caller.session) {
		return nullptr;
	}
	if (caller.IsNode()) {
		return node;
	}
	auto existing = acl_views.find(caller.acl_session);
	if (existing != acl_views.end()) {
		return existing->second;
	}
	// a session the actor no longer serves (closed while this statement ran) gets no new view: its close
	// already dropped the old one, and a new one would keep its user's material until DETACH. Checked under
	// this lock, which the close's ForgetSession takes too - so a view made here is dropped by that close
	if (!actor || !actor->Serves(caller.acl_session)) {
		return nullptr;
	}
	auto view = make_shared_ptr<View>();
	acl_views[caller.acl_session] = view;
	return view;
}

vector<Descriptor> TresorSecretStorage::Snapshot(const Caller &caller, shared_ptr<View> &view_out) {
	view_out = ViewOf(caller);
	if (!view_out) {
		return vector<Descriptor>();
	}
	auto &view = *view_out;
	bool first;
	{
		lock_guard<mutex> guard(lock);
		auto now = NowSeconds();
		first = !view.listed;
		if (now - view.failed_at < RETRY_AFTER_SECONDS || (!first && now - view.listed_at < LIST_TTL_SECONDS)) {
			return view.descriptors;
		}
	}
	// stale: one refresh at a time, outside the state lock; a lookup arriving meanwhile goes on with the
	// list it has rather than queueing behind the network - unless the view has none yet (a new acl session)
	unique_lock<mutex> fetching(view.fetch_lock, std::defer_lock);
	if (first) {
		fetching.lock();
	} else if (!fetching.try_lock()) {
		lock_guard<mutex> guard(lock);
		return view.descriptors;
	}
	uint64_t started;
	{
		lock_guard<mutex> guard(lock);
		if (first && view.listed) {
			return view.descriptors; // listed while this one waited
		}
		started = generation;
	}
	try {
		auto fresh = FetchDescriptors(caller);
		lock_guard<mutex> guard(lock);
		if (session == caller.session && generation == started) { // a write meanwhile: this list is already old
			view.descriptors = std::move(fresh);
			view.listed_at = NowSeconds();
			view.listed = true;
		}
		return view.descriptors;
	} catch (PermissionException &) {
		if (caller.IsNode()) {
			lock_guard<mutex> guard(lock);
			view.failed_at = NowSeconds();
			return view.descriptors;
		}
		return vector<Descriptor>(); // the grant was refused (marked by the call): this session gets nothing
	} catch (std::exception &) {
		// the service is unreachable: the last list stays authoritative for matching (a secret it covers
		// fails at its material fetch - closed; a path it does not cover is not this storage's business)
		lock_guard<mutex> guard(lock);
		view.failed_at = NowSeconds();
		return view.descriptors;
	}
}

vector<Descriptor> TresorSecretStorage::Refresh(const Caller &caller) {
	if (!caller.session) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	// throws the refusal: an acl session without a grant, or one the service refused (marked by the call)
	auto fresh = FetchDescriptors(caller);
	auto view = ViewOf(caller);
	lock_guard<mutex> guard(lock);
	if (view && session == caller.session) {
		view->descriptors = fresh;
		view->listed_at = NowSeconds();
		view->failed_at = 0;
		view->listed = true;
	}
	return fresh;
}

unique_ptr<const BaseSecret> TresorSecretStorage::MaterialOf(const Caller &caller, View &view, const Descriptor &d,
                                                             optional_ptr<CatalogTransaction> transaction) {
	auto now = NowSeconds();
	{
		lock_guard<mutex> guard(lock);
		auto cached = view.materials.find(d.name);
		if (cached != view.materials.end() && cached->second.version == d.version && cached->second.valid_until > now) {
			return cached->second.secret->Clone();
		}
	}
	ServiceResponse response;
	try {
		response = caller.Call("GET", "/v1/secrets/" + Encode(d.name));
	} catch (PermissionException &) {
		if (caller.IsNode()) {
			throw;
		}
		return nullptr; // the service refused the session's grant (marked by the call): a lookup finds nothing
	}
	if (response.status == 403 && ProblemType(response.body) == "mint_refused") {
		// a token for the caller the IdP would not mint (specs/010): the lookup fails with the reason, rather
		// than going on without the credential the path needs
		throw IOException("tresor: the secret %s of %s: %s", d.name, caller.session->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	if (response.status == 404 || response.status == 403) {
		// gone, or no longer ours to use, since the list was fetched: not a match - and the list is stale
		lock_guard<mutex> guard(lock);
		view.listed_at = 0;
		return nullptr;
	}
	if (response.status != 200) {
		throw IOException("tresor: the secret %s of %s: %s", d.name, caller.session->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	// numbers as raw text: a HUGEINT or DECIMAL keeps every digit
	JsonDoc doc(response.body, YYJSON_READ_NUMBER_AS_RAW);
	auto root = doc.Root();
	auto params = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "params") : nullptr;
	if (!params || !yyjson_is_obj(params)) {
		throw IOException("tresor: the secret %s of %s came without params", d.name, caller.session->Info().host);
	}
	optional_ptr<ClientContext> context = transaction ? transaction->context : nullptr;
	// a dynamic S3-family secret is refreshed by tresor (httpfs's REFRESH auto calls the provider recorded
	// in the secret, with the options of its refresh_info); every other one keeps the service's provider
	auto refreshable = d.dynamic && RefreshableType(d.type);
	auto provider = ProviderOf(d);
	auto secret = make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(provider), Identifier(d.name));
	if (refreshable) {
		child_list_t<Value> recipe;
		recipe.emplace_back(Identifier("tresor_service"), Value(storage_name));
		recipe.emplace_back(Identifier("tresor_secret"), Value(d.name));
		secret->secret_map[Identifier("refresh_info")] = Value::STRUCT(std::move(recipe));
	}
	size_t idx, max;
	yyjson_val *key, *item;
	yyjson_obj_foreach(params, idx, max, key, item) {
		string name = yyjson_get_str(key);
		auto lowered = StringUtil::Lower(name);
		if (IsRefreshKey(lowered)) {
			continue; // a service secret is refreshed only by tresor
		}
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
	if (session != caller.session) {
		return std::move(secret); // detached meanwhile: served once, never cached
	}
	// expired entries go now: material is kept for a bounded time, not until DETACH
	for (auto it = view.materials.begin(); it != view.materials.end();) {
		it = it->second.valid_until <= now ? view.materials.erase(it) : std::next(it);
	}
	if (valid_until > now) {
		Material material;
		material.version = d.version;
		material.valid_until = valid_until;
		material.secret = secret->Clone();
		view.materials[d.name] = std::move(material);
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
	// a statement under an acl session sees its user's secrets or none - never the node's (specs/008)
	auto caller = CallerOf(transaction);
	shared_ptr<View> view;
	auto list = Snapshot(caller, view);
	if (!view) {
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
	auto material = MaterialOf(caller, *view, *best_descriptor, transaction);
	if (!material) {
		return SecretMatch();
	}
	auto entry = EntryOf(std::move(material));
	return SecretMatch(entry, best.score);
}

unique_ptr<SecretEntry> TresorSecretStorage::GetSecretByName(const string &name,
                                                             optional_ptr<CatalogTransaction> transaction) {
	auto caller = CallerOf(transaction);
	shared_ptr<View> view;
	auto list = Snapshot(caller, view);
	if (!view) {
		return nullptr;
	}
	for (auto &d : list) {
		// a secret the caller may see but not use is not one it can have by name: not found here, so a
		// local secret of that name is not shadowed by an error
		if (StringUtil::CIEquals(d.name, name) && Lookupable(d) && d.May("use")) {
			auto material = MaterialOf(caller, *view, d, transaction);
			return material ? make_uniq<SecretEntry>(EntryOf(std::move(material))) : nullptr;
		}
	}
	return nullptr;
}

vector<SecretEntry> TresorSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	auto caller = CallerOf(transaction);
	shared_ptr<View> view;
	auto list = Snapshot(caller, view); // never throws: duckdb_secrets() must work while a service is down
	vector<SecretEntry> out;
	if (!view) {
		return out;
	}
	// descriptors only: listing never fetches material
	for (auto &d : list) {
		if (Lookupable(d)) {
			out.push_back(EntryOf(
			    make_uniq<KeyValueSecret>(d.scope, Identifier(d.type), Identifier(ProviderOf(d)), Identifier(d.name))));
		}
	}
	return out;
}

shared_ptr<TresorSession> TresorSecretStorage::Current() {
	lock_guard<mutex> guard(lock);
	return session;
}

void TresorSecretStorage::Invalidate(const string &name) {
	lock_guard<mutex> guard(lock);
	generation++;
	auto stale = [&](View &view) {
		view.listed_at = 0;
		view.failed_at = 0;
		view.materials.erase(name);
	};
	if (node) {
		stale(*node);
	}
	for (auto &view : acl_views) {
		stale(*view.second);
	}
}

unique_ptr<const BaseSecret> TresorSecretStorage::RefreshMaterial(const string &name,
                                                                  optional_ptr<CatalogTransaction> transaction) {
	auto caller = CallerOf(transaction);
	shared_ptr<View> view;
	for (auto &d : Snapshot(caller, view)) {
		if (!StringUtil::CIEquals(d.name, name) || !Lookupable(d) || !d.May("use")) {
			continue;
		}
		// only a dynamic secret is refreshed: a static one's credential is fixed in the service, and
		// re-creating it would be a write (the rotation is the service's business)
		if (!d.dynamic || !RefreshableType(d.type)) {
			throw InvalidInputException("tresor: the secret %s of %s is not a dynamic %s secret - there is "
			                            "nothing to refresh",
			                            d.name, storage_name, d.type);
		}
		{
			// fresh, not cached: the credential in hand was just refused. A mint made by another refresh a
			// moment ago is the answer to this one too (requests of one scan may refresh in parallel); a
			// mint made by an ordinary lookup is not - it may be the very credential that was refused
			lock_guard<mutex> guard(lock);
			auto cached = view->materials.find(d.name);
			auto now = NowSeconds();
			if (cached != view->materials.end() && cached->second.version == d.version &&
			    cached->second.refreshed_at != 0 && now - cached->second.refreshed_at < FRESH_MINT_SECONDS &&
			    cached->second.valid_until > now) {
				return cached->second.secret->Clone();
			}
			view->materials.erase(d.name);
		}
		auto material = MaterialOf(caller, *view, d, transaction);
		if (!material) {
			break;
		}
		lock_guard<mutex> guard(lock);
		auto cached = view->materials.find(d.name);
		if (cached != view->materials.end()) {
			cached->second.refreshed_at = NowSeconds();
		}
		return material;
	}
	if (!caller.session) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	if (!caller.refused.empty()) {
		throw PermissionException("tresor: %s", caller.refused);
	}
	throw InvalidInputException("tresor: %s has no secret %s this caller may use", storage_name, name);
}

string TresorSecretStorage::ServiceName(const Caller &caller, const string &name) {
	shared_ptr<View> view;
	for (auto &d : Snapshot(caller, view)) {
		if (StringUtil::CIEquals(d.name, name)) {
			return d.name;
		}
	}
	return CanonicalName(name);
}

unique_ptr<SecretEntry> TresorSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                         OnCreateConflict on_conflict,
                                                         optional_ptr<CatalogTransaction> transaction) {
	auto caller = CallerOf(transaction);
	if (!caller.session) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	auto key_value = dynamic_cast<const KeyValueSecret *>(secret.get());
	if (!key_value) {
		throw InvalidInputException("tresor: only key-value secrets can be stored in %s", storage_name);
	}
	if (secret->GetProvider() == Identifier("tresor")) {
		// httpfs's REFRESH auto re-created a service secret through the tresor provider, which fetched it
		// from the service (and cached it): a refresh, not a write - nothing goes back
		return make_uniq<SecretEntry>(EntryOf(secret->Clone()));
	}
	auto name = ServiceName(caller, secret->GetName().GetIdentifierName());
	std::map<std::string, std::string> headers;
	if (on_conflict == OnCreateConflict::ERROR_ON_CONFLICT || on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
		headers["If-None-Match"] = "*"; // CREATE / IF NOT EXISTS: never overwrite
	} else if (on_conflict != OnCreateConflict::REPLACE_ON_CONFLICT) {
		throw InternalException("tresor: unexpected conflict mode for a secret");
	}
	auto response = caller.Call("PUT", "/v1/secrets/" + Encode(name), SecretBody(*key_value), headers);
	Invalidate(name);
	if (response.status == 412) {
		if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
			return nullptr; // duckdb's IF NOT EXISTS contract: nothing created, no entry
		}
		throw InvalidInputException("Persistent secret with name %s already exists in secret storage '%s'!", name,
		                            storage_name);
	}
	if (response.status == 403) {
		throw PermissionException("tresor: you may not %s the secret %s in %s (%s)",
		                          on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT ? "create or replace" : "create",
		                          name, storage_name, DescribeProblem(response.status, response.body));
	}
	if (response.status != 200 && response.status != 201) {
		throw InvalidInputException("tresor: storing the secret %s in %s: %s", name, storage_name,
		                            DescribeProblem(response.status, response.body));
	}
	auto entry = EntryOf(secret->Clone());
	return make_uniq<SecretEntry>(std::move(entry));
}

void TresorSecretStorage::DropSecretByName(const Identifier &name_p, OnEntryNotFound on_entry_not_found,
                                           optional_ptr<CatalogTransaction> transaction) {
	auto caller = CallerOf(transaction);
	if (!caller.session) {
		throw InvalidInputException("tresor: %s is detached", storage_name);
	}
	auto name = ServiceName(caller, name_p.GetIdentifierName());
	auto response = caller.Call("DELETE", "/v1/secrets/" + Encode(name));
	Invalidate(name);
	if (response.status == 404) {
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw InvalidInputException("Failed to remove non-existent persistent secret '%s' in secret storage '%s'",
			                            name, storage_name);
		}
		return;
	}
	if (response.status == 403) {
		throw PermissionException("tresor: you may not delete the secret %s in %s (%s)", name, storage_name,
		                          DescribeProblem(response.status, response.body));
	}
	if (response.status != 204 && response.status != 200) {
		throw InvalidInputException("tresor: deleting the secret %s in %s: %s", name, storage_name,
		                            DescribeProblem(response.status, response.body));
	}
}

optional_ptr<TresorSecretStorage> FindStorage(ClientContext &context, const string &name) {
	auto registry = ObjectCache::GetObjectCache(context).GetOrCreate<StorageRegistry>(StorageRegistry::ObjectType());
	if (!registry) {
		return nullptr;
	}
	lock_guard<mutex> guard(registry->lock);
	auto existing = registry->storages.find(StringUtil::Lower(name));
	return existing == registry->storages.end() ? nullptr : existing->second;
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
