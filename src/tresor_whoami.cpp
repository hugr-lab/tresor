#include "tresor_catalog.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "yyjson.hpp"

// corp.whoami() (specs/002): who the service thinks the caller is - one row from GET /v1/whoami, plus
// what the client knows itself (the api it talks to, the flow it logged in with).

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

struct WhoamiBindData : public TableFunctionData {
	WhoamiBindData(shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p)
	    : session(std::move(session_p)), storage(storage_p) {
	}
	shared_ptr<TresorSession> session;
	TresorSecretStorage &storage;
};

struct WhoamiState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> WhoamiBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	auto add = [&](const char *name, LogicalType type) {
		names.emplace_back(name);
		return_types.push_back(std::move(type));
	};
	add("service", LogicalType::VARCHAR);
	add("issuer", LogicalType::VARCHAR);
	add("subject", LogicalType::VARCHAR);
	add("roles", LogicalType::LIST(LogicalType::VARCHAR));
	add("actor", LogicalType::VARCHAR);
	add("expires_at", LogicalType::TIMESTAMP_TZ);
	add("can_create", LogicalType::LIST(LogicalType::VARCHAR));
	add("login", LogicalType::VARCHAR);
	return make_uniq<WhoamiBindData>(info.session, *info.storage);
}

unique_ptr<GlobalTableFunctionState> WhoamiInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<WhoamiState>();
}

Value StringOrNull(yyjson_val *obj, const char *key) {
	auto value = yyjson_obj_get(obj, key);
	return value && yyjson_is_str(value) ? Value(yyjson_get_str(value)) : Value(LogicalType::VARCHAR);
}

Value StringList(yyjson_val *value) {
	vector<Value> out;
	if (value && yyjson_is_arr(value)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(value, idx, max, item) {
			if (yyjson_is_str(item)) {
				out.emplace_back(yyjson_get_str(item));
			}
		}
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(out));
}

void WhoamiScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<WhoamiState>();
	if (state.done) {
		return;
	}
	state.done = true;
	auto &bind = data.bind_data->Cast<WhoamiBindData>();
	auto &session = *bind.session;
	// under a duckdb-acl session: the session's user, through its grant - or the reason there is none
	auto caller = bind.storage.CallerFor(&context);
	auto response = caller.Call("GET", "/v1/whoami");
	if (response.status == 401 && !caller.IsNode()) {
		bind.storage.GrantRejected(caller);
		throw PermissionException("tresor: the service no longer accepts this acl session's delegation grant");
	}
	if (response.status != 200) {
		throw InvalidInputException("tresor: whoami at %s: %s", session.Info().host,
		                            DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("tresor: whoami at %s answered no JSON object", session.Info().host);
	}

	Value expires_at(LogicalType::TIMESTAMP_TZ);
	auto expires = yyjson_obj_get(root, "expires_at");
	if (expires && yyjson_is_str(expires)) {
		timestamp_t parsed;
		if (Timestamp::TryConvertTimestamp(yyjson_get_str(expires), yyjson_get_len(expires), parsed, true) ==
		    TimestampCastResult::SUCCESS) {
			expires_at = Value::TIMESTAMPTZ(timestamp_tz_t(parsed));
		}
	}
	// permissions.create: true -> everything, false -> nothing, a list -> those name patterns
	Value can_create = Value::LIST(LogicalType::VARCHAR, vector<Value>());
	auto permissions = yyjson_obj_get(root, "permissions");
	auto create = permissions && yyjson_is_obj(permissions) ? yyjson_obj_get(permissions, "create") : nullptr;
	if (create && yyjson_is_true(create)) {
		can_create = Value::LIST(LogicalType::VARCHAR, {Value("*")});
	} else if (create && yyjson_is_arr(create)) {
		can_create = StringList(create);
	}

	output.data[0].Append(Value(session.Info().api));
	output.data[1].Append(StringOrNull(root, "issuer"));
	output.data[2].Append(StringOrNull(root, "subject"));
	output.data[3].Append(StringList(yyjson_obj_get(root, "roles")));
	output.data[4].Append(StringOrNull(root, "actor"));
	output.data[5].Append(expires_at);
	output.data[6].Append(can_create);
	output.data[7].Append(Value(LoginFlowName(session.Flow())));
}

} // namespace

TableFunction WhoamiFunction(shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	TableFunction function(Identifier("whoami"), {}, WhoamiScan, WhoamiBind, WhoamiInit);
	function.function_info = make_shared_ptr<TresorFunctionInfo>(std::move(session), &storage);
	return function;
}

} // namespace tresor
} // namespace duckdb
