#include "tresor_catalog.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"

// The service's management surface as table functions of the catalog (specs/005): annotate_secret,
// grants, grant_secret, revoke_secret. Each call runs once, when its table function is scanned; the
// service decides whether it is allowed.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

enum class Action : uint8_t { ANNOTATE, GRANTS, GRANT, REVOKE };

struct ManageBindData : public TableFunctionData {
	ManageBindData(Action action_p, shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p)
	    : action(action_p), session(std::move(session_p)), storage(storage_p) {
	}
	Action action;
	shared_ptr<TresorSession> session;
	reference<TresorSecretStorage> storage; // owned by the SecretManager, for the instance's lifetime
	string name;                            // the secret, canonical
	string argument;                        // the comment, or the principal
	vector<string> verbs;
};

struct Grant {
	string id;
	string principal;
	vector<string> verbs;
};

struct ManageState : public GlobalTableFunctionState {
	bool done = false;
	vector<Grant> rows; // grants(): emitted a chunk at a time
	idx_t offset = 0;
};

string Arg(TableFunctionBindInput &input, idx_t index, const char *what) {
	auto &value = input.inputs[index];
	if (value.IsNull()) {
		throw InvalidInputException("tresor: %s must not be NULL", what);
	}
	return value.ToString();
}

//! A service answer that is not a success, as the user reads it.
[[noreturn]] void Refused(const ManageBindData &data, const ServiceResponse &response, const char *doing) {
	auto &host = data.session->Info().host;
	if (response.status == 404) {
		throw InvalidInputException("tresor: no secret %s in %s", data.name, host);
	}
	if (response.status == 403) {
		throw PermissionException("tresor: you may not %s the secret %s in %s (%s)", doing, data.name, host,
		                          DescribeProblem(response.status, response.body));
	}
	throw InvalidInputException("tresor: %s the secret %s in %s: %s", doing, data.name, host,
	                            DescribeProblem(response.status, response.body));
}

vector<Grant> ReadGrants(const ManageBindData &data) {
	auto response = data.session->Call("GET", "/v1/secrets/" + EncodePathSegment(data.name) + "/grants");
	if (response.status != 200) {
		Refused(data, response, "list the grants of");
	}
	JsonDoc doc(response.body);
	vector<Grant> out;
	auto root = doc.Root();
	if (root && yyjson_is_arr(root)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(root, idx, max, item) {
			Grant grant;
			auto id = yyjson_obj_get(item, "id");
			auto principal = yyjson_obj_get(item, "principal");
			grant.id = id && yyjson_is_str(id) ? yyjson_get_str(id) : "";
			grant.principal = principal && yyjson_is_str(principal) ? yyjson_get_str(principal) : "";
			auto verbs = yyjson_obj_get(item, "verbs");
			if (verbs && yyjson_is_arr(verbs)) {
				size_t vi, vmax;
				yyjson_val *verb;
				yyjson_arr_foreach(verbs, vi, vmax, verb) {
					if (yyjson_is_str(verb)) {
						grant.verbs.emplace_back(yyjson_get_str(verb));
					}
				}
			}
			out.push_back(std::move(grant));
		}
	}
	return out;
}

Value Verbs(const vector<string> &verbs) {
	vector<Value> values;
	for (auto &verb : verbs) {
		values.emplace_back(verb);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

//! A grant id every client computes the same way, from the principal: FNV-1a 64 - self-contained, so no
//! DuckDB version or build flag changes it.
string GrantId(const string &principal) {
	uint64_t hash = 14695981039346656037ULL;
	for (unsigned char c : principal) {
		hash ^= c;
		hash *= 1099511628211ULL;
	}
	return StringUtil::Format("g-%016llx", (unsigned long long)hash);
}

template <Action ACTION>
unique_ptr<FunctionData> ManageBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	auto data = make_uniq<ManageBindData>(ACTION, info.session, *info.storage);
	data->name = CanonicalName(Arg(input, 0, "the secret's name"));
	auto add = [&](const char *name, LogicalType type) {
		names.emplace_back(name);
		return_types.push_back(std::move(type));
	};
	switch (ACTION) {
	case Action::ANNOTATE:
		data->argument = Arg(input, 1, "the comment");
		add("name", LogicalType::VARCHAR);
		add("comment", LogicalType::VARCHAR);
		add("version", LogicalType::VARCHAR);
		break;
	case Action::GRANT:
		data->argument = Arg(input, 1, "the principal");
		if (input.inputs[2].IsNull()) {
			throw InvalidInputException("tresor: the verbs must not be NULL - revoke_secret takes all away");
		}
		for (auto &verb : ListValue::GetChildren(input.inputs[2])) {
			if (verb.IsNull()) {
				throw InvalidInputException("tresor: a verb must not be NULL");
			}
			data->verbs.push_back(verb.ToString());
		}
		if (data->verbs.empty()) {
			throw InvalidInputException("tresor: grant_secret needs at least one verb - revoke_secret takes all away");
		}
		DUCKDB_EXPLICIT_FALLTHROUGH;
	case Action::GRANTS:
	case Action::REVOKE:
		if (ACTION == Action::REVOKE) {
			data->argument = Arg(input, 1, "the principal");
		}
		add("id", LogicalType::VARCHAR);
		add("principal", LogicalType::VARCHAR);
		add("verbs", LogicalType::LIST(LogicalType::VARCHAR));
		break;
	}
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> ManageInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<ManageState>();
}

void EmitGrant(DataChunk &output, idx_t row, const Grant &grant) {
	output.data[0].Append(Value(grant.id));
	output.data[1].Append(Value(grant.principal));
	output.data[2].Append(Verbs(grant.verbs));
}

void ManageScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<ManageState>();
	if (state.done) {
		// grants(): the rest of the rows, a chunk at a time
		while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
			EmitGrant(output, 0, state.rows[state.offset++]);
		}
		return;
	}
	state.done = true;                                   // the call runs once per statement, whatever happens below
	auto data = input.bind_data->Cast<ManageBindData>(); // a copy: the name is resolved per call
	auto &storage = data.storage.get();
	// the service's own spelling: DuckDB compares names case-insensitively, the service exactly
	data.name = storage.ServiceName(data.name);
	auto path = "/v1/secrets/" + EncodePathSegment(data.name);
	switch (data.action) {
	case Action::ANNOTATE: {
		auto response = data.session->Call("PATCH", path, "{\"comment\":" + JsonString(data.argument) + "}");
		if (response.status != 200) {
			Refused(data, response, "annotate");
		}
		storage.Invalidate(data.name);
		JsonDoc doc(response.body);
		auto version = yyjson_obj_get(doc.Root(), "version");
		output.data[0].Append(Value(data.name));
		output.data[1].Append(Value(data.argument));
		output.data[2].Append(version && yyjson_is_str(version) ? Value(yyjson_get_str(version))
		                                                        : Value(LogicalType::VARCHAR));
		return;
	}
	case Action::GRANTS: {
		state.rows = ReadGrants(data);
		while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
			EmitGrant(output, 0, state.rows[state.offset++]);
		}
		return;
	}
	case Action::GRANT: {
		// one grant per principal: an existing grant to it is replaced under its id and any others to it
		// removed, so the principal ends up holding exactly these verbs; a new one gets a stable id
		auto existing = ReadGrants(data);
		string id = GrantId(data.argument);
		for (auto &grant : existing) {
			if (grant.principal == data.argument) {
				id = grant.id;
				break;
			}
		}
		string verbs;
		for (auto &verb : data.verbs) {
			verbs += (verbs.empty() ? "" : ",") + JsonString(verb);
		}
		auto response =
		    data.session->Call("PUT", path + "/grants/" + EncodePathSegment(id),
		                       "{\"principal\":" + JsonString(data.argument) + ",\"verbs\":[" + verbs + "]}");
		if (response.status != 200 && response.status != 201) {
			Refused(data, response, "grant on");
		}
		for (auto &grant : existing) {
			if (grant.principal == data.argument && grant.id != id) {
				auto removed = data.session->Call("DELETE", path + "/grants/" + EncodePathSegment(grant.id));
				if (removed.status != 204 && removed.status != 200 && removed.status != 404) {
					Refused(data, removed, "replace a grant on");
				}
			}
		}
		storage.Invalidate(data.name); // the caller's own verbs may have changed
		EmitGrant(output, 0, Grant {id, data.argument, data.verbs});
		return;
	}
	case Action::REVOKE: {
		for (auto &grant : ReadGrants(data)) {
			if (grant.principal != data.argument) {
				continue;
			}
			auto response = data.session->Call("DELETE", path + "/grants/" + EncodePathSegment(grant.id));
			if (response.status != 204 && response.status != 200 && response.status != 404) {
				Refused(data, response, "revoke on");
			}
			EmitGrant(output, 0, grant);
		}
		storage.Invalidate(data.name);
		if (output.size() == 0) {
			throw InvalidInputException("tresor: %s holds no grant on the secret %s", data.argument, data.name);
		}
		return;
	}
	}
}

TableFunction Manage(const char *name, vector<LogicalType> arguments, table_function_bind_t bind,
                     shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	TableFunction function(Identifier(name), std::move(arguments), ManageScan, bind, ManageInit);
	function.function_info = make_shared_ptr<TresorFunctionInfo>(std::move(session), &storage);
	return function;
}

} // namespace

vector<TableFunction> ManagementFunctions(shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	auto text = LogicalType::VARCHAR;
	return {
	    Manage("annotate_secret", {text, text}, ManageBind<Action::ANNOTATE>, session, storage),
	    Manage("grants", {text}, ManageBind<Action::GRANTS>, session, storage),
	    Manage("grant_secret", {text, text, LogicalType::LIST(text)}, ManageBind<Action::GRANT>, session, storage),
	    Manage("revoke_secret", {text, text}, ManageBind<Action::REVOKE>, session, storage),
	};
}

} // namespace tresor
} // namespace duckdb
