#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"

// The service's management surface as table functions of the catalog (specs/005, 009): annotate_secret,
// grants, grant_secret, revoke_secret - an administrator's (the service refuses anyone else) - and the same for
// variables (specs/018): annotate_variable, variable_grants, grant_variable, revoke_variable. Each call runs
// once, when its table function is scanned; the service decides whether it is allowed.

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
	bool variable = false; // a variable's (specs/018), else a secret's
	shared_ptr<TresorSession> session;
	reference<TresorSecretStorage> storage; // owned by the SecretManager, for the instance's lifetime
	Caller caller;                          // resolved per call: the node, or a duckdb-acl session's user
	string name;                            // the secret or the variable, canonical
	string argument;                        // the comment, or the principal
	vector<string> verbs;
	//! The change being made (per call), told of the service's refusal; mutable: told from const paths.
	mutable optional_ptr<Audited> audited;
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
	if (data.audited) {
		data.audited->Answer(response);
	}
	auto &host = data.session->Info().host;
	auto what = data.variable ? "variable" : "secret";
	if (response.status == 404) {
		throw InvalidInputException("tresor: no %s %s in %s", what, data.name, host);
	}
	if (response.status == 403) {
		throw PermissionException("tresor: you may not %s the %s %s in %s (%s)", doing, what, data.name, host,
		                          DescribeProblem(response.status, response.body));
	}
	throw InvalidInputException("tresor: %s the %s %s in %s: %s", doing, what, data.name, host,
	                            DescribeProblem(response.status, response.body));
}

string BasePath(const ManageBindData &data) {
	return data.variable ? "/v1/variables/" : "/v1/secrets/";
}

vector<Grant> ReadGrants(const ManageBindData &data) {
	auto response = data.caller.Call("GET", BasePath(data) + EncodePathSegment(data.name) + "/grants");
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

template <Action ACTION, bool VARIABLE>
unique_ptr<FunctionData> ManageBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	auto data = make_uniq<ManageBindData>(ACTION, info.session, *info.storage);
	data->variable = VARIABLE;
	if (VARIABLE) {
		RequireVariables(*info.session, info.storage->GetName());
	}
	// a secret's name is a DuckDB identifier (canonical: lower case); a variable's a string, sent as given
	auto name = Arg(input, 0, VARIABLE ? "the variable's name" : "the secret's name");
	data->name = VARIABLE ? name : CanonicalName(name);
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
		// a grant gives use to a role or a group (specs/009): refused here, before any request
		if (!(StringUtil::StartsWith(data->argument, "role:") && data->argument.size() > 5) &&
		    !(StringUtil::StartsWith(data->argument, "group:") && data->argument.size() > 6)) {
			throw InvalidInputException("tresor: a grant names a role: or a group: principal, not '%s'",
			                            data->argument);
		}
		if (input.inputs[2].IsNull()) {
			throw InvalidInputException("tresor: the verbs must not be NULL - %s takes all away",
			                            VARIABLE ? "revoke_variable" : "revoke_secret");
		}
		for (auto &verb : ListValue::GetChildren(input.inputs[2])) {
			if (verb.IsNull()) {
				throw InvalidInputException("tresor: a verb must not be NULL");
			}
			data->verbs.push_back(verb.ToString());
		}
		if (data->verbs.size() != 1 || data->verbs[0] != "use") {
			throw InvalidInputException("tresor: a grant gives use, and only use - ['use'] (%s takes it away)",
			                            VARIABLE ? "revoke_variable" : "revoke_secret");
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

void Change(ManageBindData &data, ManageState &state, TresorSecretStorage &storage, const string &path,
            DataChunk &output);

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
	data.caller = storage.CallerFor(&context);
	if (!data.variable) {
		data.name = storage.ServiceName(data.caller, data.name);
	}
	auto path = BasePath(data) + EncodePathSegment(data.name);
	if (data.action == Action::GRANTS) {
		// reading the grants changes nothing: not audited
		state.rows = ReadGrants(data);
		while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
			EmitGrant(output, 0, state.rows[state.offset++]);
		}
		return;
	}
	auto kind = data.action == Action::ANNOTATE ? "annotate" : data.action == Action::GRANT ? "grant" : "revoke";
	auto audited = storage.Audit(kind, data.caller, &context);
	audited.Secret(data.name, data.variable ? "variable" : "").Called();
	if (data.action != Action::ANNOTATE) {
		audited.Target(data.argument);
	}
	data.audited = &audited; // data is this call's own copy: the pointer never outlives `audited`
	try {
		Change(data, state, storage, path, output);
	} catch (std::exception &ex) {
		data.audited = nullptr;
		audited.Failed(ex);
		throw;
	}
	data.audited = nullptr;
	audited.Ok();
}

//! After a change: the cached lists (a secret) or values (a variable) are stale.
void Forget(const ManageBindData &data, TresorSecretStorage &storage) {
	if (data.variable) {
		storage.InvalidateVariable(data.name);
	} else {
		storage.Invalidate(data.name);
	}
}

//! annotate_secret, grant_secret, revoke_secret (and the variables'): the change, made; a refusal throws.
void Change(ManageBindData &data, ManageState &state, TresorSecretStorage &storage, const string &path,
            DataChunk &output) {
	switch (data.action) {
	case Action::ANNOTATE: {
		auto response = data.caller.Call("PATCH", path, "{\"comment\":" + JsonString(data.argument) + "}");
		if (response.status != 200) {
			Refused(data, response, "annotate");
		}
		Forget(data, storage);
		JsonDoc doc(response.body);
		auto version = yyjson_obj_get(doc.Root(), "version");
		output.data[0].Append(Value(data.name));
		output.data[1].Append(Value(data.argument));
		output.data[2].Append(version && yyjson_is_str(version) ? Value(yyjson_get_str(version))
		                                                        : Value(LogicalType::VARCHAR));
		return;
	}
	case Action::GRANTS:
		return; // read in ManageScan
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
		auto response = data.caller.Call("PUT", path + "/grants/" + EncodePathSegment(id),
		                                 "{\"principal\":" + JsonString(data.argument) + ",\"verbs\":[" + verbs + "]}");
		if (response.status != 200 && response.status != 201) {
			Refused(data, response, "grant on");
		}
		for (auto &grant : existing) {
			if (grant.principal == data.argument && grant.id != id) {
				auto removed = data.caller.Call("DELETE", path + "/grants/" + EncodePathSegment(grant.id));
				if (removed.status != 204 && removed.status != 200 && removed.status != 404) {
					Refused(data, removed, "replace a grant on");
				}
			}
		}
		Forget(data, storage); // the caller's own verbs may have changed
		EmitGrant(output, 0, Grant {id, data.argument, data.verbs});
		return;
	}
	case Action::REVOKE: {
		for (auto &grant : ReadGrants(data)) {
			if (grant.principal != data.argument) {
				continue;
			}
			auto response = data.caller.Call("DELETE", path + "/grants/" + EncodePathSegment(grant.id));
			if (response.status != 204 && response.status != 200 && response.status != 404) {
				Refused(data, response, "revoke on");
			}
			EmitGrant(output, 0, grant);
		}
		Forget(data, storage);
		if (output.size() == 0) {
			throw InvalidInputException("tresor: %s holds no grant on the %s %s", data.argument,
			                            data.variable ? "variable" : "secret", data.name);
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
	    Manage("annotate_secret", {text, text}, ManageBind<Action::ANNOTATE, false>, session, storage),
	    Manage("grants", {text}, ManageBind<Action::GRANTS, false>, session, storage),
	    Manage("grant_secret", {text, text, LogicalType::LIST(text)}, ManageBind<Action::GRANT, false>, session,
	           storage),
	    Manage("revoke_secret", {text, text}, ManageBind<Action::REVOKE, false>, session, storage),
	    // specs/018: the same for variables, where the service holds them
	    Manage("annotate_variable", {text, text}, ManageBind<Action::ANNOTATE, true>, session, storage),
	    Manage("variable_grants", {text}, ManageBind<Action::GRANTS, true>, session, storage),
	    Manage("grant_variable", {text, text, LogicalType::LIST(text)}, ManageBind<Action::GRANT, true>, session,
	           storage),
	    Manage("revoke_variable", {text, text}, ManageBind<Action::REVOKE, true>, session, storage),
	};
}

} // namespace tresor
} // namespace duckdb
