#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"

// Variables (specs/018): named strings a service may hold beside its secrets - an optional part of the
// protocol (capabilities.variables). corp.variable(name[, fallback]) reads one, corp.variables() lists them,
// set_variable / drop_variable write them; annotate, grants, grant and revoke are tresor_manage.cpp's. A
// value never reaches a log, an audit or an error.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

void RequireVariables(const TresorSession &session, const string &catalog) {
	auto &capabilities = session.Info().capabilities;
	auto found = capabilities.find("variables");
	if (found == capabilities.end() || !found->second) {
		throw InvalidInputException("tresor: %s's service does not hold variables (capabilities.variables)", catalog);
	}
}

namespace {

string Required(const Value &value, const char *what) {
	if (value.IsNull()) {
		throw InvalidInputException("tresor: %s must not be NULL", what);
	}
	return value.ToString();
}

//! A name the protocol lets a service refuse is never sent (specs/016).
string VariableName(const string &raw) {
	auto name = CanonicalName(raw);
	string why;
	if (!ProtocolName(name, why)) {
		throw InvalidInputException("tresor: a variable's name %s", why);
	}
	return name;
}

// --- corp.variable(name[, fallback]) ----------------------------------------------------------------------

void ReadVariable(TresorSecretStorage &storage, const shared_ptr<TresorSession> &session, DataChunk &args,
                  ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	RequireVariables(*session, storage.GetName());
	auto caller = storage.CallerFor(&context);
	auto with_fallback = args.ColumnCount() > 1;
	// a constant name (the usual call) is asked once per chunk, not once per row
	auto rows = args.AllConstant() ? 1 : args.size();
	for (idx_t row = 0; row < rows; row++) {
		auto raw = args.data[0].GetValue(row);
		if (raw.IsNull()) {
			result.SetValue(row, Value(LogicalType::VARCHAR));
			continue;
		}
		auto name = VariableName(raw.ToString());
		string value;
		if (storage.VariableOf(caller, name, value, &context)) {
			result.SetValue(row, Value(value));
		} else if (with_fallback) {
			result.SetValue(row, args.data[1].GetValue(row));
		} else {
			throw InvalidInputException("tresor: no variable %s in %s", name, session->Info().host);
		}
	}
	if (rows == 1 && args.AllConstant()) {
		result.SetVectorType(VectorType::CONSTANT_VECTOR);
	}
}

// --- corp.variables() --------------------------------------------------------------------------------------

struct VariablesBindData : public TableFunctionData {
	VariablesBindData(shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p)
	    : session(std::move(session_p)), storage(storage_p) {
	}
	shared_ptr<TresorSession> session;
	TresorSecretStorage &storage;
};

struct VariablesState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> VariablesBind(ClientContext &context, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	RequireVariables(*info.session, info.storage->GetName());
	auto add = [&](const char *name, LogicalType type) {
		names.emplace_back(name);
		return_types.push_back(std::move(type));
	};
	add("name", LogicalType::VARCHAR);
	add("comment", LogicalType::VARCHAR);
	add("sensitive", LogicalType::BOOLEAN);
	add("version", LogicalType::VARCHAR);
	add("permissions", LogicalType::LIST(LogicalType::VARCHAR));
	return make_uniq<VariablesBindData>(info.session, *info.storage);
}

unique_ptr<GlobalTableFunctionState> VariablesInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<VariablesState>();
}

Value StringOrNull(yyjson_val *obj, const char *key) {
	auto value = yyjson_obj_get(obj, key);
	return value && yyjson_is_str(value) ? Value(yyjson_get_str(value)) : Value(LogicalType::VARCHAR);
}

void VariablesScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<VariablesState>();
	if (state.done) {
		return;
	}
	state.done = true;
	auto &data = input.bind_data->Cast<VariablesBindData>();
	auto caller = data.storage.CallerFor(&context);
	if (!caller.refused.empty()) {
		throw PermissionException("tresor: %s: %s", data.storage.GetName(), caller.refused);
	}
	auto response = caller.Call("GET", "/v1/variables");
	if (response.status != 200) {
		throw IOException("tresor: the variables of %s: %s", data.session->Info().host,
		                  DescribeProblem(response.status, response.body));
	}
	JsonDoc doc(response.body);
	auto root = doc.Root();
	if (!root || !yyjson_is_arr(root)) {
		throw IOException("tresor: %s did not answer with a list of variables", data.session->Info().host);
	}
	size_t idx, max;
	yyjson_val *item;
	yyjson_arr_foreach(root, idx, max, item) {
		if (output.size() >= STANDARD_VECTOR_SIZE) {
			break; // a service of more variables than a chunk: the first chunk's worth (as secrets() lists)
		}
		vector<Value> permissions;
		auto verbs = yyjson_obj_get(item, "permissions");
		if (verbs && yyjson_is_arr(verbs)) {
			size_t vi, vmax;
			yyjson_val *verb;
			yyjson_arr_foreach(verbs, vi, vmax, verb) {
				if (yyjson_is_str(verb)) {
					permissions.emplace_back(yyjson_get_str(verb));
				}
			}
		}
		auto sensitive = yyjson_obj_get(item, "sensitive");
		output.data[0].Append(StringOrNull(item, "name"));
		output.data[1].Append(StringOrNull(item, "comment"));
		output.data[2].Append(Value::BOOLEAN(sensitive && yyjson_is_true(sensitive)));
		output.data[3].Append(StringOrNull(item, "version"));
		output.data[4].Append(Value::LIST(LogicalType::VARCHAR, std::move(permissions)));
	}
}

// --- set_variable / drop_variable --------------------------------------------------------------------------

enum class Write : uint8_t { SET, DROP };

struct WriteBindData : public TableFunctionData {
	WriteBindData(Write write_p, shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p)
	    : write(write_p), session(std::move(session_p)), storage(storage_p) {
	}
	Write write;
	shared_ptr<TresorSession> session;
	TresorSecretStorage &storage;
	string name;
	string value;
	string comment;
	bool has_comment = false;
	bool conditional = false; // set: if_not_exists; drop: if_exists
};

template <Write WRITE>
unique_ptr<FunctionData> WriteBind(ClientContext &context, TableFunctionBindInput &input,
                                   vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<TresorFunctionInfo>();
	RequireVariables(*info.session, info.storage->GetName());
	auto data = make_uniq<WriteBindData>(WRITE, info.session, *info.storage);
	data->name = VariableName(Required(input.inputs[0], "the variable's name"));
	if (WRITE == Write::SET) {
		data->value = Required(input.inputs[1], "the value");
	}
	for (auto &named : input.named_parameters) {
		auto option = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor: %s must not be NULL", option);
		}
		if (option == "comment") {
			data->comment = named.second.ToString();
			data->has_comment = true;
		} else if (option == "if_not_exists" || option == "if_exists") {
			data->conditional = BooleanValue::Get(named.second.DefaultCastAs(LogicalType::BOOLEAN));
		}
	}
	names.emplace_back("name");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back(WRITE == Write::SET ? "version" : "dropped");
	return_types.push_back(WRITE == Write::SET ? LogicalType::VARCHAR : LogicalType::BOOLEAN);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> WriteInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<VariablesState>();
}

void WriteScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<VariablesState>();
	if (state.done) {
		return;
	}
	state.done = true; // once per statement, whatever happens below
	auto &data = input.bind_data->Cast<WriteBindData>();
	auto &storage = data.storage;
	auto caller = storage.CallerFor(&context);
	if (!caller.refused.empty()) {
		throw PermissionException("tresor: %s: %s", storage.GetName(), caller.refused);
	}
	auto &host = data.session->Info().host;
	auto path = "/v1/variables/" + EncodePathSegment(data.name);
	auto audited = storage.Audit(data.write == Write::SET ? "write" : "drop", caller, &context);
	audited.Secret(data.name, "variable").Called();
	ServiceResponse response;
	try {
		if (data.write == Write::SET) {
			string body = "{\"value\":" + JsonString(data.value);
			if (data.has_comment) {
				body += ",\"comment\":" + JsonString(data.comment);
			}
			body += "}";
			std::map<std::string, std::string> headers;
			if (data.conditional) {
				headers["If-None-Match"] = "*"; // if_not_exists: never overwrite
			}
			response = caller.Call("PUT", path, body, headers);
		} else {
			response = caller.Call("DELETE", path);
		}
	} catch (std::exception &ex) {
		audited.Failed(ex);
		throw;
	}
	storage.InvalidateVariable(data.name);
	if (data.write == Write::SET) {
		if (response.status == 412 && data.conditional) {
			audited.None(); // it exists, and if_not_exists leaves it
			output.data[0].Append(Value(data.name));
			output.data[1].Append(Value(LogicalType::VARCHAR));
			return;
		}
		if (response.status != 200 && response.status != 201) {
			audited.Answer(response);
			if (response.status == 403) {
				throw PermissionException("tresor: you may not set the variable %s in %s (%s)", data.name, host,
				                          DescribeProblem(response.status, response.body));
			}
			throw InvalidInputException("tresor: set the variable %s in %s: %s", data.name, host,
			                            DescribeProblem(response.status, response.body));
		}
		JsonDoc doc(response.body);
		auto version = yyjson_obj_get(doc.Root(), "version");
		audited.Ok();
		output.data[0].Append(Value(data.name));
		output.data[1].Append(version && yyjson_is_str(version) ? Value(yyjson_get_str(version))
		                                                        : Value(LogicalType::VARCHAR));
		return;
	}
	if (response.status == 404 && data.conditional) {
		audited.None(); // if_exists: nothing to drop
		output.data[0].Append(Value(data.name));
		output.data[1].Append(Value::BOOLEAN(false));
		return;
	}
	if (response.status != 204 && response.status != 200) {
		audited.Answer(response);
		if (response.status == 404) {
			throw InvalidInputException("tresor: no variable %s in %s", data.name, host);
		}
		if (response.status == 403) {
			throw PermissionException("tresor: you may not drop the variable %s in %s (%s)", data.name, host,
			                          DescribeProblem(response.status, response.body));
		}
		throw InvalidInputException("tresor: drop the variable %s in %s: %s", data.name, host,
		                            DescribeProblem(response.status, response.body));
	}
	audited.Ok();
	output.data[0].Append(Value(data.name));
	output.data[1].Append(Value::BOOLEAN(true));
}

TableFunction WriteFunction(const char *name, vector<LogicalType> arguments, table_function_bind_t bind,
                            const char *option, shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	TableFunction function(Identifier(name), std::move(arguments), WriteScan, bind, WriteInit);
	function.GetSignature().WithTypedKwargs("options", [&](TypedKwargs &options) {
		if (string(name) == "set_variable") {
			options.Add("comment", LogicalType::VARCHAR);
		}
		options.Add(option, LogicalType::BOOLEAN);
	});
	function.function_info = make_shared_ptr<TresorFunctionInfo>(std::move(session), &storage);
	return function;
}

} // namespace

ScalarFunctionSet VariableFunction(shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	ScalarFunctionSet set(Identifier("variable"));
	auto read = [session, &storage](DataChunk &args, ExpressionState &state, Vector &result) {
		ReadVariable(storage, session, args, state, result);
	};
	ScalarFunction plain(Identifier("variable"), {FunctionParameter(Identifier("name"), LogicalType::VARCHAR)},
	                     LogicalType::VARCHAR, read);
	ScalarFunction with_fallback(Identifier("variable"),
	                             {FunctionParameter(Identifier("name"), LogicalType::VARCHAR),
	                              FunctionParameter(Identifier("fallback"), LogicalType::VARCHAR)},
	                             LogicalType::VARCHAR, read);
	for (auto *function : {&plain, &with_fallback}) {
		// the service is asked at execution, never folded into a plan (a prepared statement reads it anew)
		function->SetStability(FunctionStability::CONSISTENT_WITHIN_QUERY);
		function->SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING); // a NULL fallback is a value
		function->SetFallible();                                           // a refusal, a failure: it throws
		set.AddFunction(*function);
	}
	return set;
}

vector<TableFunction> VariableTableFunctions(shared_ptr<TresorSession> session, TresorSecretStorage &storage) {
	TableFunction variables(Identifier("variables"), {}, VariablesScan, VariablesBind, VariablesInit);
	variables.function_info = make_shared_ptr<TresorFunctionInfo>(session, &storage);
	auto text = LogicalType::VARCHAR;
	return {
	    variables,
	    WriteFunction("set_variable", {text, text}, WriteBind<Write::SET>, "if_not_exists", session, storage),
	    WriteFunction("drop_variable", {text}, WriteBind<Write::DROP>, "if_exists", session, storage),
	};
}

} // namespace tresor
} // namespace duckdb
