#include "tresor_catalog.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"

#include "acl_connection.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// tresor_login (specs/025): a person's login as a query of its own, for clients that show no stderr - DuckDB UI, a
// notebook, an IDE's driver. It answers at once with what the person must see (the URL to open, the device code)
// and completes in the background; ATTACH then finds the login. Nothing it returns or logs carries a token.
//
//   FROM tresor_login('tresor:secrets.corp');                          -- a service, as ATTACH names it
//   FROM tresor_login('corp', prompt := 'select_account');             -- an attached catalog's service

namespace duckdb {
namespace {

struct LoginBindData : public TableFunctionData {
	string target;
	unordered_map<string, Value> options; // ATTACH's: login, issuer, insecure_http
	string prompt;
	bool remember = true;
};

struct LoginState : public GlobalTableFunctionState {
	bool done = false;
};

const char *const PROMPTS[] = {"login", "select_account", "consent", "none"};

unique_ptr<FunctionData> LoginBind(ClientContext &context, TableFunctionBindInput &input,
                                   vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto data = make_uniq<LoginBindData>();
	if (input.inputs.empty() || input.inputs[0].IsNull()) {
		throw InvalidInputException("tresor_login: name a service ('tresor:<host>') or an attached tresor catalog");
	}
	data->target = input.inputs[0].ToString();
	for (auto &named : input.named_parameters) {
		auto name = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor_login: %s must not be NULL", name);
		}
		if (name == "prompt") {
			data->prompt = StringUtil::Lower(named.second.ToString());
			bool known = false;
			for (auto prompt : PROMPTS) {
				known = known || data->prompt == prompt;
			}
			if (!known) {
				throw InvalidInputException("tresor_login: prompt is login, select_account, consent or none - not '%s'",
				                            named.second.ToString());
			}
		} else if (name == "remember") {
			data->remember = BooleanValue::Get(named.second);
		} else {
			data->options[name] = named.second;
		}
	}
	for (auto &column : {"service", "issuer", "client_id", "flow", "status", "url", "user_code"}) {
		names.emplace_back(column);
		return_types.push_back(LogicalType::VARCHAR);
	}
	names.emplace_back("expires_at");
	return_types.push_back(LogicalType::TIMESTAMP_TZ);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> LoginInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<LoginState>();
}

bool IsPerson(tresor::LoginFlow flow) {
	return flow == tresor::LoginFlow::BROWSER || flow == tresor::LoginFlow::DEVICE ||
	       flow == tresor::LoginFlow::REMEMBERED;
}

//! What the target names, as ATTACH would read it: a service path, or an attached catalog's service.
tresor::AttachRequest RequestFor(ClientContext &context, const LoginBindData &data) {
	auto options = data.options;
	auto target = data.target;
	if (!StringUtil::StartsWith(StringUtil::Lower(target), "tresor:")) {
		auto db = DatabaseManager::Get(context).GetDatabase(context, Identifier(target));
		if (!db || db->GetCatalog().GetCatalogType() != "tresor") {
			throw InvalidInputException("tresor_login: '%s' is neither a service ('tresor:<host>') nor an attached "
			                            "tresor catalog",
			                            target);
		}
		auto session = db->GetCatalog().Cast<tresor::TresorCatalog>().SharedSession();
		if (!IsPerson(session->Flow())) {
			throw InvalidInputException("tresor_login: %s is a service's login - it logs in from its secret", target);
		}
		auto &info = session->Info();
		target = "tresor:" + info.host;
		if (!options.count("issuer")) {
			options["issuer"] = Value(info.issuer);
		}
		if (!options.count("insecure_http")) {
			options["insecure_http"] = Value::BOOLEAN(info.insecure_http);
		}
	}
	for (auto &option : options) {
		if (option.first != "login" && option.first != "issuer" && option.first != "insecure_http") {
			throw InvalidInputException("tresor_login: unknown option %s", option.first);
		}
	}
	return tresor::ParseAttach(target, options);
}

void LoginScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<LoginState>();
	if (state.done) {
		return;
	}
	state.done = true;
	// not for a statement run for someone else: an acl session's user must not log in as the node's people
	string why;
	auto acl_state = acl::AclConnection::Reach(context, why);
	acl::AclSessionView view;
	if (!acl_state || acl_state->Current(view)) {
		throw PermissionException("tresor_login: not under a duckdb-acl session");
	}
	auto &data = input.bind_data->Cast<LoginBindData>();
	auto request = RequestFor(context, data);
	auto status = tresor::StartPersonLogin(context, request, data.prompt, data.remember);
	auto text = [](const string &value) {
		return value.empty() ? Value() : Value(value);
	};
	output.data[0].Append(Value(status.key.service));
	output.data[1].Append(Value(status.key.issuer));
	output.data[2].Append(Value(status.key.client_id));
	output.data[3].Append(text(status.flow));
	output.data[4].Append(Value(status.status));
	output.data[5].Append(text(status.url));
	output.data[6].Append(text(status.user_code));
	output.data[7].Append(status.expires_at > 0
	                          ? Value::TIMESTAMPTZ(timestamp_tz_t(Timestamp::FromEpochSeconds(status.expires_at)))
	                          : Value(LogicalType::TIMESTAMP_TZ));
}

} // namespace

void RegisterTresorLogin(ExtensionLoader &loader) {
	TableFunction function(Identifier("tresor_login"), {LogicalType::VARCHAR}, LoginScan, LoginBind, LoginInit);
	function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("login", LogicalType::VARCHAR)
		    .Add("issuer", LogicalType::VARCHAR)
		    .Add("insecure_http", LogicalType::BOOLEAN)
		    .Add("remember", LogicalType::BOOLEAN)
		    .Add("prompt", LogicalType::VARCHAR);
	});
	loader.RegisterFunction(function);
}

} // namespace duckdb
