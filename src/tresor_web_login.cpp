#include "tresor_events.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"

#include "acl_connection.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// tresor_web_login (specs/020): a person's login made by a web page - with the identity provider, in the browser -
// handed to tresor in DuckDB-wasm. The page passes the refresh token as a prepared statement's parameter, so the
// token is never part of a statement's text (nor of a query log); tresor remembers it in this instance's memory, and
// the ATTACH that follows renews it as it renews any remembered login. Nothing it returns or logs carries a token.
//
//   CALL tresor_web_login($1, $2);                          -- 'tresor:secrets.corp', the refresh token
//   CALL tresor_web_login($1, $2, issuer := '...');         -- a service with several issuers, as ATTACH's ISSUER

namespace duckdb {
namespace {

struct WebLoginBindData : public TableFunctionData {
	tresor::AttachRequest request;
	string refresh_token;

	~WebLoginBindData() override {
		std::fill(refresh_token.begin(), refresh_token.end(), '\0');
	}
};

struct WebLoginState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> WebLoginBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<Identifier> &names) {
	for (auto &value : input.inputs) {
		if (value.IsNull()) {
			throw InvalidInputException("tresor_web_login: the service and the refresh token must not be NULL");
		}
	}
	// the options ATTACH would take for a person's login, with ATTACH's own rules
	unordered_map<string, Value> options;
	for (auto &named : input.named_parameters) {
		auto name = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor_web_login: %s must not be NULL", name);
		}
		options[name] = named.second;
	}
	auto data = make_uniq<WebLoginBindData>();
	data->request = tresor::ParseAttach(input.inputs[0].ToString(), options);
	data->refresh_token = input.inputs[1].ToString();
	names.emplace_back("service");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("issuer");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("client_id");
	return_types.push_back(LogicalType::VARCHAR);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> WebLoginInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<WebLoginState>();
}

void WebLoginScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<WebLoginState>();
	if (state.done) {
		return;
	}
	state.done = true;
	// not for a statement run for someone else: an acl session's user must not plant a login for the node's people
	string why;
	auto acl_state = acl::AclConnection::Reach(context, why);
	acl::AclSessionView view;
	if (!acl_state || acl_state->Current(view)) {
		throw PermissionException("tresor_web_login: not under a duckdb-acl session");
	}
	auto &data = input.bind_data->Cast<WebLoginBindData>();
	// the audit (specs/011): a login handed over - never the token
	tresor::Audited audited(tresor::TresorAudit::Get(*context.db), "login", &context);
	audited.event.host = data.request.host;
	audited.Called();
	tresor::LoginKey key;
	try {
		key = tresor::HandOverLogin(context, data.request, data.refresh_token);
	} catch (std::exception &ex) {
		audited.Failed(ex);
		throw;
	}
	audited.Detail("web_login").Ok();
	output.data[0].Append(Value(key.service));
	output.data[1].Append(Value(key.issuer));
	output.data[2].Append(Value(key.client_id));
}

} // namespace

void RegisterTresorWebLogin(ExtensionLoader &loader) {
	TableFunction function(Identifier("tresor_web_login"), {LogicalType::VARCHAR, LogicalType::VARCHAR}, WebLoginScan,
	                       WebLoginBind, WebLoginInit);
	function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("issuer", LogicalType::VARCHAR).Add("insecure_http", LogicalType::BOOLEAN);
	});
	loader.RegisterFunction(function);
}

} // namespace duckdb
