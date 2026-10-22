#include "tresor_events.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"
#include "tresor_page_tokens.hpp"

#include "acl_connection.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// tresor_web_token (specs/043): a web page that logged its user in hands tresor the access token it holds for the
// service's audience, and a new one each time it renews its own - no login of tresor's own, no second login for the
// user, and the page's refresh token never leaves the page. The token is a prepared statement's parameter, so it is
// never part of a statement's text (nor of a query log); it is kept in this instance's memory, and the ATTACH and
// every call of a session attached on it use the newest. Nothing it returns or logs carries a token.
//
//   FROM tresor_web_token($1, $2);                          -- 'tresor:secrets.corp', the access token
//   FROM tresor_web_token($1, $2, issuer := '...');         -- a service with several issuers, as ATTACH's ISSUER

namespace duckdb {
namespace tresor {

shared_ptr<PageTokens> PageTokens::Get(DatabaseInstance &db) {
	auto tokens = db.GetObjectCache().GetOrCreate<PageTokens>(ObjectType());
	if (!tokens) {
		throw InternalException("tresor: the page tokens' cache key is taken by another object");
	}
	return tokens;
}

string PageTokens::Key(const string &issuer, const string &service) {
	// length-prefixed: no two (issuer, service) pairs share one
	return std::to_string(issuer.size()) + ":" + issuer + StringUtil::Lower(service);
}

void PageTokens::Set(const string &issuer, const string &service, PageToken token) {
	lock_guard<mutex> guard(lock);
	auto key = Key(issuer, service);
	auto &held = tokens[key];
	std::fill(held.token.begin(), held.token.end(), '\0');
	held = std::move(token);
	service_of[key] = StringUtil::Lower(service);
}

bool PageTokens::Find(const string &issuer, const string &service, PageToken &out) {
	lock_guard<mutex> guard(lock);
	auto entry = tokens.find(Key(issuer, service));
	if (entry == tokens.end()) {
		return false;
	}
	out = entry->second;
	return true;
}

vector<string> PageTokens::Forget(const string &service) {
	lock_guard<mutex> guard(lock);
	vector<string> forgotten;
	auto wanted = StringUtil::Lower(service);
	for (auto entry = tokens.begin(); entry != tokens.end();) {
		auto &name = service_of[entry->first];
		if (!wanted.empty() && name != wanted) {
			++entry;
			continue;
		}
		forgotten.push_back(name);
		std::fill(entry->second.token.begin(), entry->second.token.end(), '\0');
		service_of.erase(entry->first);
		entry = tokens.erase(entry);
	}
	return forgotten;
}

PageTokens::~PageTokens() {
	for (auto &entry : tokens) {
		std::fill(entry.second.token.begin(), entry.second.token.end(), '\0');
	}
}

} // namespace tresor

namespace {

struct WebTokenBindData : public TableFunctionData {
	tresor::AttachRequest request;
	string access_token;

	~WebTokenBindData() override {
		std::fill(access_token.begin(), access_token.end(), '\0');
	}
};

struct WebTokenState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> WebTokenBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<Identifier> &names) {
	for (auto &value : input.inputs) {
		if (value.IsNull()) {
			throw InvalidInputException("tresor_web_token: the service and the access token must not be NULL");
		}
	}
	// the options ATTACH would take for a person's login, with ATTACH's own rules
	unordered_map<string, Value> options;
	for (auto &named : input.named_parameters) {
		auto name = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor_web_token: %s must not be NULL", name);
		}
		options[name] = named.second;
	}
	auto data = make_uniq<WebTokenBindData>();
	data->request = tresor::ParseAttach(input.inputs[0].ToString(), options);
	data->access_token = input.inputs[1].ToString();
	names.emplace_back("service");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("issuer");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("expires_at");
	return_types.push_back(LogicalType::TIMESTAMP_TZ);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> WebTokenInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<WebTokenState>();
}

void WebTokenScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<WebTokenState>();
	if (state.done) {
		return;
	}
	state.done = true;
	// not for a statement run for someone else: an acl session's user must not plant a login for the node's people
	string why;
	auto acl_state = acl::AclConnection::Reach(context, why);
	acl::AclSessionView view;
	if (!acl_state || acl_state->Current(view)) {
		throw PermissionException("tresor_web_token: not under a duckdb-acl session");
	}
	auto &data = input.bind_data->Cast<WebTokenBindData>();
	// the audit (specs/011): a login handed over - never the token
	tresor::Audited audited(tresor::TresorAudit::Get(*context.db), "login", &context);
	audited.event.host = data.request.host;
	audited.Called();
	tresor::PageTokenHandOver handed;
	try {
		handed = tresor::HandOverPageToken(context, data.request, data.access_token);
	} catch (std::exception &ex) {
		audited.Failed(ex);
		throw;
	}
	audited.Detail("web_token").Ok();
	output.data[0].Append(Value(handed.service));
	output.data[1].Append(Value(handed.issuer));
	output.data[2].Append(handed.expires_at == 0
	                          ? Value(LogicalType::TIMESTAMP_TZ)
	                          : Value::TIMESTAMPTZ(timestamp_tz_t(Timestamp::FromEpochSeconds(handed.expires_at))));
}

} // namespace

void RegisterTresorWebToken(ExtensionLoader &loader) {
	TableFunction function(Identifier("tresor_web_token"), {LogicalType::VARCHAR, LogicalType::VARCHAR}, WebTokenScan,
	                       WebTokenBind, WebTokenInit);
	function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("issuer", LogicalType::VARCHAR).Add("insecure_http", LogicalType::BOOLEAN);
	});
	loader.RegisterFunction(function);
}

} // namespace duckdb
