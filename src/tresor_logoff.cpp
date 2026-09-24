#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"
#include "tresor_remember.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// tresor_logoff (specs/012): a person's remembered login forgotten - removed from the keychain, revoked at the
// identity provider when it offers RFC 7009, and ended in every attachment that runs on it. Nothing it returns
// or logs carries a token.
//
//   CALL tresor_logoff();                                   -- every person login attached here
//   CALL tresor_logoff('corp');                             -- the login of that attachment
//   CALL tresor_logoff(issuer := '...', client_id := '...'); -- one by name, attached or not

namespace duckdb {
namespace {

using tresor::LoginFlow;
using tresor::TresorCatalog;
using tresor::TresorSession;

string StripSlash(string text) {
	while (!text.empty() && text.back() == '/') {
		text.pop_back();
	}
	return text;
}

bool IsPerson(LoginFlow flow) {
	return flow == LoginFlow::BROWSER || flow == LoginFlow::DEVICE || flow == LoginFlow::REMEMBERED;
}

//! The attached tresor catalogs: name and session.
vector<std::pair<string, shared_ptr<TresorSession>>> Attached(ClientContext &context) {
	vector<std::pair<string, shared_ptr<TresorSession>>> out;
	for (auto &db : DatabaseManager::Get(context).GetDatabases(context)) {
		if (db->IsSystem() || db->IsTemporary()) {
			continue;
		}
		auto &catalog = db->GetCatalog();
		if (catalog.GetCatalogType() != "tresor") {
			continue;
		}
		out.emplace_back(db->GetName().GetIdentifierName(), catalog.Cast<TresorCatalog>().SharedSession());
	}
	return out;
}

struct LogoffBindData : public TableFunctionData {
	string catalog;
	string issuer;
	string client_id;
};

struct Row {
	string issuer;
	string client_id;
	bool removed = false;
	bool revoked = false;
};

struct LogoffState : public GlobalTableFunctionState {
	bool done = false;
	vector<Row> rows;
	idx_t offset = 0;
};

unique_ptr<FunctionData> LogoffBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto data = make_uniq<LogoffBindData>();
	if (!input.inputs.empty()) {
		if (input.inputs[0].IsNull()) {
			throw InvalidInputException("tresor_logoff: the catalog must not be NULL");
		}
		data->catalog = input.inputs[0].ToString();
	}
	for (auto &named : input.named_parameters) {
		auto key = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor_logoff: %s must not be NULL", key);
		}
		if (key == "issuer") {
			data->issuer = StripSlash(named.second.ToString());
		} else if (key == "client_id") {
			data->client_id = named.second.ToString();
		}
	}
	if (data->issuer.empty() != data->client_id.empty()) {
		throw InvalidInputException("tresor_logoff: name a login by both its issuer and its client_id");
	}
	if (!data->catalog.empty() && !data->issuer.empty()) {
		throw InvalidInputException("tresor_logoff: name a catalog or an issuer and client_id, not both");
	}
	names.emplace_back("issuer");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("client_id");
	return_types.push_back(LogicalType::VARCHAR);
	names.emplace_back("removed");
	return_types.push_back(LogicalType::BOOLEAN);
	names.emplace_back("revoked");
	return_types.push_back(LogicalType::BOOLEAN);
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> LogoffInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<LogoffState>();
}

//! One login forgotten: the keychain entry removed, the attachments on it ended, the token revoked.
Row Forget(ClientContext &context, const string &issuer, const string &client_id,
           const vector<std::pair<string, shared_ptr<TresorSession>>> &attached) {
	Row row;
	row.issuer = issuer;
	row.client_id = client_id;
	auto store = tresor::RememberedLogins::Get(*context.db);
	string refresh;
	row.removed = store->Load(issuer, client_id, refresh);
	store->Remove(issuer, client_id);
	tresor::oidc::Endpoints endpoints;
	string service;
	string host;
	string login;
	for (auto &entry : attached) {
		auto &session = *entry.second;
		auto &info = session.Info();
		if (!IsPerson(session.Flow()) || StripSlash(info.issuer) != issuer || info.client_id != client_id) {
			continue;
		}
		auto held = session.LogOff();
		row.removed = true;
		if (refresh.empty()) {
			refresh = std::move(held);
		} else {
			tresor::Wipe(held);
		}
		if (service.empty()) {
			endpoints = info.endpoints;
			service = entry.first;
			host = info.host;
			login = tresor::LoginFlowName(session.Flow());
		}
	}
	if (!refresh.empty() && endpoints.revocation_endpoint.empty() && service.empty()) {
		// not attached here: the issuer's own discovery names the endpoint - https only (or loopback, for tests
		// and local IdPs), as every other IdP call
		if (StringUtil::StartsWith(issuer, "https://") || StringUtil::StartsWith(issuer, "http://127.0.0.1") ||
		    StringUtil::StartsWith(issuer, "http://localhost")) {
			endpoints = tresor::oidc::Discover(issuer);
		}
	}
	if (!refresh.empty() && !endpoints.revocation_endpoint.empty()) {
		row.revoked = tresor::oidc::Revoke(endpoints, client_id, "", refresh).ok;
	}
	tresor::Wipe(refresh);
	// the audit (specs/011): a logout, said to be a logoff - never the token
	tresor::Audited audited(tresor::TresorAudit::Get(*context.db), "logout", &context);
	audited.event.service = service;
	audited.event.host = host;
	audited.event.login = login;
	audited.Detail(row.revoked ? "logoff_revoked" : "logoff").Ok();
	return row;
}

void LogoffScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<LogoffState>();
	if (!state.done) {
		state.done = true; // the logoff runs once per statement, whatever happens below
		auto &data = input.bind_data->Cast<LogoffBindData>();
		auto attached = Attached(context);
		vector<std::pair<string, string>> keys;
		auto add = [&](const string &issuer, const string &client_id) {
			for (auto &key : keys) {
				if (key.first == issuer && key.second == client_id) {
					return;
				}
			}
			keys.emplace_back(issuer, client_id);
		};
		if (!data.issuer.empty()) {
			add(data.issuer, data.client_id);
		} else {
			bool named_found = false;
			for (auto &entry : attached) {
				if (!data.catalog.empty() && !StringUtil::CIEquals(entry.first, data.catalog)) {
					continue;
				}
				named_found = true;
				auto &session = *entry.second;
				if (!IsPerson(session.Flow())) {
					if (!data.catalog.empty()) {
						throw InvalidInputException("tresor_logoff: %s is a service's login - nothing of it is "
						                            "remembered, DETACH ends it",
						                            data.catalog);
					}
					continue;
				}
				add(StripSlash(session.Info().issuer), session.Info().client_id);
			}
			if (!data.catalog.empty() && !named_found) {
				throw InvalidInputException("tresor_logoff: no attached tresor catalog named %s", data.catalog);
			}
		}
		for (auto &key : keys) {
			state.rows.push_back(Forget(context, key.first, key.second, attached));
		}
	}
	while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.offset++];
		output.data[0].Append(Value(row.issuer));
		output.data[1].Append(Value(row.client_id));
		output.data[2].Append(Value::BOOLEAN(row.removed));
		output.data[3].Append(Value::BOOLEAN(row.revoked));
	}
}

} // namespace

void RegisterTresorLogoff(ExtensionLoader &loader) {
	TableFunctionSet set(Identifier("tresor_logoff"));
	for (auto arguments : {vector<LogicalType>(), vector<LogicalType> {LogicalType::VARCHAR}}) {
		TableFunction function(Identifier("tresor_logoff"), arguments, LogoffScan, LogoffBind, LogoffInit);
		function.named_parameters[Identifier("issuer")] = LogicalType::VARCHAR;
		function.named_parameters[Identifier("client_id")] = LogicalType::VARCHAR;
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
