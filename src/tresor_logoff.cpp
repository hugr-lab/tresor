#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"
#include "tresor_remember.hpp"

#include "acl_connection.hpp"

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
//   CALL tresor_logoff();                         -- every remembered login attached here
//   CALL tresor_logoff('corp');                   -- the login of that attachment
//   CALL tresor_logoff(service := 'secrets.corp', issuer := '...', client_id := '...');   -- by name

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
	tresor::LoginKey key; // by name: all three
};

struct Row {
	tresor::LoginKey key;
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
		auto name = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("tresor_logoff: %s must not be NULL", name);
		}
		if (name == "issuer") {
			data->key.issuer = StripSlash(named.second.ToString());
		} else if (name == "client_id") {
			data->key.client_id = named.second.ToString();
		} else if (name == "service") {
			auto service = named.second.ToString();
			if (StringUtil::StartsWith(StringUtil::Lower(service), "tresor:")) {
				service = service.substr(7);
			}
			data->key.service = StripSlash(service);
		}
	}
	auto given = int(!data->key.issuer.empty()) + int(!data->key.client_id.empty()) + int(!data->key.service.empty());
	if (given != 0 && given != 3) {
		throw InvalidInputException("tresor_logoff: a login is named by its service, issuer and client_id - all three");
	}
	if (!data->catalog.empty() && given != 0) {
		throw InvalidInputException("tresor_logoff: name a catalog, or a service, issuer and client_id - not both");
	}
	names.emplace_back("service");
	return_types.push_back(LogicalType::VARCHAR);
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

//! An issuer tresor may ask for its discovery without an attachment: https, or http on loopback.
bool Reachable(const string &issuer) {
	if (StringUtil::StartsWith(issuer, "https://")) {
		return true;
	}
	return StringUtil::StartsWith(issuer, "http://") && tresor::IsLoopbackHost(issuer.substr(7));
}

//! One login forgotten: the attachments remembered under it ended first (so no renewal stores it back), then
//! the entry removed, then every distinct refresh token revoked.
Row Forget(ClientContext &context, const tresor::LoginKey &key,
           const vector<std::pair<string, shared_ptr<TresorSession>>> &attached) {
	Row row;
	row.key = key;
	auto store = tresor::RememberedLogins::Get(*context.db);
	vector<string> tokens;
	auto keep = [&](string &token) {
		if (token.empty()) {
			return;
		}
		for (auto &known : tokens) {
			if (known == token) {
				tresor::Wipe(token);
				return;
			}
		}
		tokens.push_back(std::move(token));
	};
	tresor::oidc::Endpoints endpoints;
	string service;
	string login;
	for (auto &entry : attached) {
		auto &session = *entry.second;
		if (!session.Remembers(key)) {
			continue; // REMEMBER false, or another service's: not this login
		}
		if (service.empty()) {
			endpoints = session.Info().endpoints;
			service = entry.first;
			login = tresor::LoginFlowName(session.Flow());
		}
		auto held = session.LogOff();
		keep(held);
		row.removed = true;
	}
	{
		// after the sessions (session lock, then key lock - their order): an ATTACH renewing this chain right now
		// finishes first, and what it stored goes too
		lock_guard<mutex> chain(store->KeyLock(key));
		auto mode = store->Mode();
		string subject;
		string stored;
		if (store->Load(key, mode, subject, stored)) {
			keep(stored);
		}
		row.removed = store->Remove(key, mode) || row.removed;
	}
	if (!tokens.empty() && endpoints.revocation_endpoint.empty() && Reachable(key.issuer)) {
		endpoints = tresor::oidc::Discover(key.issuer); // not attached here: the issuer's own discovery
		// the endpoint gets the token: https, or loopback - as every endpoint a login uses
		if (!Reachable(endpoints.revocation_endpoint)) {
			endpoints.revocation_endpoint.clear();
		}
	}
	for (auto &token : tokens) {
		if (!endpoints.revocation_endpoint.empty() && tresor::oidc::Revoke(endpoints, key.client_id, "", token).ok) {
			row.revoked = true;
		}
		tresor::Wipe(token);
	}
	if (row.removed) {
		// the audit (specs/011): a logout, said to be a logoff - never the token
		tresor::Audited audited(tresor::TresorAudit::Get(*context.db), "logout", &context);
		audited.event.service = service;
		audited.event.host = key.service;
		audited.event.login = login;
		audited.Detail(row.revoked ? "logoff_revoked" : "logoff").Ok();
	}
	return row;
}

void LogoffScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<LogoffState>();
	if (!state.done) {
		state.done = true; // the logoff runs once per statement, whatever happens below
		// not for a statement run for someone else: an acl session's user must not end the node's people's logins
		string why;
		auto acl_state = acl::AclConnection::Reach(context, why);
		acl::AclSessionView view;
		if (!acl_state || acl_state->Current(view)) {
			throw PermissionException("tresor_logoff: not under a duckdb-acl session");
		}
		auto &data = input.bind_data->Cast<LogoffBindData>();
		auto attached = Attached(context);
		vector<tresor::LoginKey> keys;
		auto add = [&](const tresor::LoginKey &key) {
			for (auto &known : keys) {
				if (known.issuer == key.issuer && known.client_id == key.client_id && known.service == key.service) {
					return;
				}
			}
			keys.push_back(key);
		};
		if (!data.key.service.empty()) {
			add(data.key);
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
				auto key = session.Key();
				if (data.catalog.empty() && !session.Remembers(key)) {
					continue; // every remembered login here: a REMEMBER false one is left alone
				}
				add(key);
			}
			if (!data.catalog.empty() && !named_found) {
				throw InvalidInputException("tresor_logoff: no attached tresor catalog named %s - a login of a "
				                            "detached one is named by service, issuer and client_id",
				                            data.catalog);
			}
		}
		for (auto &key : keys) {
			state.rows.push_back(Forget(context, key, attached));
		}
	}
	while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.offset++];
		output.data[0].Append(Value(row.key.service));
		output.data[1].Append(Value(row.key.issuer));
		output.data[2].Append(Value(row.key.client_id));
		output.data[3].Append(Value::BOOLEAN(row.removed));
		output.data[4].Append(Value::BOOLEAN(row.revoked));
	}
}

} // namespace

void RegisterTresorLogoff(ExtensionLoader &loader) {
	TableFunctionSet set(Identifier("tresor_logoff"));
	for (auto arguments : {vector<LogicalType>(), vector<LogicalType> {LogicalType::VARCHAR}}) {
		TableFunction function(Identifier("tresor_logoff"), arguments, LogoffScan, LogoffBind, LogoffInit);
		function.named_parameters[Identifier("issuer")] = LogicalType::VARCHAR;
		function.named_parameters[Identifier("client_id")] = LogicalType::VARCHAR;
		function.named_parameters[Identifier("service")] = LogicalType::VARCHAR;
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
