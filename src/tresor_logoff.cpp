#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_extension.hpp"
#include "tresor_login.hpp"
#include "tresor_http.hpp"
#include "tresor_page_tokens.hpp"
#include "tresor_pending.hpp"
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

#include <map>

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

bool SameKey(const tresor::LoginKey &a, const tresor::LoginKey &b) {
	return a.issuer == b.issuer && a.client_id == b.client_id && a.service == b.service;
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
	bool detach = true;   // specs/025: the catalogs on the login go; false keeps them waiting for a new login
};

struct Row {
	tresor::LoginKey key;
	bool removed = false;
	bool revoked = false;
	vector<string> catalogs; // attached on this login
	int64_t detached = 0;
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
		if (name == "detach") {
			data->detach = BooleanValue::Get(named.second);
			continue;
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
	names.emplace_back("detached");
	return_types.push_back(LogicalType::BIGINT);
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
	vector<shared_ptr<TresorSession>> ended; // logged off here
	tresor::oidc::Endpoints endpoints;
	string service;
	string login;
	for (auto &entry : attached) {
		auto &session = *entry.second;
		if (!session.Remembers(key)) {
			if (IsPerson(session.Flow()) && session.LoggedOff() && SameKey(session.Key(), key)) {
				row.catalogs.push_back(entry.first); // kept over an earlier logoff, still logged off: detached too
			}
			continue; // REMEMBER false, or another service's: not this login
		}
		if (service.empty()) {
			endpoints = session.Info().endpoints;
			service = entry.first;
			login = session.LoginName();
		}
		auto held = session.LogOff();
		ended.push_back(entry.second);
		keep(held);
		row.removed = true;
		row.catalogs.push_back(entry.first);
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
	// gone from the store: a kept catalog may take up the next login from now on, never this one (specs/025)
	for (auto &session : ended) {
		session->AllowResume();
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
		// a revocation, on the setting's client; a client that cannot be had costs the revocation, never the removal
		tresor::oidc::Transport transport;
		try {
			transport = tresor::TransportFor(context);
		} catch (std::exception &ex) {
			auto why = string(ex.what());
			transport = [why](const std::string &, const std::string &, const std::map<std::string, std::string> &,
			                  const std::string &, const std::string &, int) {
				tresor::oidc::HttpResult unusable;
				unusable.error = why;
				return unusable;
			};
		}
		// and the built-in client's CA bundle (specs/030): DuckDB's ca_cert_file as it is now
		tresor::HttpScope http(tresor::HttpClient {transport, tresor::CaBundleFor(context)});
		auto &data = input.bind_data->Cast<LogoffBindData>();
		auto attached = Attached(context);
		// a page's logins named by catalog (specs/043): (service, issuer)
		vector<std::pair<string, string>> page_logins;
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
				if (session.Flow() == LoginFlow::PAGE) {
					if (!data.catalog.empty()) {
						page_logins.emplace_back(StringUtil::Lower(session.Info().host), session.Key().issuer);
					}
					continue; // every page login is forgotten below
				}
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
		auto pending = tresor::PendingLogins::Get(*context.db);
		for (auto &key : keys) {
			// a login tresor_login started for it ends too (specs/025) - first: once failed, what its thread receives
			// is discarded, so nothing reaches the store after the removal below
			pending->Cancel(key, "logged off");
			state.rows.push_back(Forget(context, key, attached));
		}
		if (data.key.service.empty()) {
			// the page's logins (specs/043): their tokens forgotten, and every catalog on one logged off at once - its
			// caches emptied, as a person's logoff does - until the page hands over a token again. Nothing to revoke:
			// the refresh chain is the page's.
			auto page = tresor::PageTokens::Get(*context.db);
			std::map<std::pair<string, string>, bool> logins; // (service, issuer) -> a token forgotten now
			if (data.catalog.empty()) {
				for (auto &forgotten : page->Forget(string(), string())) {
					logins[forgotten] = true;
				}
			}
			for (auto &named : page_logins) {
				auto forgotten = !page->Forget(named.first, named.second).empty();
				logins[named] = logins[named] || forgotten;
			}
			for (auto &login : logins) {
				Row row;
				row.key.service = login.first.first;
				row.key.issuer = login.first.second;
				row.removed = login.second;
				for (auto &entry : attached) {
					auto &session = *entry.second;
					if (session.Flow() == LoginFlow::PAGE &&
					    StringUtil::Lower(session.Info().host) == row.key.service &&
					    session.Key().issuer == row.key.issuer) {
						session.LogOff();
						row.catalogs.push_back(entry.first);
					}
				}
				if (row.removed) {
					tresor::Audited audited(tresor::TresorAudit::Get(*context.db), "logout", &context);
					audited.event.host = row.key.service;
					audited.event.login = "page";
					audited.Detail("logoff").Ok();
				}
				state.rows.push_back(std::move(row));
			}
		}
		if (data.detach) {
			// the catalogs on a login that is over go (specs/025); one DuckDB will not detach in this statement (the
			// connection's default database, after USE) stays, as with detach := false, and asks for a new login
			auto &manager = DatabaseManager::Get(context);
			for (auto &row : state.rows) {
				for (auto &name : row.catalogs) {
					try {
						manager.DetachDatabase(context, Identifier(name), OnEntryNotFound::RETURN_NULL);
						row.detached++;
					} catch (std::exception &) {
					}
				}
			}
		}
	}
	while (state.offset < state.rows.size() && output.size() < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.offset++];
		output.data[0].Append(Value(row.key.service));
		output.data[1].Append(Value(row.key.issuer));
		output.data[2].Append(Value(row.key.client_id));
		output.data[3].Append(Value::BOOLEAN(row.removed));
		output.data[4].Append(Value::BOOLEAN(row.revoked));
		output.data[5].Append(Value::BIGINT(row.detached));
	}
}

} // namespace

void RegisterTresorLogoff(ExtensionLoader &loader) {
	TableFunctionSet set(Identifier("tresor_logoff"));
	for (auto arguments : {vector<LogicalType>(), vector<LogicalType> {LogicalType::VARCHAR}}) {
		TableFunction function(Identifier("tresor_logoff"), arguments, LogoffScan, LogoffBind, LogoffInit);
		// options: one left out is not passed at all, so the bind sees only what the call named
		function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
			options.Add("issuer", LogicalType::VARCHAR)
			    .Add("client_id", LogicalType::VARCHAR)
			    .Add("service", LogicalType::VARCHAR)
			    .Add("detach", LogicalType::BOOLEAN);
		});
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
