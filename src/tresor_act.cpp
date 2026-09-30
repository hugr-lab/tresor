#include "tresor_actor.hpp"
#include "tresor_catalog.hpp"
#include "tresor_events.hpp"
#include "tresor_login.hpp"

#include "acl_connection.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/client_context.hpp"

// corp.act_for_sessions(...) (specs/015): acting for duckdb-acl's sessions, turned on for a catalog attached
// before duckdb-acl was loaded - the node's bootstrap installs acl from a repository whose secret this very
// catalog serves. The checks are ATTACH's ACT_FOR_SESSIONS ones; one way, and never under an acl session.

namespace duckdb {
namespace tresor {

namespace {

struct ActInfo : public TableFunctionInfo {
	explicit ActInfo(TresorCatalog &catalog_p) : catalog(catalog_p) {
	}
	TresorCatalog &catalog; // the catalog this function lives in: it outlives the function
};

struct ActBindData : public TableFunctionData {
	explicit ActBindData(TresorCatalog &catalog_p) : catalog(catalog_p) {
	}
	TresorCatalog &catalog;
	bool on_behalf_of = false;
	string scope;
	string audience;
	int64_t grant_wait_seconds = DEFAULT_GRANT_WAIT_SECONDS;
};

struct ActState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<FunctionData> ActBind(ClientContext &context, TableFunctionBindInput &input,
                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<ActInfo>();
	auto data = make_uniq<ActBindData>(info.catalog);
	for (auto &named : input.named_parameters) {
		auto name = StringUtil::Lower(named.first.GetIdentifierName());
		if (named.second.IsNull()) {
			throw InvalidInputException("act_for_sessions: %s must not be NULL", name);
		}
		if (name == "exchange") {
			data->on_behalf_of = ParseExchange(named.second.ToString());
		} else if (name == "exchange_scope") {
			data->scope = named.second.ToString();
		} else if (name == "exchange_audience") {
			data->audience = named.second.ToString();
		} else if (name == "session_grant_wait") {
			data->grant_wait_seconds = ParseGrantWait(BigIntValue::Get(named.second));
		}
	}
	auto add = [&](const char *name) {
		names.emplace_back(name);
		return_types.push_back(name == string("changed") ? LogicalType::BOOLEAN : LogicalType::VARCHAR);
	};
	add("service");
	add("exchange");
	add("audience");
	add("scope");
	add("changed");
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> ActInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<ActState>();
}

Value OrNull(const string &text) {
	return text.empty() ? Value(LogicalType::VARCHAR) : Value(text);
}

void ActScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<ActState>();
	if (state.done) {
		return;
	}
	state.done = true; // once per statement, whatever happens below
	auto &data = input.bind_data->Cast<ActBindData>();
	auto &catalog = data.catalog;
	auto service = catalog.GetAttached().GetName().GetIdentifierName();
	Audited event(catalog.Storage().AuditOf(), "login", &context);
	event.event.service = service;
	Caller node;
	node.session = catalog.SharedSession();
	event.For(node, service).Detail("act_for_sessions");
	// the node's own connection only: never a statement run for an acl session's user, nor one acl's connection
	// contract cannot place (duckdb-acl also never lets a principal call it) - an attempt is audited
	string why;
	auto acl_state = acl::AclConnection::Reach(context, why);
	acl::AclSessionView view;
	if (!acl_state || acl_state->Current(view)) {
		// whose attempt it was, as far as acl can tell: the session and its user, not the node
		if (!acl_state) {
			event.event.acl_session = "?";
		} else {
			event.event.acl_session = view.session_id.empty() ? "?" : view.session_id;
			event.event.user = view.principal.issuer.empty()
			                       ? view.principal.subject
			                       : "subject:" + view.principal.issuer + "|" + view.principal.subject;
			event.event.correlation_id = view.correlation_id;
		}
		event.Denied("other", "under a duckdb-acl session");
		throw PermissionException("act_for_sessions: not under a duckdb-acl session");
	}
	bool changed;
	ActorOptions options;
	try {
		options = ActingOptions(catalog.Session(), data.on_behalf_of, data.scope, data.audience,
		                        data.grant_wait_seconds, service);
		changed = catalog.ActForSessions(options);
	} catch (std::exception &ex) {
		event.Failed(ex);
		throw;
	}
	if (changed) {
		event.Ok();
	} else {
		event.None(); // already acting, with these options
	}
	output.data[0].Append(Value(service));
	output.data[1].Append(Value(options.on_behalf_of ? "on_behalf_of" : "token_exchange"));
	output.data[2].Append(OrNull(options.audience));
	output.data[3].Append(OrNull(options.scope));
	output.data[4].Append(Value::BOOLEAN(changed));
}

} // namespace

TableFunction ActForSessionsFunction(TresorCatalog &catalog) {
	TableFunction function(Identifier("act_for_sessions"), {}, ActScan, ActBind, ActInit);
	// options: one left out is not passed at all
	function.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("exchange", LogicalType::VARCHAR)
		    .Add("exchange_scope", LogicalType::VARCHAR)
		    .Add("exchange_audience", LogicalType::VARCHAR)
		    .Add("session_grant_wait", LogicalType::BIGINT);
	});
	function.function_info = make_shared_ptr<ActInfo>(catalog);
	return function;
}

} // namespace tresor
} // namespace duckdb
