#include "tresor_catalog.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {
namespace tresor {

TresorCatalog::TresorCatalog(AttachedDatabase &db, shared_ptr<TresorSession> session_p, TresorSecretStorage &storage_p,
                             vector<Descriptor> initial_p, unique_ptr<ActorOptions> acting_p)
    : DuckCatalog(db), session(std::move(session_p)), storage(storage_p), initial(std::move(initial_p)),
      acting(std::move(acting_p)) {
}

TresorCatalog::~TresorCatalog() {
	Shutdown();
}

void TresorCatalog::Shutdown() {
	storage.Deactivate(*session);
	shared_ptr<TresorActor> stopping;
	bool first;
	{
		lock_guard<mutex> guard(actor_lock);
		stopping = actor;
		first = !shut;
		shut = true;
	}
	if (stopping) {
		stopping->Stop(); // the grants still held are revoked with the login, before it goes
	}
	session->Close();
	if (first) {
		Caller node;
		node.session = session;
		storage.Audit("logout", node, nullptr).Ok();
	}
}

void TresorCatalog::Initialize(bool load_builtin) {
	DuckCatalog::Initialize(false);
	auto transaction = CatalogTransaction::GetSystemTransaction(GetDatabase());
	// the info's constructor marks it `internal`, which duckdb allows only in the system catalog; DROP
	// FUNCTION is refused anyway, by the read-only switch below
	CreateTableFunctionInfo whoami(WhoamiFunction(session, storage));
	whoami.internal = false;
	CreateTableFunction(transaction, whoami);
	CreateTableFunctionInfo secrets(SecretsFunction(session, storage));
	secrets.internal = false;
	CreateTableFunction(transaction, secrets);
	for (auto &function : ManagementFunctions(session, storage)) {
		CreateTableFunctionInfo manage(std::move(function));
		manage.internal = false;
		CreateTableFunction(transaction, manage);
	}
	CreateTableFunctionInfo act(ActForSessionsFunction(*this));
	act.internal = false;
	CreateTableFunction(transaction, act);
	// the secrets join the lookup only now, with the catalog that serves them: an ATTACH failing before
	// this point leaves nothing behind (specs/004)
	storage.Activate(session, std::move(initial), nullptr);
	if (acting) {
		ActForSessions(*acting);
	}
	// from here on the database is read-only: its storage stays an ordinary in-memory one (duckdb refuses
	// an in-memory storage opened read-only), and every statement that would modify `corp` is refused by
	// duckdb's own check before it runs
	GetAttached().SetReadOnlyDatabase();
}

static bool SameActing(const ActorOptions &a, const ActorOptions &b) {
	return a.on_behalf_of == b.on_behalf_of && a.scope == b.scope && a.audience == b.audience &&
	       a.grant_wait_seconds == b.grant_wait_seconds;
}

bool TresorCatalog::ActForSessions(const ActorOptions &options) {
	lock_guard<mutex> guard(actor_lock);
	if (shut) {
		throw InvalidInputException("tresor: %s is detached", options.service);
	}
	if (actor) {
		if (SameActing(actor->Options(), options)) {
			return false;
		}
		throw InvalidInputException("tresor: %s already acts for duckdb-acl sessions, with other options - acting "
		                            "is not changed on a live catalog: DETACH and ATTACH it again",
		                            options.service);
	}
	// refused unless duckdb-acl publishes its sessions here (ACLC 2)
	TresorActor::CheckHooks(GetDatabase());
	auto with = options;
	with.audit = storage.AuditOf();
	auto created = make_shared_ptr<TresorActor>(session, std::move(with));
	// acl's sessions are observed from here on (specs/008); a session's caches go with it
	auto &served = storage;
	created->OnSessionGone([&served](const string &acl_session) { served.ForgetSession(acl_session); });
	created->Start(GetDatabase());
	storage.SetActor(*session, created);
	actor = std::move(created);
	return true;
}

void TresorCatalog::OnDetach(ClientContext &context) {
	Shutdown();
	DuckCatalog::OnDetach(context);
}

} // namespace tresor
} // namespace duckdb
