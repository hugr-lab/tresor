#include "acl_stub_extension.hpp"

#include "acl_connection.hpp"
#include "tresor_audit.hpp"

#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <map>
#include <mutex>

// What duckdb-acl does for the acl_connection contract, reduced to what tresor's tests steer (specs/008):
//
//   SELECT acl_stub_open('s1', '<token>', '<issuer>', 300);   -- the observers' OnSessionOpen
//   SET acl_stub_session = 's1';                               -- the next statements run under s1
//   SELECT acl_stub_close('s1', 'client');                     -- the observers' OnSessionClose
//   SELECT acl_stub_stamp(99);                                 -- the connection state of another contract
//   SET acl_stub_traceparent = '00-...'; SET acl_stub_correlation = 'c1'; SET acl_stub_user = 'alice';
//                                                              -- the statement's trace markers and user
//   SELECT acl_stub_audit_listen();                            -- a sink on tresor's audit contract (specs/011)
//   SELECT acl_stub_audit_last('lookup');                      -- the last such event, as acl-otel sees it
//
// A session is published at each statement's QueryBegin and withdrawn at its QueryEnd, as acl does.

namespace duckdb {

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

string Setting(ClientContext &context, const char *name) {
	Value value;
	if (context.TryGetCurrentSetting(Identifier(name), value) && !value.IsNull()) {
		return value.ToString();
	}
	return string();
}

//! What acl-otel would do with tresor's events, reduced to remembering them.
class RecordingSink : public tresor::TresorAuditSink {
public:
	void OnEvent(const tresor::TresorAuditEvent &event) override {
		std::lock_guard<std::mutex> guard(lock);
		events.push_back(event);
		arrived.notify_all();
	}
	//! The last event of `kind`, waiting up to three seconds for one after the `after`-th.
	bool Last(const string &kind, tresor::TresorAuditEvent &out) {
		std::unique_lock<std::mutex> guard(lock);
		auto found = [&]() {
			for (auto it = events.rbegin(); it != events.rend(); ++it) {
				if (it->kind == kind && it->seq > seen[kind]) {
					out = *it;
					return true;
				}
			}
			return false;
		};
		if (!arrived.wait_for(guard, std::chrono::seconds(3), found)) {
			return false;
		}
		seen[kind] = out.seq;
		return true;
	}

private:
	std::mutex lock;
	std::condition_variable arrived;
	vector<tresor::TresorAuditEvent> events;
	std::map<string, int64_t> seen; // an event is answered once: the next ask waits for a newer one
};

shared_ptr<RecordingSink> recorder;

//! Per connection: publishes the session named by acl_stub_session for the statement's duration.
class StubConnection : public ClientContextState {
public:
	void QueryBegin(ClientContext &context) override {
		string why;
		auto state = acl::AclConnection::Reach(context, why);
		if (!state) {
			return;
		}
		Value session;
		if (context.TryGetCurrentSetting(Identifier("acl_stub_session"), session) && !session.IsNull() &&
		    !session.ToString().empty()) {
			acl::AclSessionView view;
			view.session_id = session.ToString();
			view.door = "stub";
			view.traceparent = Setting(context, "acl_stub_traceparent");
			view.correlation_id = Setting(context, "acl_stub_correlation");
			view.principal.subject = Setting(context, "acl_stub_user");
			state->Publish(std::move(view));
		} else {
			state->Withdraw();
		}
	}
	void QueryEnd(ClientContext &context) override {
		string why;
		auto state = acl::AclConnection::Reach(context, why);
		if (state) {
			state->Withdraw();
		}
	}
};

void OnSessionSetting(ClientContext &context, SetScope scope, Value &parameter) {
	context.registered_state->GetOrCreate<StubConnection>("acl_stub_connection");
}

shared_ptr<acl::AclSessionHooks> Hooks(ExpressionState &state) {
	string why;
	auto hooks = acl::AclSessionHooks::Reach(DatabaseInstance::GetDatabase(state.GetContext()).GetObjectCache(), why);
	if (!hooks) {
		throw InvalidInputException("acl_stub: %s", why);
	}
	return hooks;
}

//! acl_stub_open(session_id, token, issuer, expires_in; 0 = none): every observer's OnSessionOpen; the count called.
void OpenFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto hooks = Hooks(state);
	for (idx_t row = 0; row < args.size(); row++) {
		acl::SessionOpenInfo info;
		info.session_id = args.data[0].GetValue(row).ToString();
		auto token = args.data[1].GetValue(row).ToString();
		info.token_issuer = args.data[2].GetValue(row).ToString();
		info.door = "stub";
		info.principal.subject = Setting(state.GetContext(), "acl_stub_user");
		info.opened_at = NowSeconds();
		auto expires_in = args.data[3].GetValue(row).GetValue<int64_t>(); // 0: no expiry
		info.expires_at = expires_in == 0 ? 0 : info.opened_at + expires_in;
		int64_t called = 0;
		for (auto &observer : hooks->Observers()) {
			observer->OnSessionOpen(info, token);
			called++;
		}
		result.SetValue(row, Value::BIGINT(called));
	}
}

//! acl_stub_close(session_id, reason): every observer's OnSessionClose; the count called.
void CloseFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto hooks = Hooks(state);
	for (idx_t row = 0; row < args.size(); row++) {
		auto session_id = args.data[0].GetValue(row).ToString();
		auto reason = args.data[1].GetValue(row).ToString();
		int64_t called = 0;
		for (auto &observer : hooks->Observers()) {
			observer->OnSessionClose(session_id, reason);
			called++;
		}
		result.SetValue(row, Value::BIGINT(called));
	}
}

//! acl_stub_stamp(version): restamp this connection's AclConnection, as an acl built from another revision of
//! the contract would have it - the reader must refuse it. The version it had.
void StampFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &raw = *state.GetContext().registered_state->GetOrCreate<acl::AclConnection>(acl::AclConnection::StateKey());
	for (idx_t row = 0; row < args.size(); row++) {
		auto previous = raw.contract_version;
		raw.contract_version = int32_t(args.data[0].GetValue(row).GetValue<int64_t>());
		result.SetValue(row, Value::BIGINT(previous));
	}
}

//! acl_stub_publisher(who): mark the hooks as published by `who` ('' clears it: nothing publishes); the old mark.
void PublisherFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto hooks = Hooks(state);
	for (idx_t row = 0; row < args.size(); row++) {
		string previous;
		hooks->Publisher(previous);
		hooks->MarkPublisher(args.data[0].GetValue(row).ToString());
		result.SetValue(row, Value(previous));
	}
}

//! acl_stub_audit_listen(): a recording sink on tresor's audit registry (once); why it cannot, as an error.
void ListenFun(DataChunk &args, ExpressionState &state, Vector &result) {
	string why;
	auto hooks =
	    tresor::TresorAuditHooks::Reach(DatabaseInstance::GetDatabase(state.GetContext()).GetObjectCache(), why);
	if (!hooks) {
		throw InvalidInputException("acl_stub: %s", why);
	}
	if (!recorder) {
		recorder = make_shared_ptr<RecordingSink>();
		hooks->AddSink(recorder);
	}
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, Value::BOOLEAN(true));
	}
}

//! acl_stub_audit_last(kind): the newest event of `kind` not answered yet, as one line of its fields; NULL when
//! none arrives within three seconds.
void LastFun(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		tresor::TresorAuditEvent event;
		if (!recorder || !recorder->Last(args.data[0].GetValue(row).ToString(), event)) {
			result.SetValue(row, Value(LogicalType::VARCHAR));
			continue;
		}
		auto line = event.outcome + "|" + event.reason_code + "|" + event.service + "|" + event.acl_session + "|" +
		            event.user + "|" + event.correlation_id + "|" + event.traceparent + "|" + event.secret + "|" +
		            event.detail + "|" + (event.duration_us >= 0 ? "timed" : "untimed");
		result.SetValue(row, Value(line));
	}
}

} // namespace

void AclStubExtension::Load(ExtensionLoader &loader) {
	// the publisher's mark (ACLC 2), as duckdb-acl sets it at load: sessions are published in this instance
	// ACL_STUB_NO_MARK=1 leaves the mark to a real duckdb-acl loaded beside the stub (test_keycloak.sh's run)
	string why;
	auto hooks = acl::AclSessionHooks::Reach(loader.GetDatabaseInstance().GetObjectCache(), why);
	auto no_mark = std::getenv("ACL_STUB_NO_MARK");
	if (hooks && !(no_mark && string(no_mark) == "1")) {
		hooks->MarkPublisher("acl_stub (ACLC 2)");
	}
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	config.AddExtensionOption(Identifier("acl_stub_session"), "acl_stub: the session the next statements run under",
	                          LogicalType::VARCHAR, Value(""), OnSessionSetting);
	for (auto *name : {"acl_stub_traceparent", "acl_stub_correlation", "acl_stub_user"}) {
		config.AddExtensionOption(Identifier(name), "acl_stub: a marker of the statements under acl_stub_session",
		                          LogicalType::VARCHAR, Value(""));
	}
	auto text = LogicalType::VARCHAR;
	ScalarFunction listen(Identifier("acl_stub_audit_listen"), {}, LogicalType::BOOLEAN, ListenFun);
	listen.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(listen);
	ScalarFunction last(Identifier("acl_stub_audit_last"), {text}, text, LastFun);
	last.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(last);
	ScalarFunction open(Identifier("acl_stub_open"), {text, text, text, LogicalType::BIGINT}, LogicalType::BIGINT,
	                    OpenFun);
	open.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(open);
	ScalarFunction close(Identifier("acl_stub_close"), {text, text}, LogicalType::BIGINT, CloseFun);
	close.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(close);
	ScalarFunction publisher(Identifier("acl_stub_publisher"), {text}, text, PublisherFun);
	publisher.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(publisher);
	ScalarFunction stamp(Identifier("acl_stub_stamp"), {LogicalType::BIGINT}, LogicalType::BIGINT, StampFun);
	stamp.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(stamp);
}

std::string AclStubExtension::Name() {
	return "acl_stub";
}

std::string AclStubExtension::Version() const {
	return "test";
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(acl_stub, loader) {
	duckdb::AclStubExtension extension;
	extension.Load(loader);
}
}
