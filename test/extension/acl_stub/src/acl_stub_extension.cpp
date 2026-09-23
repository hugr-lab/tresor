#include "acl_stub_extension.hpp"

#include "acl_connection.hpp"

#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <chrono>

// What duckdb-acl does for the acl_connection contract, reduced to what tresor's tests steer (specs/008):
//
//   SELECT acl_stub_open('s1', '<token>', '<issuer>', 300);   -- the observers' OnSessionOpen
//   SET acl_stub_session = 's1';                               -- the next statements run under s1
//   SELECT acl_stub_close('s1', 'client');                     -- the observers' OnSessionClose
//
// A session is published at each statement's QueryBegin and withdrawn at its QueryEnd, as acl does.

namespace duckdb {

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

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

} // namespace

void AclStubExtension::Load(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	config.AddExtensionOption(Identifier("acl_stub_session"), "acl_stub: the session the next statements run under",
	                          LogicalType::VARCHAR, Value(""), OnSessionSetting);
	auto text = LogicalType::VARCHAR;
	ScalarFunction open(Identifier("acl_stub_open"), {text, text, text, LogicalType::BIGINT}, LogicalType::BIGINT,
	                    OpenFun);
	open.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(open);
	ScalarFunction close(Identifier("acl_stub_close"), {text, text}, LogicalType::BIGINT, CloseFun);
	close.SetStability(FunctionStability::VOLATILE);
	loader.RegisterFunction(close);
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
