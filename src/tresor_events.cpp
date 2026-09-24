#include "tresor_events.hpp"
#include "tresor_actor.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/logging/log_manager.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"

// What tresor did (specs/011), for the contract's sinks and duckdb's log. Nothing here sees material,
// tokens, session handles or grant ids: the events are made of names, codes and tresor's own words.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

constexpr size_t QUEUE_CAPACITY = 4096; // events waiting for the sinks; beyond this they are dropped (counted)
constexpr idx_t REASON_MAX = 300;       // a reason is tresor's own line, cut to this

//! The log type: one row per event in duckdb_logs, typed so duckdb_logs_parsed('tresor') has its columns.
class TresorLogType : public LogType {
public:
	static constexpr const char *NAME = "tresor";

	TresorLogType() : LogType(NAME, LogLevel::LOG_INFO, Type()) {
	}

	static LogicalType Type() {
		auto text = LogicalType::VARCHAR;
		return LogicalType::STRUCT({{"kind", text},
		                            {"outcome", text},
		                            {"reason_code", text},
		                            {"reason", text},
		                            {"service", text},
		                            {"host", text},
		                            {"login", text},
		                            {"principal", text},
		                            {"user", text},
		                            {"acl_session", text},
		                            {"correlation_id", text},
		                            {"traceparent", text},
		                            {"secret", text},
		                            {"secret_type", text},
		                            {"cached", LogicalType::BOOLEAN},
		                            {"dynamic", LogicalType::BOOLEAN},
		                            {"target", text},
		                            {"duration_us", LogicalType::BIGINT},
		                            {"detail", text},
		                            {"seq", LogicalType::BIGINT}});
	}

	static string Message(const TresorAuditEvent &event) {
		auto text = [](const string &value) {
			return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
		};
		child_list_t<Value> fields = {
		    {"kind", text(event.kind)},
		    {"outcome", text(event.outcome)},
		    {"reason_code", text(event.reason_code)},
		    {"reason", text(event.reason)},
		    {"service", text(event.service)},
		    {"host", text(event.host)},
		    {"login", text(event.login)},
		    {"principal", text(event.principal)},
		    {"user", text(event.user)},
		    {"acl_session", text(event.acl_session)},
		    {"correlation_id", text(event.correlation_id)},
		    {"traceparent", text(event.traceparent)},
		    {"secret", text(event.secret)},
		    {"secret_type", text(event.secret_type)},
		    {"cached", Value::BOOLEAN(event.cached)},
		    {"dynamic", Value::BOOLEAN(event.dynamic)},
		    {"target", text(event.target)},
		    {"duration_us", event.duration_us < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(event.duration_us)},
		    {"detail", text(event.detail)},
		    {"seq", Value::BIGINT(event.seq)},
		};
		return Value::STRUCT(std::move(fields)).ToString();
	}
};

AuditLevel ParseLevel(const string &text) {
	auto lowered = StringUtil::Lower(text);
	if (lowered == "off") {
		return AuditLevel::OFF;
	}
	if (lowered == "denied") {
		return AuditLevel::DENIED;
	}
	if (lowered == "all") {
		return AuditLevel::ALL;
	}
	throw InvalidInputException("tresor_audit_level is off, denied or all - not '%s'", text);
}

void SetAuditLevel(ClientContext &context, SetScope scope, Value &parameter) {
	auto level = ParseLevel(parameter.IsNull() ? string("off") : parameter.ToString());
	TresorAudit::Get(*context.db)->SetLevel(level);
}

int64_t NowMicros() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

bool IsLowerHex(const string &text, idx_t from, idx_t count) {
	for (idx_t i = from; i < from + count; i++) {
		auto c = text[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}
	return true;
}

} // namespace

TresorAudit::TresorAudit(DatabaseInstance &db_p) : db(db_p) {
	// the registry is reached by Get, not here: this runs under the ObjectCache's lock, which Reach takes too
}

TresorAudit::~TresorAudit() {
	unique_ptr<ext_common::Delivery<TresorAuditEvent>> stopping;
	{
		lock_guard<mutex> guard(lock);
		stopped = true;
		stopping = std::move(delivery);
	}
	// what is queued reaches the sinks, then they are flushed - the instance is still whole here
	stopping.reset();
}

shared_ptr<TresorAudit> TresorAudit::Get(DatabaseInstance &db) {
	auto audit = db.GetObjectCache().GetOrCreate<TresorAudit>(ObjectType(), db);
	if (!audit) {
		throw InternalException("tresor: the audit's cache key is taken by another object");
	}
	std::call_once(audit->reached, [&]() {
		string why;
		audit->hooks = TresorAuditHooks::Reach(db.GetObjectCache(), why); // null under another contract version
	});
	return audit;
}

void TresorAudit::Register(DatabaseInstance &db) {
	Get(db); // the contract's registry reached now: a consumer loaded later finds it either way
	db.GetLogManager().RegisterLogType(make_uniq<TresorLogType>());
	auto &config = DBConfig::GetConfig(db);
	config.AddExtensionOption("tresor_audit_level",
	                          "tresor: what tresor writes to duckdb's log (type 'tresor'): off, denied (refusals and "
	                          "failures) or all",
	                          LogicalType::VARCHAR, Value("off"), SetAuditLevel, SetScope::GLOBAL);
}

void TresorAudit::SetLevel(AuditLevel level_p) {
	level = uint8_t(level_p);
}

bool TresorAudit::Wanted(const string &outcome) const {
	if (hooks && hooks->HasSinks()) {
		return true;
	}
	auto current = AuditLevel(level.load());
	if (current == AuditLevel::ALL) {
		return true;
	}
	// an empty outcome: not known yet - wanted if any outcome may be
	return current == AuditLevel::DENIED && (outcome.empty() || outcome == "denied" || outcome == "error");
}

void TresorAudit::Emit(TresorAuditEvent event, optional_ptr<ClientContext> context) {
	try {
		event.ts_us = NowMicros();
		Count(event.kind, event.outcome, event.cached);
		auto current = AuditLevel(level.load());
		bool refusal = event.outcome == "denied" || event.outcome == "error";
		bool log = current == AuditLevel::ALL || (current == AuditLevel::DENIED && refusal);
		unique_ptr<TresorAuditEvent> logged;
		{
			// numbered under the lock the push takes: the sinks see the numbers in order
			lock_guard<mutex> guard(lock);
			event.seq = ++seq;
			if (log) {
				logged = make_uniq<TresorAuditEvent>(event);
			}
			if (hooks && hooks->HasSinks() && !stopped) {
				if (!delivery) {
					// the thread starts with the first event anyone listens for: a laptop without acl-otel runs none
					auto registry = hooks;
					delivery = make_uniq<ext_common::Delivery<TresorAuditEvent>>(
					    QUEUE_CAPACITY, [registry]() { return registry->Sinks(); },
					    [registry](const string &what) { registry->GetCounters().Add("tresor.audit." + what, {}); });
				}
				delivery->Push(std::move(event));
			}
		}
		if (logged) {
			auto log_level = refusal ? LogLevel::LOG_WARNING : LogLevel::LOG_INFO;
			auto &logger = context ? Logger::Get(*context) : Logger::Get(db);
			if (logger.ShouldLog(TresorLogType::NAME, log_level)) {
				logger.WriteLog(TresorLogType::NAME, log_level, TresorLogType::Message(*logged));
			}
		}
	} catch (...) {
		// the audit never fails what it describes
	}
}

void TresorAudit::Count(const string &kind, const string &outcome, bool cached) {
	if (hooks) {
		hooks->GetCounters().Add("tresor.events",
		                         {{"kind", kind}, {"outcome", outcome}, {"cached", cached ? "true" : "false"}});
	}
}

Audited::~Audited() {
	if (!finished) {
		Finish("error", "other", "ended without an outcome");
	}
}

Audited::Audited(weak_ptr<TresorAudit> audit_p, string kind, optional_ptr<ClientContext> context_p)
    : context(context_p), started(std::chrono::steady_clock::now()) {
	// anyone who may want this one, whatever its outcome turns out to be (the log may take refusals only)
	auto live = audit_p.lock();
	if (live && live->Wanted(string())) {
		audit = std::move(live);
		event.kind = std::move(kind);
	}
}

Audited &Audited::For(const Caller &caller, const string &service) {
	if (!audit) {
		return *this;
	}
	event.service = service;
	if (caller.session) {
		auto &info = caller.session->Info();
		event.host = info.host;
		event.login = LoginFlowName(caller.session->Flow());
		event.principal = caller.session->Subject();
	}
	event.user = caller.user;
	event.acl_session = caller.acl_session;
	event.correlation_id = caller.correlation_id;
	event.traceparent = caller.traceparent;
	return *this;
}

Audited &Audited::Secret(const string &name, const string &type, bool dynamic) {
	if (audit) {
		event.secret = name;
		event.secret_type = type;
		event.dynamic = dynamic;
	}
	return *this;
}

Audited &Audited::Target(const string &principal) {
	if (audit) {
		event.target = principal;
	}
	return *this;
}

Audited &Audited::Detail(const string &detail) {
	if (audit) {
		event.detail = detail;
	}
	return *this;
}

Audited &Audited::Cached(bool cached) {
	if (audit) {
		event.cached = cached;
	}
	return *this;
}

Audited &Audited::Called() {
	called = true;
	return *this;
}

void Audited::Ok() {
	Finish("ok", string(), string());
}

void Audited::None() {
	Finish("none", string(), string());
}

void Audited::Denied(const string &code, const string &reason) {
	Finish("denied", code, reason);
}

void Audited::Error(const string &code, const string &reason) {
	Finish("error", code, reason);
}

void Audited::Answer(const ServiceResponse &response) {
	called = true;
	if (response.status / 100 == 2) {
		Ok();
		return;
	}
	// the status and the code only: the service's own text is not ours to pass on (it may quote a value)
	auto code = ReasonCode(response);
	auto reason = "the service answered HTTP " + std::to_string(response.status);
	if (response.status == 403 || response.status == 401) {
		Denied(code, reason);
	} else {
		Error(code, reason);
	}
}

void Audited::Failed(const std::exception &ex) {
	// the kind of failure, in tresor's words: an exception's text may quote a value, a URL or an IdP's answer
	ErrorData error(ex);
	auto type = error.Type();
	if (type == ExceptionType::PERMISSION) {
		Finish("denied", "no_grant", "this caller may not reach the service (no usable delegation grant)");
	} else if (type == ExceptionType::IO || type == ExceptionType::HTTP || type == ExceptionType::CONNECTION) {
		Finish("error", "transport", "the service or the identity provider could not be reached");
	} else if (type == ExceptionType::INVALID_INPUT) {
		Finish("error", "invalid", "refused as invalid");
	} else {
		Finish("error", "other", "failed");
	}
}

void Audited::Finish(const string &outcome, const string &code, const string &reason) {
	if (finished) {
		return;
	}
	finished = true;
	if (!audit || !audit->Wanted(outcome)) {
		return;
	}
	event.outcome = outcome;
	event.reason_code = code;
	event.reason = reason.size() > REASON_MAX ? reason.substr(0, REASON_MAX) : reason;
	if (called) {
		event.duration_us =
		    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count();
	}
	audit->Emit(std::move(event), context);
}

string ReasonCode(const ServiceResponse &response) {
	if (response.status / 100 == 2) {
		return string();
	}
	string type;
	{
		JsonDoc doc(response.body);
		auto root = doc.Root();
		auto value = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "type") : nullptr;
		type = value && yyjson_is_str(value) ? yyjson_get_str(value) : "";
	}
	// the protocol's problem types a consumer may group by; anything else by its status (bounded, R7)
	for (auto *known : {"no_verb", "not_found", "actor_not_allowed", "mint_refused"}) {
		if (type == known) {
			return type;
		}
	}
	switch (response.status) {
	case 401:
		return "unauthenticated";
	case 403:
		return "no_verb";
	case 404:
		return "not_found";
	case 502:
	case 503:
	case 504:
		return "service_unavailable";
	default:
		return response.status >= 400 && response.status < 500 ? "invalid" : "other";
	}
}

string OwnWords(const string &text) {
	auto colon = text.find(": ");
	return colon == string::npos ? text : text.substr(0, colon);
}

string ValidTraceparent(const string &text) {
	// version "00": 00-<32 hex trace id>-<16 hex span id>-<2 hex flags>, lower case (W3C Trace Context)
	if (text.size() != 55 || text[2] != '-' || text[35] != '-' || text[52] != '-') {
		return string();
	}
	if (!IsLowerHex(text, 0, 2) || !IsLowerHex(text, 3, 32) || !IsLowerHex(text, 36, 16) || !IsLowerHex(text, 53, 2)) {
		return string();
	}
	if (text.compare(0, 2, "ff") == 0 || text.compare(3, 32, string(32, '0')) == 0 ||
	    text.compare(36, 16, string(16, '0')) == 0) {
		return string(); // an invalid version, or an all-zero id
	}
	return text;
}

} // namespace tresor
} // namespace duckdb
