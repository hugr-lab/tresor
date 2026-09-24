//===----------------------------------------------------------------------===//
// tresor_events.hpp - what tresor did, for whoever listens (specs/011)
//
// Two listeners, both optional: the contract's sinks (duckdb-ext-common contracts/tresor_audit.hpp - acl-otel
// on a node), and duckdb's own log (`tresor_audit_level`, off by default: `duckdb_logs_parsed('tresor')`).
// With neither, no event is composed. An event never carries material, a token, a session handle or a
// delegation grant id.
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_audit.hpp"

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <chrono>
#include <mutex>

namespace duckdb {
class ClientContext;
class DatabaseInstance;

namespace tresor {

struct Caller;
struct ServiceResponse;

//! What `tresor_audit_level` lets into duckdb's log: nothing, refusals and failures, or everything.
enum class AuditLevel : uint8_t { OFF, DENIED, ALL };

//! The instance's audit: the contract's registry (reached at LOAD), the delivery to its sinks (started at
//! the first event anyone listens for), counters, and the log level. Held in the ObjectCache, so it goes
//! with the instance - before duckdb's logger does; others hold it weakly.
class TresorAudit : public ObjectCacheEntry {
public:
	explicit TresorAudit(DatabaseInstance &db);
	~TresorAudit() override;

	static string ObjectType() {
		return "tresor_audit";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx(); // never evicted: the level and the delivery must outlive cache pressure
	}

	//! The instance's audit, created at the first ask.
	static shared_ptr<TresorAudit> Get(DatabaseInstance &db);
	//! LOAD: the contract's registry, the log type, the setting.
	static void Register(DatabaseInstance &db);

	void SetLevel(AuditLevel level);
	//! Is anyone to be told of an event with this outcome: a sink, or the log at this level.
	bool Wanted(const string &outcome) const;
	//! The event is stamped (time, sequence), counted, logged (on `context`'s logger when there is one, so
	//! duckdb_logs names the connection and the query) and queued for the sinks. Never throws.
	void Emit(TresorAuditEvent event, optional_ptr<ClientContext> context);
	//! Counted only: `tresor.events` {kind, outcome, cached} - what a cache hit is.
	void Count(const string &kind, const string &outcome, bool cached);

private:
	DatabaseInstance &db;
	std::once_flag reached;             // hooks is set once, by the first Get, before anyone else sees this
	shared_ptr<TresorAuditHooks> hooks; // null: another contract version holds the key - sinks unreachable
	atomic<uint8_t> level {uint8_t(AuditLevel::OFF)};
	mutex lock; // seq, delivery, stopped
	int64_t seq = 0;
	unique_ptr<ext_common::Delivery<TresorAuditEvent>> delivery;
	bool stopped = false;
};

//! One audited operation: its kind, and whom and what it is about; the outcome emits it, with the time
//! since it began. When nobody listens (no sink, the log off) it is inert: nothing is copied or composed.
class Audited {
public:
	Audited(weak_ptr<TresorAudit> audit, string kind, optional_ptr<ClientContext> context);
	//! One that ended with no outcome said (an exception past it) is an error.
	~Audited();
	Audited(Audited &&) = default;
	Audited(const Audited &) = delete;

	//! Who and where, from the caller the operation runs as.
	Audited &For(const Caller &caller, const string &service);
	Audited &Secret(const string &name, const string &type = string(), bool dynamic = false);
	Audited &Target(const string &principal);
	Audited &Detail(const string &detail);
	Audited &Cached(bool cached);
	//! A service call was made: the time counts.
	Audited &Called();

	void Ok();
	void None();
	void Denied(const string &code, const string &reason);
	void Error(const string &code, const string &reason);
	//! The outcome a service answer means: 2xx ok, 403 denied, the rest an error - with its reason code.
	void Answer(const ServiceResponse &response);
	//! An exception that ended the operation.
	void Failed(const std::exception &ex);

	TresorAuditEvent event;

private:
	void Finish(const string &outcome, const string &code, const string &reason);

	shared_ptr<TresorAudit> audit; // null: nobody listens
	optional_ptr<ClientContext> context;
	std::chrono::steady_clock::time_point started;
	bool called = false;
	bool finished = false;
};

//! The reason code of a service answer (a problem type, or the status); "" for a success.
string ReasonCode(const ServiceResponse &response);

//! tresor's own words of a reason: what comes before the first ": " - after it tresor quotes others (an
//! IdP's error, a service's problem).
string OwnWords(const string &text);

//! A W3C traceparent, or "" when the text is not one: only a well-formed value is carried or sent.
string ValidTraceparent(const string &text);

} // namespace tresor
} // namespace duckdb
