//===----------------------------------------------------------------------===//
// tresor_pending.hpp - a person's login in progress, started by tresor_login (specs/025)
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/storage/object_cache.hpp"
#include "oidc_core.hpp"
#include "tresor_remember.hpp"

#include <condition_variable>
#include <thread>

namespace duckdb {
class DatabaseInstance;

namespace tresor {

//! One login in progress for a key: the flow runs on a thread of its own; what the person needs (the URL, the
//! device code) is set as soon as it is known, the outcome when it ends. Never a token in a status.
struct PendingLogin {
	enum class State : uint8_t { STARTING, PENDING, DONE, FAILED };

	LoginKey key;
	string flow;    // browser, device
	string service; // host[:port][/base], as tresor_login named it

	mutex lock;
	std::condition_variable changed;
	State state = State::STARTING;
	string url;
	string user_code;
	int64_t expires_at = 0;
	string error;
	//! remember := false (or no store): the tokens wait here for one ATTACH, never in the store
	bool keep_tokens = false;
	oidc::TokenSet tokens;

	std::atomic<bool> cancelled {false};
	std::thread thread;

	//! Wait until the state leaves `from` (or `deadline`, or `interrupted` says so); the state then.
	State WaitBeyond(State from, int64_t deadline, const std::function<bool()> &interrupted);
};

//! The instance's logins in progress, by key. Owns their threads: closing the instance cancels and joins them.
class PendingLogins : public ObjectCacheEntry {
public:
	static string ObjectType() {
		return "tresor_pending_logins";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx(); // never evicted: the threads are owned here
	}

	static shared_ptr<PendingLogins> Get(DatabaseInstance &db);

	//! The login in progress (or ended, not yet reported) for `key`; null when there is none.
	shared_ptr<PendingLogin> Find(const LoginKey &key);
	//! Register a new one for `key`, replacing (cancelling, joining) whatever was there.
	void Add(shared_ptr<PendingLogin> login);
	//! Forget the one for `key` (its thread cancelled and joined); returns it.
	shared_ptr<PendingLogin> Remove(const LoginKey &key);
	//! A logoff: the one for `key` ends as failed ("logged off"), its thread cancelled.
	void Cancel(const LoginKey &key, const string &why);

	~PendingLogins() override;

private:
	static string Account(const LoginKey &key);
	static void Stop(PendingLogin &login);

	mutex lock;
	unordered_map<string, shared_ptr<PendingLogin>> logins;
};

} // namespace tresor
} // namespace duckdb
