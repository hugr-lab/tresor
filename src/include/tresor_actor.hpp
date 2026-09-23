//===----------------------------------------------------------------------===//
// tresor_actor.hpp - acting for duckdb-acl's sessions (specs/008)
//
// A node attaches the service as itself (ACT_FOR_SESSIONS); for every acl session that opens, the
// actor exchanges the session's token at the IdP for one meant for the service, trades it for a
// delegation grant (specs/007), and revokes the grant when the session ends. A statement under the
// session then calls the service as the node WITH the grant: the service answers as the session's
// user. Tokens live only until the grant arrives; grant ids never leave this object and the Caller.
//===----------------------------------------------------------------------===//

#pragma once

#include "tresor_session.hpp"

#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"

#include <condition_variable>
#include <deque>
#include <thread>

namespace duckdb {
class DatabaseInstance;
namespace acl {
class SessionObserver;
class AclSessionHooks;
} // namespace acl

namespace tresor {

//! Overwrite a string's bytes before it goes: tokens and grant ids do not linger in freed memory.
void Wipe(string &text);

//! How the actor exchanges and waits (the ATTACH options).
struct ActorOptions {
	bool on_behalf_of = false; // EXCHANGE 'on_behalf_of' (Entra); else RFC 8693
	string scope;              // EXCHANGE_SCOPE
	int64_t grant_wait_seconds = 10;
};

//! Whom a service call made for a statement goes as: the node, or an acl session through its grant,
//! or nobody (refused, with the reason). Resolved per statement (TresorSecretStorage::CallerFor).
struct Caller {
	shared_ptr<TresorSession> session; // null: the catalog is detached
	string acl_session;                // the acl session's ops id; empty: the node itself
	string grant;                      // the Delegation header's value, for an acl session
	string refused;                    // non-empty: this statement may not reach the service

	bool IsNode() const {
		return acl_session.empty();
	}
	bool Usable() const {
		return session && refused.empty();
	}
	//! The call, with the grant for an acl session. Throws the reason when refused or detached.
	ServiceResponse Call(const string &method, const string &path, const string &body = "",
	                     std::map<std::string, std::string> headers = {}) const;
};

class TresorActor : public enable_shared_from_this<TresorActor> {
public:
	TresorActor(shared_ptr<TresorSession> session, ActorOptions options);
	~TresorActor();

	//! Check acl's hooks (a registry stamped with another acl_connection version is refused) - at ATTACH.
	static void CheckHooks(DatabaseInstance &db);
	//! Register as an observer of acl's sessions, start the workers.
	void Start(DatabaseInstance &db);
	//! DETACH: stop observing, drop queued exchanges (their tokens wiped), revoke the grants still held,
	//! join the workers. Before the session's tokens are dropped.
	void Stop();

	//! The grant of an acl session, waiting up to the configured time for a pending one; empty, with
	//! `why`, when there is none to use.
	string GrantFor(const string &acl_session, string &why);
	//! The service refused a session's grant (401): the session gets nothing from here on.
	void Rejected(const string &acl_session);
	//! Called (outside the actor's lock) when a session is gone: the storage drops its caches.
	void OnSessionGone(std::function<void(const string &)> callback);

	// acl's observer calls, through a small adapter (tresor_actor.cpp)
	void Opened(const string &acl_session, const string &token_issuer, int64_t expires_at, const string &token);
	void Closed(const string &acl_session);

private:
	enum class State : uint8_t { PENDING, READY, FAILED };
	struct Entry {
		State state = State::PENDING;
		bool closed = false; // closed while pending: the grant is revoked as soon as it arrives
		string grant;
		int64_t grant_expires_at = 0;
		string why;
	};
	struct Job {
		bool revoke = false;
		string acl_session;
		string token; // exchange: the session's token (wiped when done); revoke: the grant
		string issuer;
		int64_t expires_at = 0;
	};

	void Work();
	void Exchange(Job &job);
	void Revoke(Job &job);
	void Fail(const string &acl_session, const string &why);

	shared_ptr<TresorSession> session;
	ActorOptions options;
	mutex lock;
	std::condition_variable changed; // an entry left PENDING
	std::condition_variable queued;  // a job, or stopping
	std::deque<Job> jobs;
	unordered_map<string, Entry> sessions;
	vector<std::thread> workers;
	bool stopping = false;
	std::function<void(const string &)> gone;
	shared_ptr<acl::SessionObserver> observer;
	shared_ptr<acl::AclSessionHooks> hooks;
};

} // namespace tresor
} // namespace duckdb
