#include "tresor_actor.hpp"
#include "tresor_login.hpp"
#include "tresor_storage.hpp"

#include "acl_connection.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/main/database.hpp"

#include <chrono>

// Acting for duckdb-acl's sessions (specs/008). acl calls the observer on its own threads and must not
// wait on the network: an open copies the token into a job and returns; tresor's workers do the
// exchange, the grant and the revocations. Nothing here logs, and no message carries a token or a grant.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

constexpr idx_t WORKERS = 2;

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

string StripSlash(string text) {
	while (!text.empty() && text.back() == '/') {
		text.pop_back();
	}
	return text;
}

//! acl's view of tresor: forwards to the actor while it lives. acl may hold the observer a moment longer
//! than tresor (a copy of the list, taken before RemoveObserver) - then it answers nothing.
class Observer : public acl::SessionObserver {
public:
	explicit Observer(weak_ptr<TresorActor> actor_p) : actor(std::move(actor_p)) {
	}
	void OnSessionOpen(const acl::SessionOpenInfo &info, const string &access_token) override {
		if (auto live = actor.lock()) {
			live->Opened(info.session_id, info.token_issuer, info.expires_at, access_token);
		}
	}
	void OnSessionClose(const string &session_id, const string &reason) override {
		if (auto live = actor.lock()) {
			live->Closed(session_id);
		}
	}

private:
	weak_ptr<TresorActor> actor;
};

} // namespace

void Wipe(string &text) {
	volatile char *bytes = &text[0];
	for (idx_t i = 0; i < text.size(); i++) {
		bytes[i] = 0;
	}
	text.clear();
}

ServiceResponse Caller::Call(const string &method, const string &path, const string &body,
                             std::map<std::string, std::string> headers) const {
	if (!session) {
		throw InvalidInputException("tresor: the catalog is detached");
	}
	if (!refused.empty()) {
		throw PermissionException("tresor: %s", refused);
	}
	if (!IsNode()) {
		headers["Delegation"] = grant;
	}
	return session->Call(method, path, body, headers);
}

TresorActor::TresorActor(shared_ptr<TresorSession> session_p, ActorOptions options_p)
    : session(std::move(session_p)), options(std::move(options_p)) {
}

TresorActor::~TresorActor() {
	Stop();
}

void TresorActor::CheckHooks(DatabaseInstance &db) {
	string why;
	if (!acl::AclSessionHooks::Reach(db.GetObjectCache(), why)) {
		throw InvalidInputException("tresor: ACT_FOR_SESSIONS cannot observe duckdb-acl's sessions: %s", why);
	}
}

void TresorActor::Start(DatabaseInstance &db) {
	string why;
	hooks = acl::AclSessionHooks::Reach(db.GetObjectCache(), why);
	if (!hooks) {
		throw InvalidInputException("tresor: ACT_FOR_SESSIONS cannot observe duckdb-acl's sessions: %s", why);
	}
	for (idx_t i = 0; i < WORKERS; i++) {
		workers.emplace_back([this]() { Work(); });
	}
	observer = make_shared_ptr<Observer>(weak_ptr<TresorActor>(shared_from_this()));
	hooks->AddObserver(observer);
}

void TresorActor::Stop() {
	if (hooks && observer) {
		hooks->RemoveObserver(observer);
	}
	observer.reset();
	{
		lock_guard<mutex> guard(lock);
		if (stopping) {
			return;
		}
		stopping = true;
		// queued exchanges are dropped - their tokens with them; the grants still held are revoked
		for (auto it = jobs.begin(); it != jobs.end();) {
			if (!it->revoke) {
				Wipe(it->token);
				it = jobs.erase(it);
			} else {
				++it;
			}
		}
		for (auto &entry : sessions) {
			if (entry.second.state == State::READY) {
				Job job;
				job.revoke = true;
				job.token = entry.second.grant;
				jobs.push_back(std::move(job));
			}
			Wipe(entry.second.grant);
		}
		sessions.clear();
	}
	queued.notify_all();
	changed.notify_all();
	for (auto &worker : workers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	workers.clear();
}

void TresorActor::OnSessionGone(std::function<void(const string &)> callback) {
	lock_guard<mutex> guard(lock);
	gone = std::move(callback);
}

void TresorActor::Opened(const string &acl_session, const string &token_issuer, int64_t expires_at,
                         const string &token) {
	lock_guard<mutex> guard(lock);
	if (stopping || acl_session.empty()) {
		return;
	}
	auto &entry = sessions[acl_session];
	entry = Entry();
	Job job;
	job.acl_session = acl_session;
	job.token = token; // the only copy, until the exchange is done
	job.issuer = token_issuer;
	job.expires_at = expires_at;
	jobs.push_back(std::move(job));
	queued.notify_one();
}

void TresorActor::Closed(const string &acl_session) {
	std::function<void(const string &)> callback;
	{
		lock_guard<mutex> guard(lock);
		auto entry = sessions.find(acl_session);
		if (entry == sessions.end()) {
			return; // opened before this ATTACH, or already gone
		}
		if (entry->second.state == State::PENDING) {
			entry->second.closed = true; // the worker revokes the grant when it arrives, and forgets the entry
		} else {
			if (entry->second.state == State::READY && !stopping) {
				Job job;
				job.revoke = true;
				job.token = entry->second.grant;
				jobs.push_back(std::move(job));
				queued.notify_one();
			}
			Wipe(entry->second.grant);
			sessions.erase(entry);
		}
		callback = gone;
	}
	changed.notify_all();
	if (callback) {
		callback(acl_session);
	}
}

string TresorActor::GrantFor(const string &acl_session, string &why) {
	unique_lock<mutex> guard(lock);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.grant_wait_seconds);
	while (true) {
		auto entry = sessions.find(acl_session);
		if (entry == sessions.end() || entry->second.closed) {
			why = "this acl session has no delegation grant here (it opened before the ATTACH, or is over)";
			return string();
		}
		if (entry->second.state == State::FAILED) {
			why = entry->second.why;
			return string();
		}
		if (entry->second.state == State::READY) {
			if (entry->second.grant_expires_at != 0 && entry->second.grant_expires_at <= NowSeconds()) {
				entry->second.state = State::FAILED;
				entry->second.why = "this acl session's delegation grant has expired";
				Wipe(entry->second.grant);
				why = entry->second.why;
				return string();
			}
			return entry->second.grant;
		}
		if (changed.wait_until(guard, deadline) == std::cv_status::timeout) {
			auto again = sessions.find(acl_session);
			if (again != sessions.end() && again->second.state == State::PENDING) {
				why = "this acl session's delegation grant is still pending (SESSION_GRANT_WAIT)";
				return string();
			}
		}
	}
}

void TresorActor::Rejected(const string &acl_session) {
	Fail(acl_session, "the service no longer accepts this acl session's delegation grant");
}

void TresorActor::Fail(const string &acl_session, const string &why) {
	{
		lock_guard<mutex> guard(lock);
		auto entry = sessions.find(acl_session);
		if (entry == sessions.end()) {
			return;
		}
		Wipe(entry->second.grant);
		if (entry->second.closed) {
			sessions.erase(entry); // closed while pending: nothing left to remember
		} else {
			entry->second.state = State::FAILED;
			entry->second.why = why;
		}
	}
	changed.notify_all();
}

void TresorActor::Work() {
	while (true) {
		Job job;
		{
			unique_lock<mutex> guard(lock);
			queued.wait(guard, [&]() { return stopping || !jobs.empty(); });
			if (jobs.empty()) {
				return; // stopping, and nothing left to revoke
			}
			job = std::move(jobs.front());
			jobs.pop_front();
		}
		try {
			if (job.revoke) {
				Revoke(job);
			} else {
				Exchange(job);
			}
		} catch (std::exception &) {
			// a failed revocation leaves the grant to its ttl; a failed exchange was already recorded
			if (!job.revoke) {
				Fail(job.acl_session, "the delegation grant could not be obtained (the service or the IdP failed)");
			}
		}
		Wipe(job.token);
	}
}

void TresorActor::Exchange(Job &job) {
	// the session's token is exchanged only at the IdP that issued it, with this node's client there
	if (StripSlash(job.issuer) != StripSlash(session->Info().issuer)) {
		Wipe(job.token);
		Fail(job.acl_session, "this acl session's token is from another issuer than " + session->Info().host +
		                          "'s login - it cannot be exchanged here");
		return;
	}
	auto exchanged = session->ExchangeForService(job.token, options.on_behalf_of, options.scope);
	Wipe(job.token);
	if (!exchanged.Ok()) {
		Fail(job.acl_session, "the identity provider refused to exchange this acl session's token: " + exchanged.error);
		return;
	}
	string body = "{\"subject_token\":" + JsonString(exchanged.access_token);
	Wipe(exchanged.access_token);
	if (job.expires_at > 0) {
		body += ",\"ttl\":" + std::to_string(MaxValue<int64_t>(1, job.expires_at - NowSeconds()));
	}
	body += "}";
	ServiceResponse response;
	try {
		response = session->Call("POST", "/v1/delegations", body);
	} catch (...) {
		Wipe(body);
		throw;
	}
	Wipe(body);
	if (response.status != 201 && response.status != 200) {
		Fail(job.acl_session, "the service refused a delegation grant for this acl session: " +
		                          DescribeProblem(response.status, response.body));
		return;
	}
	string grant;
	int64_t grant_expires_at = 0;
	{
		JsonDoc doc(response.body);
		auto root = doc.Root();
		auto id = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "id") : nullptr;
		if (id && yyjson_is_str(id)) {
			grant = yyjson_get_str(id);
		}
		auto expires = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "expires_at") : nullptr;
		if (expires && yyjson_is_str(expires)) {
			timestamp_t parsed;
			string text = yyjson_get_str(expires);
			if (Timestamp::TryConvertTimestamp(text.c_str(), text.size(), parsed, true) ==
			    TimestampCastResult::SUCCESS) {
				grant_expires_at = Timestamp::GetEpochSeconds(parsed);
			}
		}
	}
	Wipe(response.body);
	if (grant.empty()) {
		Fail(job.acl_session, "the service answered the delegation grant without an id");
		return;
	}
	bool revoke_now = false;
	{
		lock_guard<mutex> guard(lock);
		auto entry = sessions.find(job.acl_session);
		if (entry == sessions.end() || entry->second.closed || stopping) {
			// the session ended while the grant was on its way: it is revoked, never used
			revoke_now = true;
			if (entry != sessions.end()) {
				sessions.erase(entry);
			}
		} else {
			entry->second.state = State::READY;
			entry->second.grant = grant;
			entry->second.grant_expires_at = grant_expires_at;
		}
	}
	changed.notify_all();
	if (revoke_now) {
		Job revoke;
		revoke.revoke = true;
		revoke.token = grant;
		Revoke(revoke);
		Wipe(revoke.token);
	}
	Wipe(grant);
}

void TresorActor::Revoke(Job &job) {
	try {
		(void)session->Call("DELETE", "/v1/delegations/" + EncodePathSegment(job.token));
	} catch (std::exception &) {
		// the grant ends with its ttl; the error names the request's URL, with the grant in it - dropped
	}
}

} // namespace tresor
} // namespace duckdb
