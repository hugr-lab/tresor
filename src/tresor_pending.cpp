#include "tresor_pending.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/main/database.hpp"

#include <chrono>

// Logins in progress (specs/025): tresor_login answers at once with what the person must see, and the flow goes
// on here. A thread per login, owned by the instance's registry, cancelled and joined when it goes.

namespace duckdb {
namespace tresor {

namespace {

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

} // namespace

PendingLogin::State PendingLogin::WaitBeyond(State from, int64_t deadline, const std::function<bool()> &interrupted) {
	std::unique_lock<mutex> guard(lock);
	while (state == from && Now() < deadline && !(interrupted && interrupted())) {
		// in slices: an interrupt of the waiting query is noticed within a fraction of a second
		changed.wait_for(guard, std::chrono::milliseconds(200));
	}
	return state;
}

shared_ptr<PendingLogins> PendingLogins::Get(DatabaseInstance &db) {
	auto logins = db.GetObjectCache().GetOrCreate<PendingLogins>(ObjectType());
	if (!logins) {
		throw InternalException("tresor: the pending logins' cache key is taken by another object");
	}
	return logins;
}

string PendingLogins::Account(const LoginKey &key) {
	string out;
	for (auto *part : {&key.issuer, &key.client_id, &key.service}) {
		out += (out.empty() ? "" : " ") + std::to_string(part->size()) + ":" + *part;
	}
	return out;
}

void PendingLogins::Stop(PendingLogin &login) {
	login.cancelled = true;
	if (login.thread.joinable()) {
		login.thread.join(); // the flows check the flag at least every second
	}
}

shared_ptr<PendingLogin> PendingLogins::Find(const LoginKey &key) {
	lock_guard<mutex> guard(lock);
	auto it = logins.find(Account(key));
	return it == logins.end() ? nullptr : it->second;
}

void PendingLogins::Add(shared_ptr<PendingLogin> login) {
	shared_ptr<PendingLogin> replaced;
	{
		lock_guard<mutex> guard(lock);
		auto &slot = logins[Account(login->key)];
		replaced = std::move(slot);
		slot = std::move(login);
	}
	if (replaced) {
		Stop(*replaced);
	}
}

shared_ptr<PendingLogin> PendingLogins::Remove(const LoginKey &key) {
	shared_ptr<PendingLogin> removed;
	{
		lock_guard<mutex> guard(lock);
		auto it = logins.find(Account(key));
		if (it == logins.end()) {
			return nullptr;
		}
		removed = std::move(it->second);
		logins.erase(it);
	}
	Stop(*removed);
	return removed;
}

void PendingLogins::Cancel(const LoginKey &key, const string &why) {
	auto login = Find(key);
	if (!login) {
		return;
	}
	login->cancelled = true;
	bool was_running;
	{
		lock_guard<mutex> guard(login->lock);
		was_running = login->state == PendingLogin::State::STARTING || login->state == PendingLogin::State::PENDING;
		if (was_running) {
			login->state = PendingLogin::State::FAILED;
			login->error = why;
		}
		std::fill(login->tokens.refresh_token.begin(), login->tokens.refresh_token.end(), '\0');
		login->tokens = oidc::TokenSet();
	}
	login->changed.notify_all();
	if (!was_running) {
		// an ended login (done: its tokens were the store's or kept here; failed) is over with the logoff: the next
		// tresor_login starts anew rather than report it
		Remove(key);
	}
}

PendingLogins::~PendingLogins() {
	unordered_map<string, shared_ptr<PendingLogin>> all;
	{
		lock_guard<mutex> guard(lock);
		all.swap(logins);
	}
	for (auto &entry : all) {
		Stop(*entry.second);
	}
}

} // namespace tresor
} // namespace duckdb
