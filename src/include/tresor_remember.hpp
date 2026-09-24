//===----------------------------------------------------------------------===//
// tresor_remember.hpp - a person's login, remembered (specs/012)
//
// One refresh token per (issuer, public client id, service): in the operating system's credential store
// (duckdb-ext-common keychain/), or with `tresor_keychain = 'memory'` in this instance's memory. Never a file,
// never a service's credential, never anything but a person's refresh token. Keyed by the service too: a login
// is handed only to the service it was made for - another service behind the same IdP and client gets its own
// login (one browser round, quick while the IdP's own session lives), never a token refreshed for it silently.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/storage/object_cache.hpp"

namespace duckdb {
class DatabaseInstance;

namespace tresor {

//! `tresor_keychain`: the OS store where there is one, none, or this instance's memory.
enum class KeychainMode : uint8_t { AUTO, OFF, MEMORY };

//! Whose login: the identity provider, its public client, and the service it was made for (host[:port][/base]).
struct LoginKey {
	string issuer;
	string client_id;
	string service;
};

//! The instance's remembered logins. Store and Remove are best effort: a store that fails costs the person a
//! login next time, never this one. Only `auto` ever reaches the OS store; `memory` and `off` never do.
class RememberedLogins : public ObjectCacheEntry {
public:
	static string ObjectType() {
		return "tresor_remembered_logins";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx(); // never evicted: the memory store and the mode live here
	}

	//! The instance's, created at the first ask.
	static shared_ptr<RememberedLogins> Get(DatabaseInstance &db);
	//! LOAD: the `tresor_keychain` setting (its default from TRESOR_KEYCHAIN).
	static void Register(DatabaseInstance &db);

	void SetMode(KeychainMode mode);
	KeychainMode Mode() const;
	//! Can logins be remembered here: false with why ('off', or no OS store in this process).
	bool Usable(string &why);
	//! The refresh token remembered for `key`; false when there is none (or no store).
	bool Load(const LoginKey &key, string &refresh);
	//! Remember `refresh` for `key` - only while the mode is still `mode` (the one the login was remembered in:
	//! a login remembered in memory never reaches the OS store after a switch to auto).
	void Store(const LoginKey &key, const string &refresh, KeychainMode mode);
	//! Forget `key`; with `only_if`, only while that is the token stored (a session whose rotated-away token was
	//! refused must not remove the one another session stored since). True when an entry was removed.
	bool Remove(const LoginKey &key, const string &only_if = string());
	//! The lock of one key: a refresh chain is renewed by one caller at a time in this instance.
	mutex &KeyLock(const LoginKey &key);
	~RememberedLogins() override;

private:
	//! The entry's name: length-prefixed parts, so no two keys share one.
	static string Account(const LoginKey &key);

	atomic<uint8_t> mode {uint8_t(KeychainMode::AUTO)};
	mutex lock;                           // memory, key_locks
	unordered_map<string, string> memory; // 'memory' mode: account -> refresh token
	unordered_map<string, unique_ptr<mutex>> key_locks;
};

} // namespace tresor
} // namespace duckdb
