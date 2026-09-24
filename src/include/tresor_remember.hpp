//===----------------------------------------------------------------------===//
// tresor_remember.hpp - a person's login, remembered (specs/012)
//
// One refresh token per (issuer, public client id): in the operating system's credential store
// (duckdb-ext-common keychain/), or with `tresor_keychain = 'memory'` in this instance's memory. Never a file,
// never a service's credential, never anything but a person's refresh token.
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

//! The instance's remembered logins. Store and Remove are best effort: a store that fails costs the person a
//! login next time, never this one.
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
	//! LOAD: the `tresor_keychain` setting.
	static void Register(DatabaseInstance &db);

	void SetMode(KeychainMode mode);
	//! Can logins be remembered here: false with why ('off', or no OS store in this process).
	bool Usable(string &why);
	//! The refresh token remembered for (issuer, client); false when there is none (or no store).
	bool Load(const string &issuer, const string &client_id, string &refresh);
	void Store(const string &issuer, const string &client_id, const string &refresh);
	void Remove(const string &issuer, const string &client_id);
	~RememberedLogins() override;

private:
	static string Account(const string &issuer, const string &client_id);

	atomic<uint8_t> mode {uint8_t(KeychainMode::AUTO)};
	mutex lock;                           // memory
	unordered_map<string, string> memory; // 'memory' mode: account -> refresh token
};

} // namespace tresor
} // namespace duckdb
