#include "tresor_remember.hpp"

#include "keychain.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"

#include <cstdlib>

// A person's refresh token, kept for the next ATTACH of the same service (specs/012). Nothing here logs, and no
// message carries a token: the OS store's errors name the store and its status only.

namespace duckdb {
namespace tresor {

namespace {

constexpr const char *KEYCHAIN_SERVICE = "duckdb-tresor";

bool TryParseMode(const string &text, KeychainMode &mode) {
	auto lowered = StringUtil::Lower(text);
	if (lowered == "auto") {
		mode = KeychainMode::AUTO;
	} else if (lowered == "off") {
		mode = KeychainMode::OFF;
	} else if (lowered == "memory") {
		mode = KeychainMode::MEMORY;
	} else {
		return false;
	}
	return true;
}

KeychainMode ParseMode(const string &text) {
	KeychainMode mode;
	if (!TryParseMode(text, mode)) {
		throw InvalidInputException("tresor_keychain is auto, off or memory - not '%s'", text);
	}
	return mode;
}

void SetKeychainMode(ClientContext &context, SetScope scope, Value &parameter) {
	if (scope == SetScope::SESSION || scope == SetScope::LOCAL) {
		throw InvalidInputException("tresor_keychain is set for the whole instance: SET GLOBAL (or plain SET)");
	}
	RememberedLogins::Get(*context.db)->SetMode(ParseMode(parameter.IsNull() ? "auto" : parameter.ToString()));
}

void WipeString(string &text) {
	keychain::KeychainWipe(text);
}

string Normalized(string issuer) {
	while (!issuer.empty() && issuer.back() == '/') {
		issuer.pop_back();
	}
	return issuer;
}

} // namespace

shared_ptr<RememberedLogins> RememberedLogins::Get(DatabaseInstance &db) {
	auto logins = db.GetObjectCache().GetOrCreate<RememberedLogins>(ObjectType());
	if (!logins) {
		throw InternalException("tresor: the remembered logins' cache key is taken by another object");
	}
	return logins;
}

void RememberedLogins::Register(DatabaseInstance &db) {
	// the default may come from the environment: TRESOR_KEYCHAIN=off (a CI runner, a shared machine) or =memory
	// (test suites - they never touch the person's own store)
	auto from_env = std::getenv("TRESOR_KEYCHAIN");
	string default_mode = "auto";
	if (from_env && *from_env) {
		KeychainMode mode;
		if (!TryParseMode(from_env, mode)) {
			throw InvalidInputException("tresor: TRESOR_KEYCHAIN is auto, off or memory - not '%s'", from_env);
		}
		Get(db)->SetMode(mode);
		default_mode = StringUtil::Lower(from_env);
	}
	auto &config = DBConfig::GetConfig(db);
	config.AddExtensionOption("tresor_keychain",
	                          "tresor: where a person's login is remembered - auto (the OS credential store, where "
	                          "there is one), off, or memory (this instance only); the default from TRESOR_KEYCHAIN",
	                          LogicalType::VARCHAR, Value(default_mode), SetKeychainMode, SetScope::GLOBAL);
	Value given; // a value given before LOAD (a config option) is taken over without the callback
	if (config.TryGetCurrentSetting(Identifier("tresor_keychain"), given) && !given.IsNull()) {
		Get(db)->SetMode(ParseMode(given.ToString()));
	}
}

RememberedLogins::~RememberedLogins() {
	for (auto &entry : memory) {
		WipeString(entry.second);
	}
}

string RememberedLogins::Account(const LoginKey &key) {
	string out;
	for (auto *part : {&key.issuer, &key.client_id, &key.service}) {
		auto text = part == &key.issuer ? Normalized(*part) : *part;
		out += (out.empty() ? "" : " ") + std::to_string(text.size()) + ":" + text;
	}
	return out;
}

void RememberedLogins::SetMode(KeychainMode mode_p) {
	mode = uint8_t(mode_p);
	if (mode_p != KeychainMode::MEMORY) {
		lock_guard<mutex> guard(lock);
		for (auto &entry : memory) {
			WipeString(entry.second);
		}
		memory.clear();
	}
}

KeychainMode RememberedLogins::Mode() const {
	return KeychainMode(mode.load());
}

bool RememberedLogins::Usable(string &why) {
	switch (Mode()) {
	case KeychainMode::OFF:
		why = "tresor_keychain is off";
		return false;
	case KeychainMode::MEMORY:
		why.clear();
		return true;
	case KeychainMode::AUTO:
		return keychain::KeychainAvailable(why);
	}
	return false;
}

bool RememberedLogins::Load(const LoginKey &key, string &refresh) {
	WipeString(refresh);
	auto account = Account(key);
	switch (Mode()) {
	case KeychainMode::OFF:
		return false;
	case KeychainMode::MEMORY: {
		lock_guard<mutex> guard(lock);
		auto found = memory.find(account);
		if (found == memory.end()) {
			return false;
		}
		refresh = found->second;
		return true;
	}
	case KeychainMode::AUTO: {
		string why;
		if (!keychain::KeychainAvailable(why)) {
			return false;
		}
		auto loaded = keychain::KeychainLoad(KEYCHAIN_SERVICE, account, refresh);
		return loaded.ok && loaded.found && !refresh.empty();
	}
	}
	return false;
}

void RememberedLogins::Store(const LoginKey &key, const string &refresh, KeychainMode expected) {
	if (refresh.empty() || Mode() != expected) {
		return;
	}
	auto account = Account(key);
	if (expected == KeychainMode::MEMORY) {
		lock_guard<mutex> guard(lock);
		auto &slot = memory[account];
		WipeString(slot);
		slot = refresh;
		return;
	}
	string why;
	if (expected == KeychainMode::AUTO && keychain::KeychainAvailable(why)) {
		(void)keychain::KeychainStore(KEYCHAIN_SERVICE, account, refresh); // best effort: next time, a login
	}
}

bool RememberedLogins::Remove(const LoginKey &key, const string &only_if) {
	auto account = Account(key);
	switch (Mode()) {
	case KeychainMode::OFF:
		return false;
	case KeychainMode::MEMORY: {
		lock_guard<mutex> guard(lock);
		auto found = memory.find(account);
		if (found == memory.end() || (!only_if.empty() && found->second != only_if)) {
			return false;
		}
		WipeString(found->second);
		memory.erase(found);
		return true;
	}
	case KeychainMode::AUTO: {
		string why;
		if (!keychain::KeychainAvailable(why)) {
			return false;
		}
		string stored;
		auto loaded = keychain::KeychainLoad(KEYCHAIN_SERVICE, account, stored);
		auto present = loaded.ok && loaded.found;
		auto matches = present && (only_if.empty() || stored == only_if);
		WipeString(stored);
		if (!matches) {
			return false;
		}
		return keychain::KeychainRemove(KEYCHAIN_SERVICE, account).ok;
	}
	}
	return false;
}

mutex &RememberedLogins::KeyLock(const LoginKey &key) {
	lock_guard<mutex> guard(lock);
	auto &slot = key_locks[Account(key)];
	if (!slot) {
		slot = make_uniq<mutex>();
	}
	return *slot;
}

} // namespace tresor
} // namespace duckdb
