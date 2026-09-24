#include "tresor_remember.hpp"

#include "keychain.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"

#include <cstdlib>

// A person's refresh token, kept for the next ATTACH (specs/012). Nothing here logs, and no message carries a
// token: the OS store's errors name the store and its status only.

namespace duckdb {
namespace tresor {

namespace {

constexpr const char *KEYCHAIN_SERVICE = "duckdb-tresor";

KeychainMode ParseMode(const string &text) {
	auto lowered = StringUtil::Lower(text);
	if (lowered == "auto") {
		return KeychainMode::AUTO;
	}
	if (lowered == "off") {
		return KeychainMode::OFF;
	}
	if (lowered == "memory") {
		return KeychainMode::MEMORY;
	}
	throw InvalidInputException("tresor_keychain is auto, off or memory - not '%s'", text);
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
	// (test suites - they never touch the person's own store). It can only narrow: `auto` is the default anyway
	auto from_env = std::getenv("TRESOR_KEYCHAIN");
	if (from_env && *from_env) {
		Get(db)->SetMode(ParseMode(from_env));
	}
	auto &config = DBConfig::GetConfig(db);
	config.AddExtensionOption("tresor_keychain",
	                          "tresor: where a person's login is remembered - auto (the OS credential store, where "
	                          "there is one), off, or memory (this instance only)",
	                          LogicalType::VARCHAR, Value(from_env && *from_env ? StringUtil::Lower(from_env) : "auto"),
	                          SetKeychainMode, SetScope::GLOBAL);
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

string RememberedLogins::Account(const string &issuer, const string &client_id) {
	auto normalized = issuer;
	while (!normalized.empty() && normalized.back() == '/') {
		normalized.pop_back();
	}
	return normalized + " " + client_id;
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

bool RememberedLogins::Usable(string &why) {
	switch (KeychainMode(mode.load())) {
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

bool RememberedLogins::Load(const string &issuer, const string &client_id, string &refresh) {
	WipeString(refresh);
	auto account = Account(issuer, client_id);
	if (KeychainMode(mode.load()) == KeychainMode::MEMORY) {
		lock_guard<mutex> guard(lock);
		auto found = memory.find(account);
		if (found == memory.end()) {
			return false;
		}
		refresh = found->second;
		return true;
	}
	string why;
	if (!Usable(why)) {
		return false;
	}
	auto loaded = keychain::KeychainLoad(KEYCHAIN_SERVICE, account, refresh);
	return loaded.ok && loaded.found && !refresh.empty();
}

void RememberedLogins::Store(const string &issuer, const string &client_id, const string &refresh) {
	if (refresh.empty()) {
		return;
	}
	auto account = Account(issuer, client_id);
	if (KeychainMode(mode.load()) == KeychainMode::MEMORY) {
		lock_guard<mutex> guard(lock);
		auto &slot = memory[account];
		WipeString(slot);
		slot = refresh;
		return;
	}
	string why;
	if (Usable(why)) {
		(void)keychain::KeychainStore(KEYCHAIN_SERVICE, account, refresh); // best effort: next time, a login
	}
}

void RememberedLogins::Remove(const string &issuer, const string &client_id) {
	auto account = Account(issuer, client_id);
	{
		lock_guard<mutex> guard(lock);
		auto found = memory.find(account);
		if (found != memory.end()) {
			WipeString(found->second);
			memory.erase(found);
		}
	}
	// the OS store too, whatever the mode: a logoff with the keychain switched off still clears what an earlier
	// mode left there
	{
		string why;
		if (keychain::KeychainAvailable(why)) {
			(void)keychain::KeychainRemove(KEYCHAIN_SERVICE, account);
		}
	}
}

} // namespace tresor
} // namespace duckdb
