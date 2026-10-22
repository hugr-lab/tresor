//===----------------------------------------------------------------------===//
// tresor_page_tokens.hpp - the access tokens a web page hands over (specs/043)
//
// A page that logged its user in (oidc-client-ts, MSAL) hands tresor an access token for the service's audience
// with tresor_web_token, and a new one each time it renews its own. One per (issuer, service), in this instance's
// memory only: never a file, never the OS store, never a refresh token - the page's refresh chain stays the page's.
// A session attached on it reads the newest at every call; a token forgotten (tresor_logoff) ends its use.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/storage/object_cache.hpp"

namespace duckdb {
class DatabaseInstance;

namespace tresor {

struct PageToken {
	string token;
	int64_t expires_at = 0; // the JWT's `exp`; 0 for a token that names none (an opaque one)
};

class PageTokens : public ObjectCacheEntry {
public:
	static string ObjectType() {
		return "tresor_page_tokens";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx(); // never evicted: a page's login lives here
	}
	//! The instance's, created at the first ask.
	static shared_ptr<PageTokens> Get(DatabaseInstance &db);

	//! The page's newest token for the service (host[:port][/base]) from that issuer (no trailing slash).
	void Set(const string &issuer, const string &service, PageToken token);
	//! The token held for them; false when there is none (never handed over, or forgotten).
	bool Find(const string &issuer, const string &service, PageToken &out);
	//! Forget the service's tokens (from any issuer); every service's with an empty one. The services forgotten.
	vector<string> Forget(const string &service);
	~PageTokens() override;

private:
	static string Key(const string &issuer, const string &service);
	mutex lock;
	unordered_map<string, PageToken> tokens;  // by Key
	unordered_map<string, string> service_of; // Key -> service, for Forget
};

} // namespace tresor
} // namespace duckdb
