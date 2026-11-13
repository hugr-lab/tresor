#include "tresor_credentials.hpp"
#include "tresor_actor.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// A service login's proof (specs/013). Nothing here logs; no error names a key's, a token's or a secret's
// content - only the path and what is wrong with it.

namespace duckdb {
namespace tresor {

namespace {

constexpr size_t MAX_FILE_BYTES = 64 * 1024; // a key, a certificate or a token: never more

//! A JWT's shape: three base64url parts. What a federated token file must hold - so that the flow never carries a
//! file of another kind (a key, a config) to an identity provider.
bool JwtShaped(const string &text) {
	idx_t dots = 0;
	for (auto c : text) {
		if (c == '.') {
			dots++;
		} else if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')) {
			return false;
		}
	}
	return dots == 2 && text.size() > 16;
}

//! What the file says goes into an error only shortened: it is not secret, but it is the file's, unchecked.
string Shown(const string &text) {
	return text.size() > 200 ? text.substr(0, 200) + "..." : text;
}

string WithoutTrailingSlashes(string url) {
	while (!url.empty() && url.back() == '/') {
		url.pop_back();
	}
	return url;
}

bool MeantFor(const JwtClaims &claims, const string &audience) {
	return std::any_of(claims.audiences.begin(), claims.audiences.end(), [&](const string &aud) {
		return WithoutTrailingSlashes(aud) == WithoutTrailingSlashes(audience);
	});
}

//! Why a JWT-SVID read from `path` is not sent (specs/046, 047), or nothing: it is a JWT whose `sub` is the SPIFFE ID
//! named, for `audience`, alive - an SVID is a credential wherever it is accepted.
string SvidRefusal(const string &token, const JwtClaims &claims, const string &path, const string &spiffe_id,
                   const string &audience) {
	if (!JwtShaped(token) || !claims.is_jwt) {
		return path + " does not hold a token (a JWT) - never sent";
	}
	if (!StringUtil::StartsWith(claims.subject, "spiffe://")) {
		return path + " does not hold a JWT-SVID: its sub is no SPIFFE ID - never sent";
	}
	if (spiffe_id.empty()) {
		// CREATE SECRET requires it; a persistent secret read back is not validated again
		return "the tresor secret names no SPIFFE_ID for the JWT-SVID in " + path + " - never sent";
	}
	if (claims.subject != spiffe_id) {
		return "the JWT-SVID in " + path + " is " + Shown(claims.subject) + ", not SPIFFE_ID " + spiffe_id +
		       " - never sent";
	}
	if (!MeantFor(claims, audience)) {
		return "the JWT-SVID in " + path + " is not meant for " + audience +
		       " (its aud: " + Shown(StringUtil::Join(claims.audiences, ", ")) + ") - never sent";
	}
	if (claims.expires_at <= int64_t(std::time(nullptr))) {
		return "the JWT-SVID in " + path +
		       (claims.expires_at == 0 ? " has no expiry" : " has expired - is spiffe-helper renewing it?") +
		       " - never sent";
	}
	return string();
}

} // namespace

bool ReadCredentialFile(const string &path, bool private_to_owner, bool trim, string &out, string &why) {
	Wipe(out);
#ifndef _WIN32
	// opened first, then checked on the descriptor: what is checked is what is read
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		why = "cannot read " + path;
		return false;
	}
	struct stat info;
	if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
		close(fd);
		why = path + " is not a file";
		return false;
	}
	// the SSH rule, as Kubernetes allows it: nobody else may read it, and a group may only read it (a pod's
	// fsGroup makes a secret volume 0440) - never write it
	if (private_to_owner && (info.st_mode & (S_IRWXO | S_IWGRP | S_IXGRP)) != 0) {
		close(fd);
		why = path + " may be read or written by others than its owner - chmod 600 (or 640/440 for a group of its "
		             "own, as a Kubernetes fsGroup mounts it)";
		return false;
	}
	if (size_t(info.st_size) > MAX_FILE_BYTES) {
		close(fd);
		why = path + " is larger than a key, a certificate or a token is";
		return false;
	}
	out.resize(size_t(info.st_size));
	size_t read_total = 0;
	while (read_total < out.size()) {
		auto n = read(fd, &out[read_total], out.size() - read_total);
		if (n <= 0) {
			break;
		}
		read_total += size_t(n);
	}
	close(fd);
	out.resize(read_total);
#else
	// no POSIX modes on Windows: the file's ACL is the operator's to set
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		why = "cannot read " + path;
		return false;
	}
	std::ostringstream content;
	content << file.rdbuf();
	out = content.str();
	if (out.size() > MAX_FILE_BYTES) {
		Wipe(out);
		why = path + " is larger than a key, a certificate or a token is";
		return false;
	}
#endif
	if (trim) {
		while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) {
			out.pop_back();
		}
	}
	if (out.empty()) {
		why = path + " is empty";
		return false;
	}
	return true;
}

void WipeAuth(oidc::ClientAuth &auth) {
	Wipe(auth.client_secret);
	Wipe(auth.private_key_pem);
	Wipe(auth.certificate_pem);
	Wipe(auth.assertion);
}

void ServiceCredential::CheckAccess(ClientContext &context) const {
	// DuckDB's own sandbox (enable_external_access, allowed_directories/paths): a file read_text() may not read
	// is not one a login may read and send to an identity provider either
	auto &config = DBConfig::GetConfig(context);
	for (auto *path : {&private_key_file, &certificate_file, &assertion_file, &token_file}) {
		if (!path->empty() && !config.CanAccessFile(*path, FileType::FILE_TYPE_REGULAR)) {
			throw PermissionException("tresor: %s is outside what this DuckDB may read (enable_external_access, "
			                          "allowed_directories)",
			                          *path);
		}
	}
}

//! Is a managed identity's token for the federation audience asked for? Azure's identity endpoints answer a v1 token
//! for `api://AzureADTokenExchange` whose `aud` is that application's app id instead - the same first-party app in
//! every tenant (checked live on Container Apps, specs/027), and Entra takes it as the assertion. Either form, for
//! that audience only.
static bool MeantForFederation(const vector<string> &audiences, const string &asked) {
	if (std::find(audiences.begin(), audiences.end(), asked) != audiences.end()) {
		return true;
	}
	static constexpr const char *TOKEN_EXCHANGE = "api://AzureADTokenExchange";
	static constexpr const char *TOKEN_EXCHANGE_APP_ID = "fb60f99c-7a34-4190-8149-302f77469936";
	return asked == TOKEN_EXCHANGE &&
	       std::find(audiences.begin(), audiences.end(), TOKEN_EXCHANGE_APP_ID) != audiences.end();
}

bool ServiceCredential::Auth(oidc::ClientAuth &auth, string &why) const {
	WipeAuth(auth);
	auth.client_id = client_id;
	auth.assertion_type.clear(); // set below only with an assertion: the OIDC core refuses a type without one
	switch (kind) {
	case Kind::SECRET:
		auth.client_secret = client_secret;
		return true;
	case Kind::PRIVATE_KEY:
		auth.key_id = key_id;
		if (!ReadCredentialFile(private_key_file, true, false, auth.private_key_pem, why)) {
			return false;
		}
		if (!certificate_file.empty() &&
		    !ReadCredentialFile(certificate_file, false, false, auth.certificate_pem, why)) {
			WipeAuth(auth);
			return false;
		}
		return true;
	case Kind::ASSERTION_FILE:
		// re-read every time: the platform rotates it (a Kubernetes projected token lives an hour)
		if (!ReadCredentialFile(assertion_file, false, true, auth.assertion, why)) {
			return false;
		}
		if (!JwtShaped(auth.assertion)) {
			WipeAuth(auth);
			why = assertion_file + " does not hold a token (a JWT) - never sent";
			return false;
		}
		auth.assertion_type = assertion_type;
		return true;
	case Kind::SPIFFE: {
		// a JWT-SVID (specs/046): re-read every time (spiffe-helper rotates it in minutes), and sent only when it is
		// the workload's, for this identity provider, and alive - an SVID is a credential wherever it is accepted
		if (!ReadCredentialFile(assertion_file, false, true, auth.assertion, why)) {
			return false;
		}
		why = SvidRefusal(auth.assertion, ReadJwtClaims(auth.assertion), assertion_file, spiffe_id, assertion_audience);
		if (!why.empty()) {
			WipeAuth(auth);
			return false;
		}
		auth.assertion_type = assertion_type;
		return true;
	}
	case Kind::GITHUB_ACTIONS: {
		auto token = oidc::GithubActionsToken(assertion_audience);
		if (!token.Ok()) {
			why = token.error;
			return false;
		}
		auth.assertion = std::move(token.access_token);
		return true;
	}
	case Kind::AZURE_MANAGED_IDENTITY_ASSERTION: {
		// the platform's token for the federation's audience is the app registration's client assertion
		// (specs/015) - asked for every time (the platform caches and rotates it), sent only when it is for
		// that audience
		oidc::ManagedIdentity identity;
		identity.resource = assertion_audience;
		identity.client_id = identity_client_id;
		auto token = oidc::ManagedIdentityToken(identity);
		if (!token.Ok()) {
			why = "the managed identity gave no assertion: " + token.error;
			return false;
		}
		bool is_jwt = false;
		auto audiences = JwtAudiences(token.access_token, is_jwt);
		if (!is_jwt || !MeantForFederation(audiences, assertion_audience)) {
			tresor::Wipe(token.access_token);
			why = "the managed identity's token is not meant for " + assertion_audience + " - not sent";
			return false;
		}
		auth.assertion = std::move(token.access_token);
		return true;
	}
	case Kind::MANAGED_IDENTITY:
		why = "a managed identity is no client at the identity provider";
		return false;
	case Kind::TOKEN_FILE:
		why = "a token is no client at the identity provider";
		return false;
	}
	return false;
}

oidc::TokenSet ServiceCredential::ReadToken() const {
	// the service's bearer token (specs/047): re-read at the login, before it expires and after a 401 (a platform
	// rotates it - spiffe-helper in minutes)
	string token;
	string why;
	if (!ReadCredentialFile(token_file, false, true, token, why)) {
		oidc::TokenSet out;
		out.error = why;
		return out;
	}
	return CheckToken(std::move(token));
}

oidc::TokenSet ServiceCredential::CheckToken(string token) const {
	// sent only when it is for this service - an IdP token goes only to its audience
	oidc::TokenSet out;
	out.access_token = std::move(token);
	auto claims = ReadJwtClaims(out.access_token);
	string why;
	if (!spiffe_id.empty() || StringUtil::StartsWith(claims.subject, "spiffe://")) {
		why = SvidRefusal(out.access_token, claims, token_file, spiffe_id, token_audience);
	} else if (claims.is_jwt) {
		if (token_audience.empty()) {
			why = token_file + " held no JWT at the login, and does now - never sent (ATTACH again)";
		} else if (!MeantFor(claims, token_audience)) {
			why = "the token in " + token_file + " is not meant for " + token_audience +
			      " (its aud: " + Shown(StringUtil::Join(claims.audiences, ", ")) + ") - never sent";
		} else if (claims.expires_at != 0 && claims.expires_at <= int64_t(std::time(nullptr))) {
			why = "the token in " + token_file + " has expired - is the platform renewing it? - never sent";
		}
	} else if (!token_audience.empty()) {
		// the login's was a JWT, checked: what is not one now (a torn write, another kind of token) is not sent
		// unchecked - the 401 retry reads the file again
		why = token_file + " held a JWT at the login, and does not now - never sent";
	}
	// a JWT names its issuer: the one the service listed and the login chose, or none (one issuer listed)
	if (why.empty() && claims.is_jwt && !claims.issuer.empty() &&
	    WithoutTrailingSlashes(claims.issuer) != WithoutTrailingSlashes(token_issuer)) {
		why = "the token in " + token_file + " is from " + Shown(claims.issuer) + ", not the issuer " + token_issuer +
		      " - never sent";
	}
	if (!why.empty()) {
		tresor::Wipe(out.access_token);
		out = oidc::TokenSet();
		out.error = why;
		return out;
	}
	out.expires_at = claims.expires_at;
	return out;
}

oidc::TokenSet ServiceCredential::Mint(const oidc::Endpoints &endpoints, const string &scope,
                                       const std::map<std::string, std::string> &extra) const {
	if (kind == Kind::TOKEN_FILE) {
		return ReadToken();
	}
	oidc::TokenSet out;
	if (kind == Kind::MANAGED_IDENTITY) {
		// the audience the secret names - never the service's own word for it (a service could name another
		// Azure resource the identity may reach, and receive its token)
		oidc::ManagedIdentity identity;
		identity.resource = audience;
		identity.client_id = client_id;
		out = oidc::ManagedIdentityToken(identity);
		if (out.Ok()) {
			bool is_jwt = false;
			auto audiences = JwtAudiences(out.access_token, is_jwt);
			if (!is_jwt || std::find(audiences.begin(), audiences.end(), audience) == audiences.end()) {
				tresor::Wipe(out.access_token);
				out = oidc::TokenSet();
				out.error = "the managed identity's token is not meant for " + audience + " - not sent";
			}
		}
		return out;
	}
	oidc::ClientAuth auth;
	string why;
	if (!Auth(auth, why)) {
		out.error = why;
		out.error_code = "invalid_client";
		return out;
	}
	out = oidc::ClientCredentials(endpoints, auth, scope, extra);
	WipeAuth(auth);
	return out;
}

string ServiceCredential::LoginName() const {
	switch (kind) {
	case Kind::PRIVATE_KEY:
		return "private_key_jwt";
	case Kind::ASSERTION_FILE:
	case Kind::SPIFFE:
	case Kind::GITHUB_ACTIONS:
	case Kind::AZURE_MANAGED_IDENTITY_ASSERTION:
		return "federated";
	case Kind::MANAGED_IDENTITY:
		return "managed_identity";
	case Kind::TOKEN_FILE:
		return "token";
	case Kind::SECRET:
		return "client_credentials";
	}
	return "client_credentials";
}

void ServiceCredential::Wipe() {
	tresor::Wipe(client_secret);
}

} // namespace tresor
} // namespace duckdb
