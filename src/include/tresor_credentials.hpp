//===----------------------------------------------------------------------===//
// tresor_credentials.hpp - how a service login proves itself (specs/002, 013)
//
// What a `tresor` secret names, never what it reads: a client secret (as the secret holds it), or the paths of
// a private key and certificate, or a federated token's file or source, or the Azure platform's own identity.
// Files are read at the moment of use - every mint, every exchange - and wiped after; nothing read is kept.
//===----------------------------------------------------------------------===//

#pragma once

#include "oidc_core.hpp"

#include "duckdb/common/common.hpp"

namespace duckdb {
class ClientContext;

namespace tresor {

struct ServiceCredential {
	enum class Kind : uint8_t { SECRET, PRIVATE_KEY, ASSERTION_FILE, GITHUB_ACTIONS, MANAGED_IDENTITY };

	Kind kind = Kind::SECRET;
	string client_id;
	string client_secret;      // SECRET
	string private_key_file;   // PRIVATE_KEY
	string key_id;             // PRIVATE_KEY, optional
	string certificate_file;   // PRIVATE_KEY, optional
	string assertion_file;     // ASSERTION_FILE
	string assertion_audience; // GITHUB_ACTIONS
	string audience;           // MANAGED_IDENTITY: the resource its token is for - the secret's, never the service's

	//! The client's proof for one request (a key's and a token's files read now). The caller wipes it.
	bool Auth(oidc::ClientAuth &auth, string &why) const;
	//! A token for the service: client credentials, or - a managed identity - the platform's token for the
	//! secret's `audience`, which must name it.
	oidc::TokenSet Mint(const oidc::Endpoints &endpoints, const string &scope,
	                    const std::map<std::string, std::string> &extra) const;
	//! Refused (PermissionException) when a file it names is outside DuckDB's sandbox for `context`.
	void CheckAccess(ClientContext &context) const;
	//! What whoami and the audit call the login: client_credentials, private_key_jwt, federated, managed_identity.
	string LoginName() const;
	//! Can it act for duckdb-acl's sessions: a confidential client at the IdP (not a managed identity).
	bool ExchangesTokens() const {
		return kind != Kind::MANAGED_IDENTITY;
	}
	void Wipe();
};

//! Read a file the credential names. `private_to_owner`: refused when group or others may read it (a key); a
//! federated token file is short-lived and audience-bound, and platforms mount it readable. Trailing whitespace
//! is dropped for a token.
bool ReadCredentialFile(const string &path, bool private_to_owner, bool trim, string &out, string &why);

//! Overwrite a ClientAuth's secrets.
void WipeAuth(oidc::ClientAuth &auth);

} // namespace tresor
} // namespace duckdb
