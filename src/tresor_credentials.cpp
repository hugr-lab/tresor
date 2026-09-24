#include "tresor_credentials.hpp"
#include "tresor_actor.hpp"
#include "tresor_login.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

// A service login's proof (specs/013). Nothing here logs; no error names a key's, a token's or a secret's
// content - only the path and what is wrong with it.

namespace duckdb {
namespace tresor {

bool ReadCredentialFile(const string &path, bool private_to_owner, bool trim, string &out, string &why) {
	Wipe(out);
#ifndef _WIN32
	struct stat info;
	if (stat(path.c_str(), &info) != 0) {
		why = "cannot read " + path;
		return false;
	}
	if (!S_ISREG(info.st_mode)) {
		why = path + " is not a file";
		return false;
	}
	if (private_to_owner && (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		// the SSH rule: a key others may read is not a key only this service holds
		why = path + " may be read by others than its owner - chmod 600 (Kubernetes: defaultMode 0400)";
		return false;
	}
#endif
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		why = "cannot read " + path;
		return false;
	}
	std::ostringstream content;
	content << file.rdbuf();
	out = content.str();
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

bool ServiceCredential::Auth(oidc::ClientAuth &auth, string &why) const {
	WipeAuth(auth);
	auth.client_id = client_id;
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
		return ReadCredentialFile(assertion_file, false, true, auth.assertion, why);
	case Kind::GITHUB_ACTIONS: {
		auto token = oidc::GithubActionsToken(assertion_audience);
		if (!token.Ok()) {
			why = token.error;
			return false;
		}
		auth.assertion = std::move(token.access_token);
		return true;
	}
	case Kind::MANAGED_IDENTITY:
		why = "a managed identity is no client at the identity provider";
		return false;
	}
	return false;
}

oidc::TokenSet ServiceCredential::Mint(const oidc::Endpoints &endpoints, const string &scope,
                                       const std::map<std::string, std::string> &extra, const string &resource) const {
	oidc::TokenSet out;
	if (kind == Kind::MANAGED_IDENTITY) {
		if (resource.empty()) {
			out.error = "the service names no audience for a managed identity's token (the discovery's audience)";
			return out;
		}
		oidc::ManagedIdentity identity;
		identity.resource = resource;
		identity.client_id = client_id;
		out = oidc::ManagedIdentityToken(identity);
		if (out.Ok()) {
			// a token the platform minted goes to the service only if it is meant for it
			bool is_jwt = false;
			auto audiences = JwtAudiences(out.access_token, is_jwt);
			if (is_jwt && std::find(audiences.begin(), audiences.end(), resource) == audiences.end()) {
				tresor::Wipe(out.access_token);
				out = oidc::TokenSet();
				out.error = "the managed identity's token is not meant for " + resource + " - not sent";
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

void ServiceCredential::Wipe() {
	tresor::Wipe(client_secret);
}

} // namespace tresor
} // namespace duckdb
