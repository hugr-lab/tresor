#include "tresor_credentials.hpp"
#include "tresor_actor.hpp"
#include "tresor_login.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"

#include <algorithm>
#include <cctype>
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
	for (auto *path : {&private_key_file, &certificate_file, &assertion_file}) {
		if (!path->empty() && !config.CanAccessFile(*path, FileType::FILE_TYPE_REGULAR)) {
			throw PermissionException("tresor: %s is outside what this DuckDB may read (enable_external_access, "
			                          "allowed_directories)",
			                          *path);
		}
	}
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
		if (!ReadCredentialFile(assertion_file, false, true, auth.assertion, why)) {
			return false;
		}
		if (!JwtShaped(auth.assertion)) {
			WipeAuth(auth);
			why = assertion_file + " does not hold a token (a JWT) - never sent";
			return false;
		}
		return true;
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
                                       const std::map<std::string, std::string> &extra) const {
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
	case Kind::GITHUB_ACTIONS:
		return "federated";
	case Kind::MANAGED_IDENTITY:
		return "managed_identity";
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
