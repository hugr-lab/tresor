#include "tresor_session.hpp"

#include "duckdb/common/exception.hpp"

#include <chrono>

namespace duckdb {
namespace tresor {

namespace {

//! A token with less life than this is renewed before a call rather than sent to die on the way.
constexpr int64_t RENEW_MARGIN_SECONDS = 60;

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

} // namespace

string LoginFlowName(LoginFlow flow) {
	switch (flow) {
	case LoginFlow::BROWSER:
		return "browser";
	case LoginFlow::DEVICE:
		return "device";
	case LoginFlow::CLIENT_CREDENTIALS:
		return "client_credentials";
	case LoginFlow::TOKEN:
		return "token";
	}
	return "unknown";
}

TresorSession::TresorSession(ServiceInfo info_p, LoginFlow flow_p, oidc::TokenSet tokens_p, string client_secret_p)
    : info(std::move(info_p)), flow(flow_p), tokens(std::move(tokens_p)), client_secret(std::move(client_secret_p)) {
}

string TresorSession::AccessToken(bool force) {
	if (closed) {
		throw InvalidInputException("tresor: the session to %s is closed (DETACHed)", info.host);
	}
	auto fresh = tokens.expires_at == 0 || tokens.expires_at - RENEW_MARGIN_SECONDS > NowSeconds();
	if (fresh && !force) {
		return tokens.access_token;
	}
	oidc::TokenSet renewed;
	switch (flow) {
	case LoginFlow::BROWSER:
	case LoginFlow::DEVICE:
		if (tokens.refresh_token.empty()) {
			throw InvalidInputException("tresor: the login to %s has expired and the identity provider issued no "
			                            "refresh token - log in again: DETACH and ATTACH",
			                            info.host);
		}
		renewed = oidc::RefreshGrant(info.endpoints, info.client_id, "", tokens.refresh_token);
		if (renewed.Ok() && renewed.refresh_token.empty()) {
			renewed.refresh_token = tokens.refresh_token; // RFC 6749 §6: a refresh may keep the old one
		}
		break;
	case LoginFlow::CLIENT_CREDENTIALS:
		renewed = oidc::ClientCredentials(info.endpoints, info.client_id, client_secret, info.scope);
		break;
	case LoginFlow::TOKEN:
		throw InvalidInputException("tresor: the token of the tresor secret for %s has expired or was refused - "
		                            "replace the secret and ATTACH again",
		                            info.host);
	}
	if (!renewed.Ok()) {
		if (renewed.error_code == "invalid_grant") {
			// the refresh chain is dead (revoked, expired, rotated elsewhere): only a new login helps
			tokens = oidc::TokenSet();
			throw InvalidInputException("tresor: the login to %s is over (%s) - log in again: DETACH and ATTACH",
			                            info.host, renewed.error);
		}
		throw IOException("tresor: renewing the login to %s failed: %s", info.host, renewed.error);
	}
	tokens = std::move(renewed);
	return tokens.access_token;
}

ServiceResponse TresorSession::Call(const string &method, const string &path, const string &body) {
	lock_guard<mutex> guard(lock);
	for (int attempt = 0; attempt < 2; attempt++) {
		auto token = AccessToken(attempt > 0);
		std::map<std::string, std::string> headers {{"Authorization", "Bearer " + token},
		                                            {"Accept", "application/json"}};
		auto result = oidc::HttpSend(method, info.api + path, headers, body, body.empty() ? "" : "application/json");
		if (!result.error.empty()) {
			throw IOException("tresor: %s %s failed: %s", method, info.api + path, result.error);
		}
		if (result.status == 401 && attempt == 0) {
			continue; // the protocol's rule: refresh and retry once
		}
		ServiceResponse out;
		out.status = result.status;
		out.body = std::move(result.body);
		return out;
	}
	throw InvalidInputException("tresor: %s refused the renewed login (401) - log in again: DETACH and ATTACH",
	                            info.host);
}

void TresorSession::Close() {
	lock_guard<mutex> guard(lock);
	closed = true;
	tokens = oidc::TokenSet();
	client_secret.clear();
}

} // namespace tresor
} // namespace duckdb
