#include "tresor_login.hpp"

#include <algorithm>

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/printer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "yyjson.hpp"

#include <cctype>
#include <chrono>

// The attach's login (specs/002): the service's discovery names the identity provider; the login is
// directly with it (never through the service); the service's whoami proves the token is accepted.

namespace duckdb {
namespace tresor {

using namespace duckdb_yyjson; // NOLINT

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

string Str(yyjson_val *obj, const char *key) {
	auto value = obj && yyjson_is_obj(obj) ? yyjson_obj_get(obj, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : "";
}

//! The strings of an array member; `present` tells an empty list from a missing one.
vector<string> StrList(yyjson_val *obj, const char *key, bool *present = nullptr) {
	vector<string> out;
	auto value = obj && yyjson_is_obj(obj) ? yyjson_obj_get(obj, key) : nullptr;
	if (present) {
		*present = value && yyjson_is_arr(value);
	}
	if (value && yyjson_is_arr(value)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(value, idx, max, item) {
			if (yyjson_is_str(item)) {
				out.emplace_back(yyjson_get_str(item));
			}
		}
	}
	return out;
}

bool Contains(const vector<string> &list, const string &value) {
	return std::find(list.begin(), list.end(), value) != list.end();
}

string StripSlashes(string url) {
	while (!url.empty() && url.back() == '/') {
		url.pop_back();
	}
	return url;
}

//! The host part of host[:port][/base] (brackets of an IPv6 literal removed).
string HostName(const string &host) {
	auto authority = host.substr(0, host.find('/'));
	if (!authority.empty() && authority[0] == '[') {
		auto close = authority.find(']');
		return close == string::npos ? authority : authority.substr(1, close - 1);
	}
	return authority.substr(0, authority.find(':'));
}

//! The host of an absolute URL, for the loopback check of what discovery points at.
string UrlHost(const string &url) {
	auto scheme = url.find("://");
	return scheme == string::npos ? "" : HostName(url.substr(scheme + 3));
}

bool IsLoopbackName(const string &name) {
	return name == "127.0.0.1" || name == "::1" || StringUtil::CIEquals(name, "localhost");
}

//! An endpoint the discovery named: https, or http to loopback when the user explicitly allowed it.
void CheckTransport(const AttachRequest &request, const string &what, const string &url) {
	if (url.rfind("https://", 0) == 0) {
		return;
	}
	if (url.rfind("http://", 0) == 0 && request.insecure_http && IsLoopbackName(UrlHost(url))) {
		return;
	}
	throw InvalidInputException("tresor: the %s of %s is not https (%s) - refused", what, request.host, url);
}

struct Discovered {
	string api;
	unordered_map<string, bool> capabilities;
	struct Issuer {
		string issuer;
		string client_id;
		string audience;
		vector<string> scopes;
		vector<string> human_flows; // when present (even empty), a client attempts no others (protocol)
		vector<string> service_flows;
		bool has_human_flows = false;
		bool has_service_flows = false;

		bool OffersHuman(const char *flow) const {
			return !has_human_flows || Contains(human_flows, flow);
		}
		bool OffersService(const char *flow) const {
			return !has_service_flows || Contains(service_flows, flow);
		}
	};
	vector<Issuer> issuers;
};

Discovered Discover(const AttachRequest &request, string &discovery_url) {
	discovery_url = (request.insecure_http ? "http://" : "https://") + request.host + "/.well-known/duckdb-secrets";
	auto response = oidc::HttpGet(discovery_url);
	if (!response.error.empty()) {
		throw IOException("tresor: discovery of %s failed: %s", request.host, response.error);
	}
	if (response.status != 200) {
		throw IOException("tresor: discovery of %s answered HTTP %d - is it a duckdb-secrets service?", request.host,
		                  response.status);
	}
	JsonDoc json(response.body);
	auto root = json.Root();
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("tresor: the discovery document of %s is not a JSON object", request.host);
	}
	auto protocol = Str(root, "protocol");
	if (protocol != "duckdb-secrets/1") {
		throw InvalidInputException("tresor: %s speaks \"%s\", this client speaks duckdb-secrets/1", request.host,
		                            protocol);
	}
	Discovered out;
	out.api = StripSlashes(Str(root, "api"));
	auto capabilities = yyjson_obj_get(root, "capabilities");
	if (capabilities && yyjson_is_obj(capabilities)) {
		size_t cidx, cmax;
		yyjson_val *ckey, *cvalue;
		yyjson_obj_foreach(capabilities, cidx, cmax, ckey, cvalue) {
			out.capabilities[yyjson_get_str(ckey)] = yyjson_is_true(cvalue);
		}
	}
	if (out.api.empty()) {
		throw IOException("tresor: the discovery document of %s names no api", request.host);
	}
	CheckTransport(request, "api", out.api);
	auto issuers = yyjson_obj_get(root, "issuers");
	if (issuers && yyjson_is_arr(issuers)) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(issuers, idx, max, item) {
			Discovered::Issuer issuer;
			issuer.issuer = StripSlashes(Str(item, "issuer"));
			issuer.client_id = Str(item, "client_id");
			issuer.audience = Str(item, "audience");
			issuer.scopes = StrList(item, "scopes");
			issuer.human_flows = StrList(item, "human_flows", &issuer.has_human_flows);
			issuer.service_flows = StrList(item, "service_flows", &issuer.has_service_flows);
			if (!issuer.issuer.empty()) {
				out.issuers.push_back(std::move(issuer));
			}
		}
	}
	if (out.issuers.empty()) {
		throw IOException("tresor: the discovery document of %s lists no issuers", request.host);
	}
	return out;
}

const Discovered::Issuer &ChooseIssuer(const AttachRequest &request, const Discovered &discovered,
                                       const string &asked) {
	if (!asked.empty()) {
		for (auto &issuer : discovered.issuers) {
			if (issuer.issuer == StripSlashes(asked)) {
				return issuer;
			}
		}
	} else if (discovered.issuers.size() == 1) {
		return discovered.issuers[0];
	}
	vector<string> listed;
	for (auto &issuer : discovered.issuers) {
		listed.push_back("'" + issuer.issuer + "'");
	}
	if (!asked.empty()) {
		throw InvalidInputException("tresor: %s does not accept the issuer '%s' - it lists %s", request.host, asked,
		                            StringUtil::Join(listed, ", "));
	}
	// several issuers and none named: which identity to log in with is the user's decision, not list order
	throw InvalidInputException("tresor: %s accepts several identity providers - name one with ISSUER: %s",
	                            request.host, StringUtil::Join(listed, ", "));
}

//! Does a secret's SCOPE cover the ATTACH path at a host boundary: the path itself, a path under it
//! ('/'), or - for a scope that names no port - the same host on any port (':'). A plain prefix would
//! let 'tresor:secrets.corp' cover 'tresor:secrets.corp.attacker.net' and hand it the credential.
//! Compared case-insensitively, like host names.
bool ScopeCovers(const string &scope_p, const string &path_p) {
	auto scope = StringUtil::Lower(StripSlashes(scope_p));
	auto path = StringUtil::Lower(path_p);
	if (!StringUtil::StartsWith(scope, "tresor:") || scope.size() <= 7 || !StringUtil::StartsWith(path, scope)) {
		return false;
	}
	if (path.size() == scope.size() || path[scope.size()] == '/') {
		return true;
	}
	if (path[scope.size()] != ':') {
		return false;
	}
	auto authority = scope.substr(7);
	if (authority.find('/') != string::npos) {
		return false;
	}
	auto bracket = authority.rfind(']');
	return authority.find(':', bracket == string::npos ? 0 : bracket) == string::npos;
}

unique_ptr<KeyValueSecret> AsTresorSecret(const BaseSecret &secret, const string &name) {
	auto key_value = dynamic_cast<const KeyValueSecret *>(&secret);
	if (secret.GetType() != Identifier("tresor") || !key_value) {
		throw InvalidInputException("tresor: the secret '%s' is of type %s, not tresor", name,
		                            secret.GetType().GetIdentifierName());
	}
	return make_uniq<KeyValueSecret>(*key_value);
}

//! The service's login, read from a `tresor` secret: the one ATTACH named, or the one whose SCOPE covers
//! the path most specifically. Null when there is none - a person logs in. Two secrets equally specific
//! are an error: which credential to present is not a guess.
unique_ptr<KeyValueSecret> FindServiceSecret(ClientContext &context, const AttachRequest &request) {
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	if (!request.secret_name.empty()) {
		auto entry = manager.GetSecretByName(transaction, request.secret_name);
		if (!entry) {
			throw InvalidInputException("tresor: no secret named '%s'", request.secret_name);
		}
		return AsTresorSecret(*entry->secret, request.secret_name);
	}
	auto path = "tresor:" + request.host;
	optional_ptr<const BaseSecret> best;
	idx_t best_length = 0;
	bool tie = false;
	auto secrets = manager.AllSecrets(transaction);
	for (auto &entry : secrets) {
		if (entry.secret->GetType() != Identifier("tresor")) {
			continue;
		}
		// an unscoped secret covers nothing here (duckdb's own lookup would let it cover everything)
		for (auto &scope : entry.secret->GetScope()) {
			if (!ScopeCovers(scope, path)) {
				continue;
			}
			if (scope.size() > best_length) {
				best = entry.secret.get();
				best_length = scope.size();
				tie = false;
			} else if (scope.size() == best_length && best.get() != entry.secret.get()) {
				tie = true;
			}
		}
	}
	if (tie) {
		throw InvalidInputException("tresor: several tresor secrets cover '%s' equally - name one with SECRET", path);
	}
	return best ? AsTresorSecret(*best, best->GetName().GetIdentifierName()) : nullptr;
}

string SecretString(const KeyValueSecret &secret, const char *key) {
	auto value = secret.TryGetValue(Identifier(key));
	return value.IsNull() ? "" : value.ToString();
}

oidc::TokenSet PersonLogin(ClientContext &context, const AttachRequest &request, const ServiceInfo &info,
                           const Discovered::Issuer &issuer, LoginFlow &flow) {
	auto browser_possible = !info.endpoints.authorization_endpoint.empty() && issuer.OffersHuman("authorization_code");
	auto device_possible = !info.endpoints.device_authorization_endpoint.empty() && issuer.OffersHuman("device_code");
	switch (request.mode) {
	case LoginMode::BROWSER:
		if (!browser_possible) {
			throw InvalidInputException("tresor: the identity provider of %s offers no browser login", request.host);
		}
		flow = LoginFlow::BROWSER;
		break;
	case LoginMode::DEVICE:
		if (!device_possible) {
			throw InvalidInputException("tresor: the identity provider of %s offers no device login", request.host);
		}
		flow = LoginFlow::DEVICE;
		break;
	case LoginMode::AUTO:
		if (browser_possible && (CanOpenBrowser() || !device_possible)) {
			flow = LoginFlow::BROWSER;
		} else if (device_possible) {
			flow = LoginFlow::DEVICE;
		} else {
			throw InvalidInputException("tresor: the identity provider of %s offers neither a browser nor a device "
			                            "login for people - a service logs in with a tresor secret",
			                            request.host);
		}
		break;
	}
	auto deadline = NowSeconds() + request.timeout_seconds;
	auto cancelled = [&context] {
		return context.IsInterrupted();
	};
	oidc::TokenSet tokens;
	if (flow == LoginFlow::BROWSER) {
		tokens = oidc::AuthorizationCodeLogin(
		    info.endpoints, info.client_id, info.scope,
		    [&](const std::string &url) {
			    Printer::Print(OutputStream::STREAM_STDERR, "tresor: log in to " + request.host +
			                                                    " in your browser - if it did not open, visit:\n  " +
			                                                    url);
			    OpenBrowser(url);
		    },
		    deadline, cancelled);
	} else {
		auto begun = oidc::DeviceBegin(info.endpoints, info.client_id, info.scope);
		if (!begun.Ok()) {
			throw IOException("tresor: the device login to %s could not start: %s", request.host, begun.error);
		}
		auto where = begun.verification_uri_complete.empty() ? begun.verification_uri : begun.verification_uri_complete;
		Printer::Print(OutputStream::STREAM_STDERR,
		               "tresor: to log in to " + request.host + ", visit " + begun.verification_uri +
		                   " and enter the code " + begun.user_code +
		                   (where == begun.verification_uri ? "" : "\n  or open " + where));
		auto device_deadline = MinValue<int64_t>(deadline, NowSeconds() + begun.expires_in);
		tokens = oidc::DevicePoll(info.endpoints, info.client_id, begun.device_code, begun.interval, device_deadline,
		                          cancelled);
	}
	if (!tokens.Ok()) {
		if (tokens.error_code == "cancelled") {
			throw InterruptException();
		}
		throw InvalidInputException("tresor: the %s login to %s failed: %s", LoginFlowName(flow), request.host,
		                            tokens.error);
	}
	return tokens;
}

} // namespace

JsonDoc::JsonDoc(const string &body, yyjson_read_flag flags) {
	doc = yyjson_read(body.data(), body.size(), flags);
}

JsonDoc::~JsonDoc() {
	if (doc) {
		yyjson_doc_free(doc);
	}
}

yyjson_val *JsonDoc::Root() const {
	return doc ? yyjson_doc_get_root(doc) : nullptr;
}

bool IsLoopbackHost(const string &host) {
	return IsLoopbackName(HostName(host));
}

AttachRequest ParseAttach(const string &path, const unordered_map<string, Value> &options) {
	AttachRequest request;
	auto host = path;
	if (StringUtil::StartsWith(StringUtil::Lower(host), "tresor:")) {
		host = host.substr(7);
	}
	host = StripSlashes(host);
	if (host.empty()) {
		throw InvalidInputException("tresor: ATTACH needs the service - 'tresor:<host>[:port][/base]'");
	}
	if (host.find("://") != string::npos) {
		throw InvalidInputException("tresor: name the service without a scheme - 'tresor:<host>[:port][/base]', "
		                            "https is implied");
	}
	// nothing that could make a URL mean another host than the one the checks below looked at
	for (char c : host) {
		if (c == '@' || c == '?' || c == '#' || c == '\\' || std::isspace(static_cast<unsigned char>(c)) ||
		    static_cast<unsigned char>(c) < 0x20) {
			throw InvalidInputException("tresor: '%s' is not a service name - 'tresor:<host>[:port][/base]'", host);
		}
	}
	request.host = host;
	bool actor_option_given = false;
	for (auto &option : options) {
		auto key = StringUtil::Lower(option.first);
		auto &value = option.second;
		if (key == "login") {
			request.mode_given = true;
			auto mode = StringUtil::Lower(value.ToString());
			if (mode == "auto") {
				request.mode = LoginMode::AUTO;
			} else if (mode == "browser") {
				request.mode = LoginMode::BROWSER;
			} else if (mode == "device") {
				request.mode = LoginMode::DEVICE;
			} else {
				throw InvalidInputException("tresor: LOGIN is 'auto', 'browser' or 'device', not '%s'",
				                            value.ToString());
			}
		} else if (key == "issuer") {
			request.issuer = value.ToString();
		} else if (key == "secret") {
			request.secret_name = value.ToString();
		} else if (key == "insecure_http") {
			request.insecure_http = BooleanValue::Get(value.DefaultCastAs(LogicalType::BOOLEAN));
		} else if (key == "login_timeout") {
			request.timeout_seconds = BigIntValue::Get(value.DefaultCastAs(LogicalType::BIGINT));
			if (request.timeout_seconds <= 0) {
				throw InvalidInputException("tresor: LOGIN_TIMEOUT is a positive number of seconds");
			}
		} else if (key == "act_for_sessions") {
			request.act_for_sessions = BooleanValue::Get(value.DefaultCastAs(LogicalType::BOOLEAN));
		} else if (key == "exchange") {
			actor_option_given = true;
			auto kind = StringUtil::Lower(value.ToString());
			if (kind != "token_exchange" && kind != "on_behalf_of") {
				throw InvalidInputException("tresor: EXCHANGE is 'token_exchange' or 'on_behalf_of', not '%s'",
				                            value.ToString());
			}
			request.on_behalf_of = kind == "on_behalf_of";
		} else if (key == "exchange_scope") {
			actor_option_given = true;
			request.exchange_scope = value.ToString();
		} else if (key == "exchange_audience") {
			actor_option_given = true;
			request.exchange_audience = value.ToString();
		} else if (key == "session_grant_wait") {
			actor_option_given = true;
			request.grant_wait_seconds = BigIntValue::Get(value.DefaultCastAs(LogicalType::BIGINT));
			if (request.grant_wait_seconds < 0 || request.grant_wait_seconds > 600) {
				throw InvalidInputException("tresor: SESSION_GRANT_WAIT is 0 to 600 seconds");
			}
		} else {
			throw InvalidInputException("tresor: unknown ATTACH option '%s' (known: LOGIN, ISSUER, SECRET, "
			                            "INSECURE_HTTP, LOGIN_TIMEOUT, ACT_FOR_SESSIONS, EXCHANGE, EXCHANGE_SCOPE, "
			                            "EXCHANGE_AUDIENCE, SESSION_GRANT_WAIT)",
			                            option.first);
		}
	}
	if (!request.act_for_sessions && actor_option_given) {
		throw InvalidInputException("tresor: EXCHANGE, EXCHANGE_SCOPE, EXCHANGE_AUDIENCE and SESSION_GRANT_WAIT "
		                            "configure ACT_FOR_SESSIONS - set it too");
	}
	if (request.act_for_sessions && request.mode_given) {
		throw InvalidInputException("tresor: ACT_FOR_SESSIONS is for a node's service login (SECRET of flow "
		                            "client_credentials), not a person's LOGIN");
	}
	if (request.on_behalf_of && request.exchange_scope.empty()) {
		throw InvalidInputException("tresor: EXCHANGE 'on_behalf_of' needs EXCHANGE_SCOPE (the service's "
		                            "api://.../.default)");
	}
	if (request.mode_given && !request.secret_name.empty()) {
		throw InvalidInputException("tresor: LOGIN is how a person logs in and SECRET how a service does - not both");
	}
	if (request.insecure_http && !IsLoopbackHost(request.host)) {
		throw InvalidInputException("tresor: INSECURE_HTTP is for a service on this machine only (127.0.0.1, ::1, "
		                            "localhost), not '%s'",
		                            request.host);
	}
	return request;
}

string DescribeProblem(int status, const string &body) {
	JsonDoc json(body);
	auto root = json.Root();
	auto type = Str(root, "type");
	auto detail = Str(root, "detail");
	if (detail.empty()) {
		detail = Str(root, "title");
	}
	string out = "HTTP " + std::to_string(status);
	if (!type.empty()) {
		out += " " + type;
	}
	if (!detail.empty()) {
		// the service's words, bounded: a service is responsible for keeping values out of them (the
		// reference server does), the client for not letting a long echo run on
		out += ": " + (detail.size() > 200 ? detail.substr(0, 200) + "..." : detail);
	}
	return out;
}

vector<string> JwtAudiences(const string &token, bool &is_jwt) {
	is_jwt = false;
	vector<string> out;
	auto first = token.find('.');
	auto second = first == string::npos ? string::npos : token.find('.', first + 1);
	if (second == string::npos) {
		return out;
	}
	// base64url, no padding
	string payload;
	uint32_t buffer = 0;
	int bits = 0;
	for (auto c : token.substr(first + 1, second - first - 1)) {
		int value;
		if (c >= 'A' && c <= 'Z') {
			value = c - 'A';
		} else if (c >= 'a' && c <= 'z') {
			value = c - 'a' + 26;
		} else if (c >= '0' && c <= '9') {
			value = c - '0' + 52;
		} else if (c == '-' || c == '+') {
			value = 62;
		} else if (c == '_' || c == '/') {
			value = 63;
		} else if (c == '=') {
			break;
		} else {
			return out;
		}
		buffer = (buffer << 6) | uint32_t(value);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			payload.push_back(char((buffer >> bits) & 0xff));
		}
	}
	JsonDoc doc(payload);
	auto root = doc.Root();
	if (!root || !yyjson_is_obj(root)) {
		return out;
	}
	is_jwt = true;
	auto aud = yyjson_obj_get(root, "aud");
	if (aud && yyjson_is_str(aud)) {
		out.emplace_back(yyjson_get_str(aud));
	}
	out = aud && yyjson_is_arr(aud) ? StrList(root, "aud") : out;
	return out;
}

shared_ptr<TresorSession> Login(ClientContext &context, const AttachRequest &request) {
	ServiceInfo info;
	info.host = request.host;
	info.insecure_http = request.insecure_http;
	auto discovered = Discover(request, info.discovery);
	info.api = discovered.api;
	info.capabilities = discovered.capabilities;

	// a LOGIN given is a person asking to log in as themselves: no secret is looked up for them
	auto service_secret = request.mode_given ? nullptr : FindServiceSecret(context, request);
	if (request.act_for_sessions &&
	    (!service_secret || StringUtil::Lower(SecretString(*service_secret, "flow")) != "client_credentials")) {
		// refused before any login: a headless node must not sit in a browser or device flow first
		throw InvalidInputException("tresor: ACT_FOR_SESSIONS needs a service login - a SECRET of flow "
		                            "client_credentials");
	}
	LoginFlow flow;
	oidc::TokenSet tokens;
	string client_secret;
	if (service_secret && StringUtil::Lower(SecretString(*service_secret, "flow")) == "token") {
		// a token already held: no identity provider is involved, the service alone judges it
		flow = LoginFlow::TOKEN;
		tokens.access_token = SecretString(*service_secret, "token");
	} else {
		auto asked_issuer = request.issuer;
		if (service_secret) {
			// the credential is bound to the IdP the secret names (required at CREATE SECRET): the
			// service's discovery never decides where a client secret is sent
			auto bound = SecretString(*service_secret, "issuer");
			if (!asked_issuer.empty() && StripSlashes(asked_issuer) != StripSlashes(bound)) {
				throw InvalidInputException("tresor: ISSUER '%s' is not the issuer the secret is bound to ('%s')",
				                            asked_issuer, bound);
			}
			asked_issuer = bound;
		}
		auto &issuer = ChooseIssuer(request, discovered, asked_issuer);
		CheckTransport(request, "issuer", issuer.issuer);
		info.issuer = issuer.issuer;
		info.audience = issuer.audience;
		info.endpoints = oidc::Discover(issuer.issuer);
		if (!info.endpoints.Ok()) {
			throw IOException("tresor: the identity provider %s of %s: %s", issuer.issuer, request.host,
			                  info.endpoints.error);
		}
		for (auto *endpoint : {&info.endpoints.token_endpoint, &info.endpoints.authorization_endpoint,
		                       &info.endpoints.device_authorization_endpoint}) {
			if (!endpoint->empty()) {
				CheckTransport(request, "identity provider endpoint", *endpoint);
			}
		}
		if (service_secret) {
			flow = LoginFlow::CLIENT_CREDENTIALS;
			if (!issuer.OffersService("client_credentials")) {
				throw InvalidInputException("tresor: %s does not accept client_credentials logins", request.host);
			}
			info.client_id = SecretString(*service_secret, "client_id");
			info.scope = SecretString(*service_secret, "oauth_scope");
			if (info.scope.empty()) {
				vector<string> scopes;
				for (auto &scope : issuer.scopes) {
					if (scope != "openid" && scope != "offline_access") { // no use to a client-credentials grant
						scopes.push_back(scope);
					}
				}
				info.scope = StringUtil::Join(scopes, " ");
			}
			client_secret = SecretString(*service_secret, "client_secret");
			tokens = oidc::ClientCredentials(info.endpoints, info.client_id, client_secret, info.scope);
			if (!tokens.Ok()) {
				throw InvalidInputException("tresor: the client_credentials login to %s failed: %s", request.host,
				                            tokens.error);
			}
		} else {
			info.client_id = issuer.client_id;
			if (info.client_id.empty()) {
				throw IOException("tresor: %s names no client_id for people to log in with", request.host);
			}
			info.scope = StringUtil::Join(issuer.scopes, " ");
			tokens = PersonLogin(context, request, info, issuer, flow);
		}
	}

	if (request.act_for_sessions) {
		// the exchange is made as the node's own client: only a client_credentials login has one
		if (flow != LoginFlow::CLIENT_CREDENTIALS) {
			throw InvalidInputException("tresor: ACT_FOR_SESSIONS needs a service login - a SECRET of flow "
			                            "client_credentials");
		}
		// the audience users' tokens are exchanged for is the node's to decide, not the service's: pinned by
		// EXCHANGE_AUDIENCE, or the discovery's - only when the node's own token, which the IdP issued for this
		// login, is meant for it too. A service (or whoever alters its discovery) never picks where tokens go
		if (!request.exchange_audience.empty()) {
			info.audience = request.exchange_audience;
		} else if (!info.audience.empty() && !request.on_behalf_of) {
			bool is_jwt = false;
			auto own = JwtAudiences(tokens.access_token, is_jwt);
			if (std::find(own.begin(), own.end(), info.audience) == own.end()) {
				throw InvalidInputException("tresor: %s names the audience '%s', which the node's own token is not "
				                            "issued for - set EXCHANGE_AUDIENCE to the audience users' tokens are "
				                            "to be exchanged for",
				                            request.host, info.audience);
			}
		}
		if (request.on_behalf_of) {
			info.audience.clear(); // On-Behalf-Of targets its scope
		}
		if (info.audience.empty() && request.exchange_scope.empty()) {
			throw InvalidInputException("tresor: %s names no audience for its issuer, and no EXCHANGE_AUDIENCE or "
			                            "EXCHANGE_SCOPE was given - nothing to exchange a session's token for",
			                            request.host);
		}
	}
	auto session = make_shared_ptr<TresorSession>(std::move(info), flow, std::move(tokens), std::move(client_secret));
	// the login is proven only when the service accepts it: fail closed at ATTACH, not at first use
	auto whoami = session->Call("GET", "/v1/whoami");
	if (whoami.status != 200) {
		session->Close();
		throw InvalidInputException("tresor: %s refused the login: %s", request.host,
		                            DescribeProblem(whoami.status, whoami.body));
	}
	return session;
}

} // namespace tresor
} // namespace duckdb
