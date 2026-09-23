#include "tresor_login.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/printer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "yyjson.hpp"

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

//! One parsed JSON document; the accessors return empty on anything of the wrong shape.
struct JsonDoc {
	yyjson_doc *doc = nullptr;
	explicit JsonDoc(const string &body) {
		doc = yyjson_read(body.data(), body.size(), 0);
	}
	~JsonDoc() {
		if (doc) {
			yyjson_doc_free(doc);
		}
	}
	yyjson_val *Root() const {
		return doc ? yyjson_doc_get_root(doc) : nullptr;
	}
};

string Str(yyjson_val *obj, const char *key) {
	auto value = obj && yyjson_is_obj(obj) ? yyjson_obj_get(obj, key) : nullptr;
	return value && yyjson_is_str(value) ? yyjson_get_str(value) : "";
}

vector<string> StrList(yyjson_val *obj, const char *key) {
	vector<string> out;
	auto value = obj && yyjson_is_obj(obj) ? yyjson_obj_get(obj, key) : nullptr;
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
	struct Issuer {
		string issuer;
		string client_id;
		vector<string> scopes;
		vector<string> human_flows;
		vector<string> service_flows;
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
			issuer.scopes = StrList(item, "scopes");
			issuer.human_flows = StrList(item, "human_flows");
			issuer.service_flows = StrList(item, "service_flows");
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

//! The service's login, read from a `tresor` secret: the one ATTACH named, or the one whose scope
//! matches the path. Null when there is none - a person logs in.
unique_ptr<KeyValueSecret> FindServiceSecret(ClientContext &context, const AttachRequest &request) {
	auto &manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	unique_ptr<const BaseSecret> secret;
	if (!request.secret_name.empty()) {
		auto entry = manager.GetSecretByName(transaction, request.secret_name);
		if (!entry) {
			throw InvalidInputException("tresor: no secret named '%s'", request.secret_name);
		}
		secret = std::move(entry->secret);
	} else {
		auto match = manager.LookupSecret(transaction, "tresor:" + request.host, "tresor");
		if (!match.HasMatch()) {
			return nullptr;
		}
		secret = match.GetSecret().Clone();
	}
	if (secret->GetType() != Identifier("tresor")) {
		throw InvalidInputException("tresor: the secret '%s' is of type %s, not tresor", request.secret_name,
		                            secret->GetType().GetIdentifierName());
	}
	return make_uniq<KeyValueSecret>(dynamic_cast<const KeyValueSecret &>(*secret));
}

string SecretString(const KeyValueSecret &secret, const char *key) {
	auto value = secret.TryGetValue(Identifier(key));
	return value.IsNull() ? "" : value.ToString();
}

oidc::TokenSet PersonLogin(ClientContext &context, const AttachRequest &request, const ServiceInfo &info,
                           const Discovered::Issuer &issuer, LoginFlow &flow) {
	auto offers = [&](const char *name) {
		return issuer.human_flows.empty() || Contains(issuer.human_flows, name);
	};
	auto browser_possible = !info.endpoints.authorization_endpoint.empty() && offers("authorization_code");
	auto device_possible = !info.endpoints.device_authorization_endpoint.empty() && offers("device_code");
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
	request.host = host;
	for (auto &option : options) {
		auto key = StringUtil::Lower(option.first);
		auto &value = option.second;
		if (key == "login") {
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
		} else {
			throw InvalidInputException("tresor: unknown ATTACH option '%s' (known: LOGIN, ISSUER, SECRET, "
			                            "INSECURE_HTTP, LOGIN_TIMEOUT)",
			                            option.first);
		}
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
		out += ": " + detail;
	}
	return out;
}

shared_ptr<TresorSession> Login(ClientContext &context, const AttachRequest &request) {
	ServiceInfo info;
	info.host = request.host;
	info.insecure_http = request.insecure_http;
	auto discovered = Discover(request, info.discovery);
	info.api = discovered.api;

	auto service_secret = FindServiceSecret(context, request);
	auto asked_issuer = request.issuer;
	if (asked_issuer.empty() && service_secret) {
		asked_issuer = SecretString(*service_secret, "issuer");
	}
	auto &issuer = ChooseIssuer(request, discovered, asked_issuer);
	CheckTransport(request, "issuer", issuer.issuer);
	info.issuer = issuer.issuer;
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

	LoginFlow flow;
	oidc::TokenSet tokens;
	string client_secret;
	if (service_secret) {
		auto flow_name = StringUtil::Lower(SecretString(*service_secret, "flow"));
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
		if (flow_name == "token") {
			flow = LoginFlow::TOKEN;
			tokens.access_token = SecretString(*service_secret, "token");
		} else {
			flow = LoginFlow::CLIENT_CREDENTIALS;
			if (!issuer.service_flows.empty() && !Contains(issuer.service_flows, "client_credentials")) {
				throw InvalidInputException("tresor: %s does not accept client_credentials logins", request.host);
			}
			client_secret = SecretString(*service_secret, "client_secret");
			tokens = oidc::ClientCredentials(info.endpoints, info.client_id, client_secret, info.scope);
			if (!tokens.Ok()) {
				throw InvalidInputException("tresor: the client_credentials login to %s failed: %s", request.host,
				                            tokens.error);
			}
		}
	} else {
		info.client_id = issuer.client_id;
		if (info.client_id.empty()) {
			throw IOException("tresor: %s names no client_id for people to log in with", request.host);
		}
		info.scope = StringUtil::Join(issuer.scopes, " ");
		tokens = PersonLogin(context, request, info, issuer, flow);
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
