#include "tresor_http.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/http/http_util.hpp"
#include "duckdb/main/settings.hpp"

#include <cstdlib>

// tresor's requests - the IdP's and the service's - go through one transport (specs/020). Natively it is the
// OIDC core's own client unless `tresor_http_client` says `duckdb`; in wasm there are no sockets, so it is always
// DuckDB's HTTPUtil, which duckdb-wasm implements over the browser's XMLHttpRequest.

namespace duckdb {
namespace tresor {

namespace {

#ifdef __EMSCRIPTEN__
constexpr const char *DEFAULT_CLIENT = "duckdb";
#else
constexpr const char *DEFAULT_CLIENT = "builtin";
#endif

string ParseClient(const Value &value) {
	auto text = value.IsNull() ? string(DEFAULT_CLIENT) : StringUtil::Lower(value.ToString());
	if (text != "builtin" && text != "duckdb") {
		throw InvalidInputException("tresor_http_client is builtin or duckdb - not '%s'", value.ToString());
	}
#ifdef __EMSCRIPTEN__
	if (text == "builtin") {
		throw InvalidInputException("tresor_http_client: a wasm build has no client of its own - only duckdb");
	}
#endif
	return text;
}

void CheckClient(ClientContext &, SetScope, Value &parameter) {
	ParseClient(parameter);
}

oidc::HttpResult Send(DatabaseInstance &db, const string &method, const string &url,
                      const std::map<std::string, std::string> &headers, const string &body, const string &content_type,
                      int timeout_seconds) {
	oidc::HttpResult out;
	if (method == "PATCH") {
		// HTTPUtil has no PATCH (annotate_secret / annotate_variable): natively tresor's own client carries it - a
		// transport calling back into the OIDC core reaches the built-in client; in wasm there is none
#ifdef __EMSCRIPTEN__
		out.error = "DuckDB's HTTP client has no PATCH: annotating is not available in wasm";
		return out;
#else
		return oidc::HttpSend(method, url, headers, body, content_type, timeout_seconds);
#endif
	}
	try {
		auto &util = HTTPUtil::Get(db);
		// no opener: neither an `http` secret (a bearer token, extra headers) nor extra_http_headers is mixed in -
		// what tresor sends is exactly what it means to send, to the IdP above all
		auto params = util.InitializeParameters(nullptr, nullptr);
		params->timeout = timeout_seconds > 0 ? uint64_t(timeout_seconds) : HTTPParams::DEFAULT_TIMEOUT_SECONDS;
		params->retries = 0;             // tresor retries what it may (a 401 renews once), nothing else
		params->follow_location = false; // a followed 307 would re-send a secret to where it points
		params->logger = nullptr;        // DuckDB's HTTP log writes the request's headers: an Authorization
		params->extra_headers.clear();
		auto &proxy = db.config.options.http_proxy;
		if (!proxy.empty()) {
			auto proxy_value = proxy;
			HTTPUtil::ParseHTTPProxyHost(proxy_value, params->http_proxy, params->http_proxy_port);
			params->http_proxy_username = Settings::Get<HTTPProxyUsernameSetting>(db);
			params->http_proxy_password = Settings::Get<HTTPProxyPasswordSetting>(db);
		}
		HTTPHeaders request_headers;
		for (auto &header : headers) {
			request_headers.Insert(header.first, header.second);
		}
		if (!content_type.empty()) {
			request_headers.Insert("Content-Type", content_type);
		}
		auto data = const_data_ptr_cast(body.data());
		unique_ptr<HTTPResponse> response;
		string post_body;
		if (method == "GET") {
			GetRequestInfo info(url, request_headers, *params, nullptr, nullptr);
			info.try_request = true;
			response = util.Request(info);
		} else if (method == "POST") {
			PostRequestInfo info(url, request_headers, *params, data, body.size());
			info.try_request = true;
			response = util.Request(info);
			post_body = std::move(info.buffer_out); // a provider may answer a POST here instead of in the response
		} else if (method == "PUT") {
			PutRequestInfo info(url, request_headers, *params, data, body.size(), content_type);
			info.try_request = true;
			response = util.Request(info);
		} else if (method == "DELETE") {
			DeleteRequestInfo info(url, request_headers, *params);
			info.try_request = true;
			response = util.Request(info);
		} else {
			out.error = "DuckDB's HTTP client has no " + method;
			return out;
		}
		if (response->HasRequestError()) {
			out.error = response->GetRequestError();
			return out;
		}
		out.status = int(response->status);
		out.body = response->body.empty() ? std::move(post_body) : std::move(response->body);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		out.status = 0;
		out.error = error.RawMessage();
	}
	return out;
}

} // namespace

void RegisterHttpClient(DatabaseInstance &db) {
	// the default may come from the environment: TRESOR_HTTP_CLIENT=duckdb (a test suite run on DuckDB's client)
	auto from_env = std::getenv("TRESOR_HTTP_CLIENT");
	auto default_client = from_env && *from_env ? ParseClient(Value(from_env)) : string(DEFAULT_CLIENT);
	auto &config = DBConfig::GetConfig(db);
	config.AddExtensionOption("tresor_http_client",
	                          "tresor: the HTTP client of its requests - builtin (its own) or duckdb (DuckDB's, "
	                          "httpfs where loaded; the only one in wasm); the default from TRESOR_HTTP_CLIENT",
	                          LogicalType::VARCHAR, Value(default_client), CheckClient);
}

oidc::Transport DuckDBTransport(const shared_ptr<DatabaseInstance> &db) {
	weak_ptr<DatabaseInstance> weak = db;
	return [weak](const std::string &method, const std::string &url, const std::map<std::string, std::string> &headers,
	              const std::string &body, const std::string &content_type, int timeout_seconds) {
		auto held = weak.lock();
		if (!held) {
			oidc::HttpResult gone;
			gone.error = "the database is closed";
			return gone;
		}
		return Send(*held, method, url, headers, body, content_type, timeout_seconds);
	};
}

oidc::Transport TransportFor(ClientContext &context) {
	Value value;
	string client = DEFAULT_CLIENT;
	if (context.TryGetCurrentSetting(Identifier("tresor_http_client"), value)) {
		client = ParseClient(value);
	}
	if (client == "builtin") {
		return nullptr;
	}
#ifndef __EMSCRIPTEN__
	// natively DuckDB's own client is GET-only: httpfs is what makes it one tresor can use (loaded as an http path
	// would load it, under the instance's autoload settings); duckdb-wasm's is complete without it
	auto has_client = [&]() {
		auto name = HTTPUtil::Get(*context.db).GetName();
		return name != "none" && name != "Built-In";
	};
	if (!has_client() && !(ExtensionHelper::TryAutoLoadExtension(*context.db, "httpfs") && has_client())) {
		throw InvalidInputException("tresor_http_client = 'duckdb' needs httpfs: INSTALL httpfs; LOAD httpfs");
	}
#endif
	return DuckDBTransport(context.db);
}

} // namespace tresor
} // namespace duckdb
