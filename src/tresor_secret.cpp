#include "tresor_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"

// The `tresor` secret type (specs/002): how a SERVICE logs in to a secrets service. Found by the ATTACH
// path through its SCOPE ('tresor:<host>'), or named by ATTACH ... (SECRET name). People need no secret.

namespace duckdb {

namespace {

//! Which parameters each flow takes: a flow refuses the others' parameters, so a secret never carries
//! a credential it does not use.
const vector<string> &FlowParameters(const string &flow) {
	// ISSUER binds the client secret to its identity provider: the service's discovery never decides where
	// a service's credential is sent
	static const vector<string> client_credentials {"client_id", "client_secret", "issuer"};
	static const vector<string> token {"token"};
	if (flow == "client_credentials") {
		return client_credentials;
	}
	if (flow == "token") {
		return token;
	}
	throw InvalidInputException("tresor secret: FLOW is 'client_credentials' or 'token', not '%s'", flow);
}

unique_ptr<BaseSecret> CreateTresorSecret(ClientContext &context, CreateSecretInput &input) {
	auto flow_entry = input.options.find("flow");
	if (flow_entry == input.options.end()) {
		throw InvalidInputException("tresor secret: FLOW is required ('client_credentials' or 'token')");
	}
	auto flow = StringUtil::Lower(flow_entry->second.ToString());
	auto &required = FlowParameters(flow);
	for (auto &name : required) {
		auto entry = input.options.find(name);
		if (entry == input.options.end() || entry->second.IsNull() || entry->second.ToString().empty()) {
			throw InvalidInputException("tresor secret: FLOW '%s' needs %s", flow, StringUtil::Upper(name));
		}
	}
	for (auto &option : input.options) {
		auto key = StringUtil::Lower(option.first);
		auto shared = key == "flow" || (key == "oauth_scope" && flow == "client_credentials");
		auto own = std::find(required.begin(), required.end(), key) != required.end();
		if (!shared && !own) {
			throw InvalidInputException("tresor secret: FLOW '%s' does not take %s", flow,
			                            StringUtil::Upper(option.first));
		}
	}

	// a SCOPE is the service this credential is for: without one duckdb's lookup would offer it to every
	// ATTACH 'tresor:...', and a scope not in the ATTACH path's shape would match none
	auto scope = input.scope;
	if (scope.empty()) {
		throw InvalidInputException("tresor secret: SCOPE is required - the service it logs in to, "
		                            "'tresor:<host>[:port][/base]'");
	}
	for (auto &entry : scope) {
		if (!StringUtil::StartsWith(StringUtil::Lower(entry), "tresor:") || entry.size() <= 7) {
			throw InvalidInputException("tresor secret: SCOPE '%s' is not a service - 'tresor:<host>[:port][/base]'",
			                            entry);
		}
	}
	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	for (auto &option : input.options) {
		auto key = StringUtil::Lower(option.first);
		secret->secret_map[Identifier(key)] = key == "flow" ? Value(flow) : Value(option.second.ToString());
	}
	secret->redact_keys = {Identifier("client_secret"), Identifier("token")};
	return std::move(secret);
}

} // namespace

void RegisterTresorSecret(ExtensionLoader &loader) {
	SecretType type;
	type.name = Identifier("tresor");
	type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	type.default_provider = "config";
	type.extension = "tresor";
	loader.RegisterSecretType(type);

	CreateSecretFunction function;
	function.secret_type = "tresor";
	function.provider = Identifier("config");
	function.function = CreateTresorSecret;
	for (auto name : {"flow", "client_id", "client_secret", "token", "oauth_scope", "issuer"}) {
		function.named_parameters[name] = LogicalType::VARCHAR;
	}
	loader.RegisterFunction(function);
}

} // namespace duckdb
