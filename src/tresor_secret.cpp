#include "tresor_extension.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "tresor_storage.hpp"

// The `tresor` secret type (specs/002): how a SERVICE logs in to a secrets service. Found by the ATTACH
// path through its SCOPE ('tresor:<host>'), or named by ATTACH ... (SECRET name). People need no secret.

namespace duckdb {

namespace {

//! Which parameters each flow takes (specs/002, 013): a flow refuses the others' parameters, so a secret never
//! carries a credential it does not use. ISSUER binds the credential to its identity provider: the service's
//! discovery never decides where a service's credential is sent.
struct FlowRule {
	vector<string> required;
	vector<vector<string>> one_of; // exactly one of each group
	vector<string> optional;
};

const FlowRule &RuleOf(const string &flow) {
	static const FlowRule client_credentials {{"client_id", "issuer"},
	                                          {{"client_secret", "private_key_file"}},
	                                          {"oauth_scope", "key_id", "certificate_file"}};
	static const FlowRule federated {
	    {"client_id", "issuer"}, {{"assertion_file", "assertion_source"}}, {"oauth_scope", "assertion_audience"}};
	static const FlowRule managed_identity {{"issuer", "audience"}, {}, {"client_id"}};
	static const FlowRule token {{"token"}, {}, {}};
	if (flow == "client_credentials") {
		return client_credentials;
	}
	if (flow == "federated") {
		return federated;
	}
	if (flow == "managed_identity") {
		return managed_identity;
	}
	if (flow == "token") {
		return token;
	}
	throw InvalidInputException("tresor secret: FLOW is 'client_credentials', 'federated', 'managed_identity' or "
	                            "'token', not '%s'",
	                            flow);
}

unique_ptr<BaseSecret> CreateTresorSecret(ClientContext &context, CreateSecretInput &input) {
	auto flow_entry = input.options.find("flow");
	if (flow_entry == input.options.end()) {
		throw InvalidInputException("tresor secret: FLOW is required ('client_credentials', 'federated', "
		                            "'managed_identity' or 'token')");
	}
	auto flow = StringUtil::Lower(flow_entry->second.ToString());
	auto &rule = RuleOf(flow);
	auto given = [&](const string &name) {
		auto entry = input.options.find(name);
		return entry != input.options.end() && !entry->second.IsNull() && !entry->second.ToString().empty();
	};
	auto value = [&](const string &name) {
		return given(name) ? input.options.find(name)->second.ToString() : string();
	};
	for (auto &name : rule.required) {
		if (!given(name)) {
			throw InvalidInputException("tresor secret: FLOW '%s' needs %s", flow, StringUtil::Upper(name));
		}
	}
	for (auto &group : rule.one_of) {
		idx_t count = 0;
		for (auto &name : group) {
			count += given(name) ? 1 : 0;
		}
		if (count != 1) {
			throw InvalidInputException("tresor secret: FLOW '%s' needs exactly one of %s", flow,
			                            StringUtil::Upper(StringUtil::Join(group, ", ")));
		}
	}
	for (auto &option : input.options) {
		auto key = StringUtil::Lower(option.first);
		auto listed = [&](const vector<string> &names) {
			return std::find(names.begin(), names.end(), key) != names.end();
		};
		bool known = key == "flow" || listed(rule.required) || listed(rule.optional);
		for (auto &group : rule.one_of) {
			known = known || listed(group);
		}
		if (!known) {
			throw InvalidInputException("tresor secret: FLOW '%s' does not take %s", flow,
			                            StringUtil::Upper(option.first));
		}
	}
	// a key's companions come with the key only; GitHub's token needs the audience the federation expects
	if ((given("key_id") || given("certificate_file")) && !given("private_key_file")) {
		throw InvalidInputException("tresor secret: KEY_ID and CERTIFICATE_FILE go with PRIVATE_KEY_FILE");
	}
	if (given("assertion_source")) {
		if (StringUtil::Lower(value("assertion_source")) != "github_actions") {
			throw InvalidInputException("tresor secret: ASSERTION_SOURCE is 'github_actions', not '%s'",
			                            value("assertion_source"));
		}
		if (!given("assertion_audience")) {
			throw InvalidInputException("tresor secret: ASSERTION_SOURCE 'github_actions' needs ASSERTION_AUDIENCE "
			                            "(what the identity provider's federation expects, e.g. "
			                            "api://AzureADTokenExchange)");
		}
	} else if (given("assertion_audience")) {
		throw InvalidInputException("tresor secret: ASSERTION_AUDIENCE goes with ASSERTION_SOURCE");
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

//! The tresor provider of s3 / r2 / gcs (specs/006): httpfs's REFRESH auto re-creates a dynamic service
//! secret through it, IN the service's storage, with the options of its refresh_info. It fetches fresh
//! material from the service; its StoreSecret is a refresh, not a write.
unique_ptr<BaseSecret> CreateTresorProvided(ClientContext &context, CreateSecretInput &input) {
	auto option = [&](const char *name) {
		auto entry = input.options.find(name);
		if (entry == input.options.end() || entry->second.IsNull()) {
			throw InvalidInputException("tresor provider: %s is required", StringUtil::Upper(name));
		}
		return entry->second.ToString();
	};
	auto service = option("tresor_service");
	auto name = option("tresor_secret");
	// the secret is created under its own name (httpfs's refresh passes it): TRESOR_SECRET names the same
	if (!StringUtil::CIEquals(input.name.GetIdentifierName(), name)) {
		throw InvalidInputException("tresor provider: the secret is %s, but TRESOR_SECRET names %s",
		                            input.name.GetIdentifierName(), name);
	}
	// service material stays in the service's own storage: never memory, never a file on disk
	if (!StringUtil::CIEquals(input.storage_type.GetIdentifierName(), service)) {
		throw InvalidInputException("tresor provider: a secret of the service %s is created only IN %s", service,
		                            service);
	}
	auto storage = tresor::FindStorage(context, service);
	if (!storage) {
		throw InvalidInputException("tresor provider: %s is not an attached tresor service", service);
	}
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto fresh = storage->RefreshMaterial(name, &transaction);
	if (!StringUtil::CIEquals(fresh->GetType().GetIdentifierName(), input.type.GetIdentifierName())) {
		throw InvalidInputException("tresor provider: the secret %s of %s is of type %s, not %s", name, service,
		                            fresh->GetType().GetIdentifierName(), input.type.GetIdentifierName());
	}
	auto key_value = dynamic_cast<const KeyValueSecret *>(fresh.get());
	if (!key_value) {
		throw InternalException("tresor provider: service material is not a key-value secret");
	}
	return make_uniq<KeyValueSecret>(*key_value);
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
	for (auto name :
	     {"flow", "client_id", "client_secret", "token", "oauth_scope", "issuer", "private_key_file", "key_id",
	      "certificate_file", "assertion_file", "assertion_source", "assertion_audience", "audience"}) {
		function.named_parameters[name] = LogicalType::VARCHAR;
	}
	loader.RegisterFunction(function);

	// the S3-family types are httpfs's: duckdb checks a type at CREATE, not here, so httpfs may load later
	for (auto type : {"s3", "r2", "gcs", "aws"}) { // httpfs's S3SecretConfig::SecretTypes()
		CreateSecretFunction provided;
		provided.secret_type = type;
		provided.provider = Identifier("tresor");
		provided.function = CreateTresorProvided;
		provided.named_parameters["tresor_service"] = LogicalType::VARCHAR;
		provided.named_parameters["tresor_secret"] = LogicalType::VARCHAR;
		loader.RegisterFunction(provided);
	}
}

} // namespace duckdb
