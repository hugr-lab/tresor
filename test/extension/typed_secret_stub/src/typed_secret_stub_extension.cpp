#include "typed_secret_stub_extension.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

// Secret types whose extension casts what a lookup finds to a class of its own, as bigquery casts to
// BigquerySecret (specs/032):
//
//   CREATE SECRET s (TYPE typed_stub, PROJECT 'p', TOKEN 't', SCOPE 'stub://one');
//   SELECT typed_stub_project('s');            -- by name, cast to StubSecret: its PROJECT
//   SELECT typed_stub_lookup('stub://one/x');  -- by path, the same
//   CREATE SECRET o (TYPE opaque_stub, ...);   -- a type whose deserializer reads a layout of its own
//   SELECT opaque_stub_class('o');             -- 'OpaqueSecret', or 'KeyValueSecret' as served from elsewhere

namespace duckdb {

namespace {

class StubSecret : public KeyValueSecret {
public:
	StubSecret(const vector<string> &scope, const Identifier &type, const Identifier &provider, const Identifier &name)
	    : KeyValueSecret(scope, type, provider, name) {
		redact_keys = {Identifier("token")};
	}
	explicit StubSecret(const BaseSecret &base) : KeyValueSecret(base) {
		redact_keys = {Identifier("token")};
	}
	unique_ptr<const BaseSecret> Clone() const override {
		return make_uniq<StubSecret>(*this);
	}
};

class OpaqueSecret : public KeyValueSecret {
public:
	using KeyValueSecret::KeyValueSecret;
	explicit OpaqueSecret(const BaseSecret &base) : KeyValueSecret(base) {
	}
	unique_ptr<const BaseSecret> Clone() const override {
		return make_uniq<OpaqueSecret>(*this);
	}
};

//! A layout of its own: nothing a key-value secret's serialization holds can be read by it.
unique_ptr<BaseSecret> DeserializeOpaque(Deserializer &deserializer, BaseSecret base) {
	throw SerializationException("opaque_stub: not a layout this type reads");
}

template <class SECRET>
unique_ptr<BaseSecret> CreateStub(ClientContext &context, CreateSecretInput &input) {
	auto secret = make_uniq<SECRET>(input.scope, input.type, input.provider, input.name);
	for (auto &option : input.options) {
		secret->secret_map[Identifier(StringUtil::Lower(option.first))] = option.second;
	}
	return std::move(secret);
}

void RegisterStubType(ExtensionLoader &loader, const char *name, secret_deserializer_t deserializer,
                      create_secret_function_t create) {
	SecretType type;
	type.name = Identifier(name);
	type.deserializer = deserializer;
	type.default_provider = "config";
	type.extension = "typed_secret_stub";
	loader.RegisterSecretType(type);
	CreateSecretFunction function = {name, Identifier("config"), create};
	function.named_parameters[Identifier("project")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("token")] = LogicalType::VARCHAR;
	loader.RegisterFunction(function);
}

string ProjectOf(const BaseSecret &secret) {
	// what bigquery does: a reference cast, std::bad_cast for any other class
	auto &stub = dynamic_cast<const StubSecret &>(secret);
	auto project = stub.secret_map.find(Identifier("project"));
	return project == stub.secret_map.end() ? string() : project->second.ToString();
}

void ProjectFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto name = args.data[0].GetValue(0).ToString();
	auto entry = SecretManager::Get(context).GetSecretByName(transaction, name);
	if (!entry) {
		throw InvalidInputException("typed_stub_project: no secret named '%s'", name);
	}
	result.Reference(Value(ProjectOf(*entry->secret)), count_t(args.size()));
}

void LookupFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto path = args.data[0].GetValue(0).ToString();
	auto match = SecretManager::Get(context).LookupSecret(transaction, path, "typed_stub");
	if (!match.HasMatch()) {
		throw InvalidInputException("typed_stub_lookup: no secret for '%s'", path);
	}
	result.Reference(Value(ProjectOf(match.GetSecret())), count_t(args.size()));
}

void OpaqueClassFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto name = args.data[0].GetValue(0).ToString();
	auto entry = SecretManager::Get(context).GetSecretByName(transaction, name);
	if (!entry) {
		throw InvalidInputException("opaque_stub_class: no secret named '%s'", name);
	}
	auto &secret = *entry->secret;
	string kind = dynamic_cast<const OpaqueSecret *>(&secret)     ? "OpaqueSecret"
	              : dynamic_cast<const KeyValueSecret *>(&secret) ? "KeyValueSecret"
	                                                              : "BaseSecret";
	result.Reference(Value(kind), count_t(args.size()));
}

void RegisterScalar(ExtensionLoader &loader, const char *name, scalar_function_t function) {
	ScalarFunction fun(Identifier(name), {LogicalType::VARCHAR}, LogicalType::VARCHAR, function);
	fun.SetVolatile();
	fun.SetFallible();
	loader.RegisterFunction(fun);
}

} // namespace

void TypedSecretStubExtension::Load(ExtensionLoader &loader) {
	RegisterStubType(loader, "typed_stub", KeyValueSecret::Deserialize<StubSecret>, CreateStub<StubSecret>);
	RegisterStubType(loader, "opaque_stub", DeserializeOpaque, CreateStub<OpaqueSecret>);
	RegisterScalar(loader, "typed_stub_project", ProjectFun);
	RegisterScalar(loader, "typed_stub_lookup", LookupFun);
	RegisterScalar(loader, "opaque_stub_class", OpaqueClassFun);
}

std::string TypedSecretStubExtension::Name() {
	return "typed_secret_stub";
}

std::string TypedSecretStubExtension::Version() const {
	return "test";
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(typed_secret_stub, loader) {
	duckdb::TypedSecretStubExtension extension;
	extension.Load(loader);
}
}
