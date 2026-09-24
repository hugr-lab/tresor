#pragma once

#include "duckdb.hpp"

namespace duckdb {

class TresorExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
	std::string Version() const override;
};

//! The `tresor` secret type: a service's login (tresor_secret.cpp).
void RegisterTresorSecret(ExtensionLoader &loader);
//! tresor_secret_param(name, key): a secret's parameter as DuckDB holds it (tresor_secrets.cpp).
void RegisterTresorSecretParam(ExtensionLoader &loader);
//! tresor_logoff(...): forget a person's remembered login (tresor_logoff.cpp, specs/012).
void RegisterTresorLogoff(ExtensionLoader &loader);

} // namespace duckdb
