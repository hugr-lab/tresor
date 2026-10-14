#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! specs/024: tresor's whole load - the ATTACH type, the secret type, every tresor_* function and setting - for
//! tresor's own entry point and for an extension that builds tresor into itself (hugr-node's hugr_node), whose
//! entry calls it. Under TRESOR_EMBEDDED tresor's entry point and TresorExtension are not compiled.
void LoadTresorCore(ExtensionLoader &loader);

//! tresor's version, as tresor_version() and the User-Agent say it - tresor's own when built into another extension
std::string TresorVersion();

#ifndef TRESOR_EMBEDDED
class TresorExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
	std::string Version() const override;
};
#endif

//! The `tresor` secret type: a service's login (tresor_secret.cpp).
void RegisterTresorSecret(ExtensionLoader &loader);
//! tresor_secret_param(name, key): a secret's parameter as DuckDB holds it (tresor_secrets.cpp).
void RegisterTresorSecretParam(ExtensionLoader &loader);
//! tresor_logoff(...): forget a person's remembered login (tresor_logoff.cpp, specs/012).
void RegisterTresorLogoff(ExtensionLoader &loader);
//! tresor_web_login (specs/020): a login a web page made, handed over
void RegisterTresorWebLogin(ExtensionLoader &loader);
//! tresor_login (specs/025): a person's login answered at once, completed in the background
void RegisterTresorLogin(ExtensionLoader &loader);

} // namespace duckdb
