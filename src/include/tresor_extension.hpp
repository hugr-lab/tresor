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

} // namespace duckdb
