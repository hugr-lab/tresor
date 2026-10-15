#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Secret types of an extension's own classes, for tresor's tests (specs/032): what bigquery does with
//! BigquerySecret, reduced to a cast.
class TypedSecretStubExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};

} // namespace duckdb
