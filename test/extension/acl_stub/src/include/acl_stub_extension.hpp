#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! duckdb-acl's side of the acl_connection contract, for tresor's tests (specs/008): opens and closes
//! sessions for the observers, and publishes a session on a connection's statements.
class AclStubExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};

} // namespace duckdb
