#define DUCKDB_EXTENSION_MAIN

#include "tresor_extension.hpp"

#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// An extension that builds tresor into itself (specs/024), as hugr-node's hugr_node does: its entry is the one main,
// tresor's whole load is LoadTresorCore, and its own part registers beside it.
//
//   LOAD '.../tresor_embedder.duckdb_extension';
//   ATTACH 'tresor:...';  SELECT tresor_version();  SELECT tresor_embedder_probe();

#ifndef TRESOR_EMBEDDED
#error "tresor_configure_targets defines TRESOR_EMBEDDED on an embedder's targets"
#endif

namespace duckdb {

// Traps for what TRESOR_EMBEDDED leaves out of tresor: were tresor's TresorExtension compiled in, its members and
// this class's would be the same symbols, and the loadable would not link - on GNU ld (the Linux CI job) and
// link.exe; Apple's linker lets the duplicate pass under -dead_strip
class TresorExtension {
public:
	std::string Name();
};
std::string TresorExtension::Name() {
	return "tresor_embedder";
}

namespace {

void ProbeFun(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value("embedder"), count_t(args.size()));
}

} // namespace
} // namespace duckdb

extern "C" {

// ... and were tresor's entry point compiled in, this one would be defined twice
DUCKDB_EXTENSION_API void tresor_duckdb_cpp_init(duckdb::ExtensionLoader &loader) {
	throw duckdb::InternalException("tresor_embedder: tresor's own entry point is not this extension's");
}

DUCKDB_CPP_EXTENSION_ENTRY(tresor_embedder, loader) {
	duckdb::LoadTresorCore(loader);
	loader.RegisterFunction(duckdb::ScalarFunction(duckdb::Identifier("tresor_embedder_probe"), {},
	                                               duckdb::LogicalType::VARCHAR, duckdb::ProbeFun));
}
}
