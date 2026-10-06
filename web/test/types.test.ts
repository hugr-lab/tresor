// DuckDB-wasm's own objects are what a page passes: the helper's structural types must accept them (a type error
// here fails `tsc`, before any test runs).
import type { AsyncDuckDB, AsyncDuckDBConnection } from "@duckdb/duckdb-wasm";
import { it } from "node:test";

import type { Connection, Database } from "../src/duckdb.js";

export function asDatabase(db: AsyncDuckDB): Database {
	return db;
}

export function asConnection(conn: AsyncDuckDBConnection): Connection {
	return conn;
}

it("AsyncDuckDB and its connection are what attachTresor takes", () => {});
