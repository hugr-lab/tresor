// What attachTresor needs of DuckDB-wasm: the parts of @duckdb/duckdb-wasm's AsyncDuckDB and its connection it
// calls, structurally - so any compatible object (a test's stub included) will do.

export interface QueryResult {
	toArray(): Array<Record<string, unknown>>;
}

export interface Statement {
	query(...params: unknown[]): Promise<QueryResult>;
	close(): Promise<void>;
}

export interface Connection {
	query(sql: string): Promise<QueryResult>;
	prepare(sql: string): Promise<Statement>;
	close(): Promise<void>;
}

export interface Database {
	connect(): Promise<Connection>;
	registerFileBuffer(name: string, buffer: Uint8Array): Promise<void>;
	dropFile?(name: string): Promise<unknown>;
}

/** A SQL string literal. */
export function literal(text: string): string {
	return "'" + text.replace(/'/g, "''") + "'";
}

/** A SQL identifier. */
export function identifier(text: string): string {
	return '"' + text.replace(/"/g, '""') + '"';
}
