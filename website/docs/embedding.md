---
sidebar_position: 3.75
title: In your application
---

# tresor in your application

Any program that embeds DuckDB 2.0 can use tresor the same way the CLI does: Python, Go, Rust and Java (JDBC) today,
.NET and a web page (DuckDB-wasm) as their packages reach 2.0. It loads tresor, logs in once and attaches the secrets
service. From then on its
queries find the right secret by scope (`FROM 's3://lake/…'`) or by name (`ATTACH '…' (TYPE postgres, SECRET crm)`), and nothing secret lives in the
application's configuration.

```sql
INSTALL tresor FROM community;     -- once per machine (or ship the extension with the application)
LOAD tresor;
-- a login (below), then:
ATTACH 'tresor:secrets.corp.example' AS corp;
```

DuckDB loads an extension only into the exact DuckDB version it was built for, so the application's DuckDB package must
be 2.0:

| Language | Package on DuckDB 2.0 |
| --- | --- |
| Python | `duckdb` 2.0.0 |
| Go | `github.com/duckdb/duckdb-go/v2` v2.20000.0 |
| Rust | `duckdb` crate 1.20000.0, linked to DuckDB's `libduckdb` 2.0.0 (not `bundled`, below) |
| Java / JVM | `org.duckdb:duckdb_jdbc` 2.0.0.0 |
| .NET | DuckDB.NET: not yet on 2.0 (1.5.x); the code below waits for it |
| Browser | DuckDB-wasm on 2.0: not on npm yet, see [In a web application](./web.md) |

## Which login

| Who uses the application | The login | |
| --- | --- | --- |
| A person, on their own machine (a desktop tool, a notebook) | `ATTACH` opens the browser once. The login is remembered in the OS keychain, so the next process of the same person asks nothing. | [From DuckDB UI, Python and IDEs](./clients.md) |
| A person the application has already logged in (it holds their OIDC tokens) | The application hands tresor its **access token** for the service, and each renewed one: `tresor_web_token`. No second login. | below |
| The application itself (a job, a service, a backend's own data) | Its own identity: a `tresor` secret with `FLOW 'client_credentials'`, `'federated'` (Kubernetes, GitHub Actions) or `'managed_identity'`. | [Pipelines](./pipelines.md) |
| A server that queries for many users | Each user's query runs with that user's rights: a [duckdb-acl](https://github.com/hugr-lab/duckdb-acl) node with `ACT_FOR_SESSIONS`, or one DuckDB instance per user with that user's token. Never one attached catalog shared by many users. | [Acting for users](./concepts.md#acting-for-users) |

## The application's own login: `tresor_web_token`

The application already logs its user in with the organisation's identity provider (MSAL, an OIDC library, the
platform's sign-in). It asks for a token the secrets service accepts, whose `aud` is the `audience` of the service's
discovery. Then it passes that token to tresor:

- **as a parameter** of a prepared statement, never in the SQL text (and so never in a query log);
- **again on each renewal** (the OIDC library's refresh event): the attached catalog uses the newest from its next
  query. tresor never renews the token, and the application's refresh token never reaches it;
- **to one DuckDB instance per user**: the token is kept in that instance's memory, for that service.

A JWT for another audience or issuer, or one already expired, is refused and never sent; an opaque token is taken as
the application's word. When a token of another user arrives, the catalog empties itself of everything held for the
previous one. When the user logs out, call `FROM tresor_logoff('corp')`: it forgets the token and detaches `corp`
(`detach := false` keeps the catalog for the next token). `corp.whoami()` reports the login as `page`.

Hand over a valid token **before** the `ATTACH`: an ATTACH with no valid token for the service (none yet, or an expired
one) is a person's login instead - in a backend, a browser that never opens. A backend sets `LOGIN` nowhere: an ATTACH
that names a login mode logs a person in and ignores the token.

The examples below are the whole flow; `token` comes from the application's login.

### Python

```python
import duckdb

con = duckdb.connect()
con.execute("INSTALL tresor FROM community")
con.execute("LOAD tresor")
service = "tresor:secrets.corp.example"
con.execute("FROM tresor_web_token(?, ?)", [service, token])      # and again with each renewed token
con.execute(f"ATTACH '{service}' AS corp")

print(con.execute("SELECT login, name FROM corp.whoami()").fetchone())
lake = con.execute("FROM 's3://lake/sales/*.parquet' LIMIT 10").fetchall()
```

### Go

```go
import (
	"database/sql"

	_ "github.com/duckdb/duckdb-go/v2"
)

db, err := sql.Open("duckdb", "")
// a plain SET is per connection, and database/sql pools them: one connection keeps settings in one place
db.SetMaxOpenConns(1)
_, err = db.Exec("INSTALL tresor FROM community")
_, err = db.Exec("LOAD tresor")
service := "tresor:secrets.corp.example"
_, err = db.Exec("FROM tresor_web_token(?, ?)", service, token) // and again with each renewed token
_, err = db.Exec("ATTACH '" + service + "' AS corp")

var login, name string
err = db.QueryRow("SELECT login, name FROM corp.whoami()").Scan(&login, &name)
```

### Rust

Link the crate to the `libduckdb` of DuckDB's v2.0.0 release (`duckdb-shared-libs-<platform>.tar.gz`):
`DUCKDB_LIB_DIR=<dir> cargo build`, without the `bundled` feature. A `bundled` build compiles DuckDB without its
release tag and reports the version `d54cbbe3df`, not `v2.0.0`. It then refuses every extension built for v2.0.0, the
community repository's included.

```rust
use duckdb::{params, Connection};

let conn = Connection::open_in_memory()?;
conn.execute_batch("INSTALL tresor FROM community; LOAD tresor;")?;
let service = "tresor:secrets.corp.example";
// a table function: run it as a query (and again with each renewed token)
conn.prepare("FROM tresor_web_token(?, ?)")?.query(params![service, token])?.next()?;
conn.execute_batch(&format!("ATTACH '{service}' AS corp"))?;

let (login, name): (String, String) =
    conn.query_row("SELECT login, name FROM corp.whoami()", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
```

### Java (JDBC)

```java
import java.sql.*;

try (Connection conn = DriverManager.getConnection("jdbc:duckdb:");
     Statement st = conn.createStatement()) {
    st.execute("INSTALL tresor FROM community");
    st.execute("LOAD tresor");
    String service = "tresor:secrets.corp.example";
    try (PreparedStatement hand = conn.prepareStatement("FROM tresor_web_token(?, ?)")) {   // and on each renewal
        hand.setString(1, service);
        hand.setString(2, token);
        hand.executeQuery().close();
    }
    st.execute("ATTACH '" + service + "' AS corp");
    try (ResultSet rs = st.executeQuery("SELECT login, name FROM corp.whoami()")) {
        rs.next();
    }
}
```

### .NET

For DuckDB.NET on DuckDB 2.0 (not released yet):

```csharp
using DuckDB.NET.Data;

using var conn = new DuckDBConnection("DataSource=:memory:");
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "INSTALL tresor FROM community; LOAD tresor;";
cmd.ExecuteNonQuery();

cmd.CommandText = "FROM tresor_web_token($service, $token)";      // and again with each renewed token
cmd.Parameters.Add(new DuckDBParameter("service", "tresor:secrets.corp.example"));
cmd.Parameters.Add(new DuckDBParameter("token", accessToken));
cmd.ExecuteNonQuery();
cmd.Parameters.Clear();

cmd.CommandText = "ATTACH 'tresor:secrets.corp.example' AS corp";
cmd.ExecuteNonQuery();
```

### In the browser

A page that embeds DuckDB-wasm does the same with the helper `attachTresor` (`token`, `onTokenChange`), which also
loads tresor with its signature checked. See [In a web application](./web.md#the-applications-token).

## Notes for an application

- **A backend process** keeps no person's login. Run `SET tresor_keychain = 'off'` (or `'memory'`) so nothing reaches
  the machine's credential store.
- **The extension**: `INSTALL tresor FROM community` downloads it once into DuckDB's extension directory. An
  application can ship the extension file with itself and `LOAD '<path>'` instead. Only signed extensions load unless
  `allow_unsigned_extensions` is set, so ship the community build, not a development one.
- **Renewals**: an expired or refused token makes queries on `corp` fail with *the page's token … has expired or was
  refused - the page hands over a new one*. Hand tresor the new token, not a new ATTACH.
- **Errors carry no token**: tresor never writes a token to an error, a log or the audit.
