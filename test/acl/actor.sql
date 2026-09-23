-- tresor acting for a real duckdb-acl session (specs/008, 009), run by scripts/ci/test_keycloak.sh when the test
-- build carries acl (TRESOR_TEST_ACL_DIR, extension_config.cmake) or TRESOR_ACL_EXTENSION names one built at
-- this repository's duckdb commit. A CLI script,
-- not a sqllogictest: the statements under the session carry the handle acl_session_open returns.
-- @...@ are filled in by the script; the checks read the lines marked "check:".
.mode list
.headers off
LOAD '@ACL_EXTENSION@';
LOAD '@TRESOR_EXTENSION@';

-- an admin (the etl service) stores what the node serves, and grants it to the node's role (specs/009)
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:@HOST@', FLOW 'client_credentials', CLIENT_ID 'etl',
    CLIENT_SECRET 'etl-secret', ISSUER '@ISSUER@');
ATTACH 'tresor:@HOST@' AS owner (INSECURE_HTTP true, SECRET etl);
CREATE OR REPLACE PERSISTENT SECRET acl_lake IN owner (TYPE http, SCOPE 'https://acl-lake.example', BEARER_TOKEN 'x');
CALL owner.grant_secret('acl_lake', 'role:nodes', ['use']);

-- the node: acl trusts Keycloak's tokens for acl-node; tresor acts for acl's sessions
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true) AS ok;
SET GLOBAL acl_allow_anonymous_admin = true;
SELECT acl_define_issuer('@ISSUER@', '@JWKS@', 'acl-node', 'RS256', 'realm_access.roles', '{}') AS ok;
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:elsewhere', FLOW 'client_credentials', CLIENT_ID 'acl-node',
    CLIENT_SECRET 'node-secret', ISSUER '@ISSUER@');
ATTACH 'tresor:@HOST@' AS node (INSECURE_HTTP true, SECRET node, ACT_FOR_SESSIONS true);

-- what a session's user may call: acl's virtual functions over tresor's
ACL ADMIN CREATE ROLE analysts;
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.me RETURNS TABLE (subject VARCHAR, actor VARCHAR)
    AS SELECT subject, actor FROM node.main.whoami();
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.lake RETURNS TABLE (name VARCHAR)
    AS SELECT name FROM which_secret('https://acl-lake.example/x', 'http') WHERE storage = 'node';
ACL ADMIN GRANT CATALOG c TO ROLE analysts MAIN;

-- outside any session: the node, with what its role was granted
SELECT 'check:node ' || subject || '|' || coalesce(actor, 'NULL') FROM node.whoami();
SELECT 'check:node-lake ' || count(*) FROM which_secret('https://acl-lake.example/x', 'http') WHERE storage = 'node';

-- alice's session: tresor's observer exchanges her token and obtains the grant
CREATE TABLE h AS SELECT acl_session_open('@TOKEN@') AS handle;
SELECT 'check:opened ' || (handle IS NOT NULL) FROM h;
.output @WORK@/under_session.sql
SELECT acl_session_sql(handle, 'SELECT ''check:session '' || subject || ''|'' || actor FROM c.me()') || ';' FROM h;
SELECT acl_session_sql(handle, 'SELECT ''check:session-lake '' || name FROM c.lake()') || ';' FROM h;
.output
.read @WORK@/under_session.sql
SELECT 'check:closed ' || acl_session_close(handle) FROM h;

DETACH node;
DROP PERSISTENT SECRET acl_lake FROM owner;
