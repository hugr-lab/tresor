-- The node's login with ASSERTION_TYPE (tresor specs/046): the JWT-SVID sent as jwt-spiffe, as Keycloak's SPIFFE
-- authentication takes it. Run by console.py, which LOADs tresor first and masks anything token-shaped.
-- Environment: SPIKE_HOST, SPIKE_ISSUER, SPIKE_SVID_FILE.
SET tresor_audit_level = 'all';
CALL enable_logging('tresor', storage = 'memory'); -- the CLI's own log storage cannot be queried
SELECT 'tresor=' || tresor_version();
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:' || getenv('SPIKE_HOST'), FLOW 'federated',
    CLIENT_ID 'acl-node', ISSUER getenv('SPIKE_ISSUER'), ASSERTION_FILE getenv('SPIKE_SVID_FILE'),
    ASSERTION_TYPE 'jwt-spiffe');
ATTACH 'tresor:' || getenv('SPIKE_HOST') AS corp (SECRET node, INSECURE_HTTP true);
SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM corp.whoami();
SELECT 'secrets=' || coalesce(string_agg(name || ':' || type, ',' ORDER BY name), '') FROM corp.secrets();
SELECT 'audit=' || kind || ' ' || outcome || ' ' || coalesce(detail, '-') || ' ' || coalesce(reason_code, '-')
    FROM duckdb_logs_parsed('tresor') ORDER BY seq;
