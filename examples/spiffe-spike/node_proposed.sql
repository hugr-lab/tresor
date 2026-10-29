-- The node's login as specs/046 proposes it: ASSERTION_SOURCE 'spiffe', the SPIFFE ID it must carry, and the
-- jwt-spiffe assertion type. Until the option exists, CREATE SECRET refuses SPIFFE_ID - the console shows that.
-- Environment: SPIKE_HOST, SPIKE_ISSUER, SPIKE_SVID_FILE, SPIKE_SPIFFE_ID.
SET tresor_audit_level = 'all';
CALL enable_logging('tresor', storage = 'memory'); -- the CLI's own log storage cannot be queried
SELECT 'tresor=' || tresor_version();
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:' || getenv('SPIKE_HOST'), FLOW 'federated',
    CLIENT_ID 'acl-node', ISSUER getenv('SPIKE_ISSUER'), ASSERTION_SOURCE 'spiffe',
    ASSERTION_FILE getenv('SPIKE_SVID_FILE'), SPIFFE_ID getenv('SPIKE_SPIFFE_ID'), ASSERTION_TYPE 'jwt-spiffe');
ATTACH 'tresor:' || getenv('SPIKE_HOST') AS corp (SECRET node, INSECURE_HTTP true);
SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM corp.whoami();
SELECT 'secrets=' || coalesce(string_agg(name || ':' || type, ',' ORDER BY name), '') FROM corp.secrets();
SELECT 'audit=' || kind || ' ' || outcome || ' ' || coalesce(detail, '-') || ' ' || coalesce(reason_code, '-')
    FROM duckdb_logs_parsed('tresor') ORDER BY seq;
