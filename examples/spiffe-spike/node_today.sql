-- The node's login today (tresor specs/046 spike): the JWT-SVID as an ordinary federated assertion -
-- FLOW 'federated', ASSERTION_FILE - which tresor sends as jwt-bearer. Run by console.py, which LOADs tresor
-- first and masks anything token-shaped. Environment: SPIKE_HOST, SPIKE_ISSUER, SPIKE_SVID_FILE.
SET tresor_audit_level = 'all';
CALL enable_logging('tresor', storage = 'memory'); -- the CLI's own log storage cannot be queried
SELECT 'tresor=' || tresor_version();
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:' || getenv('SPIKE_HOST'), FLOW 'federated',
    CLIENT_ID 'acl-node', ISSUER getenv('SPIKE_ISSUER'), ASSERTION_FILE getenv('SPIKE_SVID_FILE'));
ATTACH 'tresor:' || getenv('SPIKE_HOST') AS corp (SECRET node, INSECURE_HTTP true);
SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM corp.whoami();
SELECT 'secrets=' || coalesce(string_agg(name || ':' || type, ',' ORDER BY name), '') FROM corp.secrets();
SELECT 'audit=' || kind || ' ' || outcome || ' ' || coalesce(detail, '-') || ' ' || coalesce(reason_code, '-')
    FROM duckdb_logs_parsed('tresor') ORDER BY seq;
