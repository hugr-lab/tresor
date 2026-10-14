-- Check 4 (specs/027): a Kubernetes pod logs in to Keycloak with its projected service-account token as the client
-- assertion - FLOW 'federated', ASSERTION_FILE. Keycloak authenticates the client by "Signed JWT - Federated"
-- (federated-jwt) against an identity provider that trusts the cluster's service-account issuer (specs/027).
-- Run by scripts/live/run.sh k8s_keycloak, which LOADs tresor first. Environment:
--   TRESOR_URL             the service (https://host[/base]; http:// against a local one)
--   TRESOR_ISSUER          the realm (https://<keycloak>/realms/<realm>)
--   TRESOR_CLIENT_ID       the Keycloak client that logs in (or TRESOR_ACL_CLIENT_ID)
--   TRESOR_ASSERTION_FILE  the projected token (default /var/run/secrets/tresor/token)
--   TRESOR_EXPECT_ROLE     the role the client must hold (default role:nodes)
.bail on
SET VARIABLE url = regexp_replace(getenv('TRESOR_URL'), '/+$', '');
SET VARIABLE host = regexp_replace(getvariable('url'), '^https?://', '');
SET VARIABLE insecure = starts_with(getvariable('url'), 'http://');
SET VARIABLE client = coalesce(nullif(getenv('TRESOR_CLIENT_ID'), ''), getenv('TRESOR_ACL_CLIENT_ID'));
SET VARIABLE token_file = coalesce(nullif(getenv('TRESOR_ASSERTION_FILE'), ''), '/var/run/secrets/tresor/token');
SET VARIABLE expect_role = coalesce(nullif(getenv('TRESOR_EXPECT_ROLE'), ''), 'role:nodes');
SELECT 'tresor=' || tresor_version() || ' duckdb=' || version() || ' service=' || getvariable('host');

CREATE SECRET live (TYPE tresor, SCOPE 'tresor:' || getvariable('host'), FLOW 'federated',
    CLIENT_ID getvariable('client'), ISSUER getenv('TRESOR_ISSUER'), ASSERTION_FILE getvariable('token_file'));
ATTACH 'tresor:' || getvariable('host') AS live (SECRET live, INSECURE_HTTP getvariable('insecure'));

SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM live.whoami();
SELECT 'secrets=' || coalesce(string_agg(name, ',' ORDER BY name), '') FROM live.secrets();
SELECT CASE WHEN login = 'federated' AND list_contains(roles, getvariable('expect_role'))
                 AND (subject = 'client:' || getvariable('client')
                      OR list_contains(roles, 'client:' || getvariable('client'))) THEN 'check=ok'
    ELSE error('check failed: want login federated, ' || getvariable('expect_role') || ' and client:'
               || getvariable('client') || ', got login ' || login || ' subject ' || subject || ' roles ' || array_to_string(roles, ','))
    END FROM live.whoami();
