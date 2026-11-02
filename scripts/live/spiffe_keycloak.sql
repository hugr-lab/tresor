-- Check 5 (specs/046): a SPIFFE workload logs in to Keycloak with its JWT-SVID - FLOW 'federated', ASSERTION_SOURCE
-- 'spiffe', the file spiffe-helper writes, SPIFFE_ID. tresor checks the SVID (sub, aud, exp) before it is sent, and
-- sends it as jwt-spiffe: Keycloak authenticates the client by "Signed JWT - Federated" against an identity provider
-- of type spiffe that trusts the trust domain. Run by scripts/live/run.sh spiffe_keycloak, which LOADs tresor first.
-- Environment:
--   TRESOR_URL             the service (https://host[/base]; http:// against a local one)
--   TRESOR_ISSUER          the realm (https://<keycloak>/realms/<realm>)
--   TRESOR_CLIENT_ID       the Keycloak client that logs in (or TRESOR_ACL_CLIENT_ID)
--   TRESOR_ASSERTION_FILE  the JWT-SVID's file (default /var/run/secrets/tresor/token)
--   TRESOR_SPIFFE_ID       the SPIFFE ID the SVID must be
--   TRESOR_ASSERTION_TYPE  optional: jwt-bearer for an IdP that federates SPIRE as an OIDC issuer (default jwt-spiffe)
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
    CLIENT_ID getvariable('client'), ISSUER getenv('TRESOR_ISSUER'), ASSERTION_SOURCE 'spiffe',
    ASSERTION_FILE getvariable('token_file'), SPIFFE_ID getenv('TRESOR_SPIFFE_ID'),
    ASSERTION_TYPE nullif(getenv('TRESOR_ASSERTION_TYPE'), ''));
ATTACH 'tresor:' || getvariable('host') AS live (SECRET live, INSECURE_HTTP getvariable('insecure'));

SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM live.whoami();
SELECT 'secrets=' || coalesce(string_agg(name, ',' ORDER BY name), '') FROM live.secrets();
SELECT CASE WHEN login = 'federated' AND list_contains(roles, getvariable('expect_role'))
                 AND (subject = 'client:' || getvariable('client')
                      OR list_contains(roles, 'client:' || getvariable('client'))) THEN 'check=ok'
    ELSE error('check failed: want login federated, ' || getvariable('expect_role') || ' and client:'
               || getvariable('client') || ', got login ' || login || ' subject ' || subject || ' roles ' || array_to_string(roles, ','))
    END FROM live.whoami();
