-- Check 3 (specs/027): a Kubernetes pod logs in to Entra with its projected service-account token as the federated
-- client assertion - FLOW 'federated', ASSERTION_FILE. The app registration has a federated credential naming the
-- cluster's OIDC issuer, the subject system:serviceaccount:<namespace>:<name> and the audience
-- api://AzureADTokenExchange (the projected token's audience).
-- Run by scripts/live/run.sh k8s_entra, which LOADs tresor first. Environment:
--   TRESOR_URL             the service (https://host[/base])
--   TRESOR_ISSUER          the tenant's v2 issuer
--   TRESOR_API_URI         the service API's Application ID URI: OAUTH_SCOPE '<uri>/.default'
--   TRESOR_ACL_CLIENT_ID   the app registration that logs in (TRESOR_CLIENT_ID overrides it)
--   TRESOR_ASSERTION_FILE  the projected token (default /var/run/secrets/tresor/token)
--   TRESOR_EXPECT_ROLE     the role the registration must hold (default role:nodes)
.bail on
SET VARIABLE url = regexp_replace(getenv('TRESOR_URL'), '/+$', '');
SET VARIABLE host = regexp_replace(getvariable('url'), '^https?://', '');
SET VARIABLE insecure = starts_with(getvariable('url'), 'http://');
SET VARIABLE client = coalesce(nullif(getenv('TRESOR_CLIENT_ID'), ''), getenv('TRESOR_ACL_CLIENT_ID'));
SET VARIABLE token_file = coalesce(nullif(getenv('TRESOR_ASSERTION_FILE'), ''), '/var/run/secrets/tresor/token');
SET VARIABLE expect_role = coalesce(nullif(getenv('TRESOR_EXPECT_ROLE'), ''), 'role:nodes');
SELECT 'tresor=' || tresor_version() || ' duckdb=' || version() || ' service=' || getvariable('host');

CREATE SECRET live (TYPE tresor, SCOPE 'tresor:' || getvariable('host'), FLOW 'federated',
    CLIENT_ID getvariable('client'), ISSUER getenv('TRESOR_ISSUER'),
    OAUTH_SCOPE getenv('TRESOR_API_URI') || '/.default', ASSERTION_FILE getvariable('token_file'));
ATTACH 'tresor:' || getvariable('host') AS live (SECRET live, INSECURE_HTTP getvariable('insecure'));

SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM live.whoami();
SELECT 'secrets=' || coalesce(string_agg(name, ',' ORDER BY name), '') FROM live.secrets();
SELECT CASE WHEN login = 'federated' AND list_contains(roles, getvariable('expect_role'))
                 AND (subject = 'client:' || getvariable('client')
                      OR list_contains(roles, 'client:' || getvariable('client'))) THEN 'check=ok'
    ELSE error('check failed: want login federated, ' || getvariable('expect_role') || ' and client:'
               || getvariable('client') || ', got login ' || login || ' subject ' || subject || ' roles ' || array_to_string(roles, ','))
    END FROM live.whoami();
