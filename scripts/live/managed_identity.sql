-- Check 1 (specs/027): an Azure managed identity logs in itself - FLOW 'managed_identity'. The platform's token
-- for the service's audience is the login; no client at the identity provider, nothing secret on the machine.
-- Run by scripts/live/run.sh managed_identity, which LOADs tresor first. Environment:
--   TRESOR_URL           the service (https://host[/base]); http:// only against a local service
--   TRESOR_ISSUER        the identity provider (Entra: https://login.microsoftonline.com/<tenant>/v2.0)
--   TRESOR_AUDIENCE      the service's audience (Entra v2: the API's client id) - what the token is asked for
--   TRESOR_MI_CLIENT_ID  the user-assigned identity's client id
--   TRESOR_EXPECT_ROLE   the role the identity must hold (default role:nodes)
.bail on
SET VARIABLE url = regexp_replace(getenv('TRESOR_URL'), '/+$', '');
SET VARIABLE host = regexp_replace(getvariable('url'), '^https?://', '');
SET VARIABLE insecure = starts_with(getvariable('url'), 'http://');
SET VARIABLE expect_role = coalesce(nullif(getenv('TRESOR_EXPECT_ROLE'), ''), 'role:nodes');
SELECT 'tresor=' || tresor_version() || ' duckdb=' || version() || ' service=' || getvariable('host');

CREATE SECRET live (TYPE tresor, SCOPE 'tresor:' || getvariable('host'), FLOW 'managed_identity',
    ISSUER getenv('TRESOR_ISSUER'), AUDIENCE getenv('TRESOR_AUDIENCE'), CLIENT_ID getenv('TRESOR_MI_CLIENT_ID'));
ATTACH 'tresor:' || getvariable('host') AS live (SECRET live, INSECURE_HTTP getvariable('insecure'));

SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM live.whoami();
SELECT 'secrets=' || coalesce(string_agg(name, ',' ORDER BY name), '') FROM live.secrets();
SELECT CASE WHEN login = 'managed_identity' AND list_contains(roles, getvariable('expect_role')) THEN 'check=ok'
    ELSE error('check failed: want login managed_identity and ' || getvariable('expect_role') || ', got login '
               || login || ' roles ' || array_to_string(roles, ','))
    END FROM live.whoami();
