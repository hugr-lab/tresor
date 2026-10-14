-- Check 2 (specs/027): an app registration (the acl-node) logs in with an Azure managed identity's token as its
-- federated client assertion - FLOW 'federated', ASSERTION_SOURCE 'azure_managed_identity' (specs/015). The
-- registration has a federated credential naming the identity (issuer the tenant's v2 issuer, subject the
-- identity's object id, audience api://AzureADTokenExchange).
-- Run by scripts/live/run.sh mi_federated, which LOADs tresor first. Environment:
--   TRESOR_URL            the service (https://host[/base])
--   TRESOR_ISSUER         the tenant's v2 issuer
--   TRESOR_API_URI        the service API's Application ID URI: OAUTH_SCOPE '<uri>/.default'
--   TRESOR_ACL_CLIENT_ID  the app registration that logs in (TRESOR_CLIENT_ID overrides it)
--   TRESOR_MI_CLIENT_ID   the user-assigned identity whose token is the assertion
--   TRESOR_EXPECT_ROLE    the role the registration must hold (default role:nodes)
.bail on
SET VARIABLE url = regexp_replace(getenv('TRESOR_URL'), '/+$', '');
SET VARIABLE host = regexp_replace(getvariable('url'), '^https?://', '');
SET VARIABLE insecure = starts_with(getvariable('url'), 'http://');
SET VARIABLE client = coalesce(nullif(getenv('TRESOR_CLIENT_ID'), ''), getenv('TRESOR_ACL_CLIENT_ID'));
SET VARIABLE expect_role = coalesce(nullif(getenv('TRESOR_EXPECT_ROLE'), ''), 'role:nodes');
SELECT 'tresor=' || tresor_version() || ' duckdb=' || version() || ' service=' || getvariable('host');

CREATE SECRET live (TYPE tresor, SCOPE 'tresor:' || getvariable('host'), FLOW 'federated',
    CLIENT_ID getvariable('client'), ISSUER getenv('TRESOR_ISSUER'),
    OAUTH_SCOPE getenv('TRESOR_API_URI') || '/.default',
    ASSERTION_SOURCE 'azure_managed_identity', IDENTITY_CLIENT_ID getenv('TRESOR_MI_CLIENT_ID'));
ATTACH 'tresor:' || getvariable('host') AS live (SECRET live, INSECURE_HTTP getvariable('insecure'));

SELECT 'login=' || login || ' subject=' || subject || ' roles=' || array_to_string(roles, ',') FROM live.whoami();
SELECT 'secrets=' || coalesce(string_agg(name, ',' ORDER BY name), '') FROM live.secrets();
SELECT CASE WHEN login = 'federated' AND list_contains(roles, getvariable('expect_role'))
                 AND list_contains(roles, 'client:' || getvariable('client')) THEN 'check=ok'
    ELSE error('check failed: want login federated, ' || getvariable('expect_role') || ' and client:'
               || getvariable('client') || ', got login ' || login || ' roles ' || array_to_string(roles, ','))
    END FROM live.whoami();
