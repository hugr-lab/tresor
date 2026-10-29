#!/usr/bin/env bash
# One live check of a pipeline's login (specs/027): runs scripts/live/<check>.sql in the DuckDB CLI with tresor
# loaded, prints its check lines, and exits 0 only when the script printed check=ok and the expected login.
# Never prints a token: anything shaped like a JWT, and the platform's identity header, are masked.
#
#   run.sh managed_identity | mi_federated | k8s_entra | k8s_keycloak | spiffe_keycloak
#
# Each script's header names its environment (TRESOR_URL, TRESOR_ISSUER, ...). In the image
# (ghcr.io/hugr-lab/tresor-live) the CLI is /usr/local/bin/duckdb, the extension /opt/tresor; elsewhere TRESOR_DUCKDB and
# TRESOR_EXTENSION point at a build (build/release/duckdb, build/release/extension/tresor/tresor.duckdb_extension).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="${1:-}"
case "$check" in
managed_identity) login=managed_identity required="TRESOR_URL TRESOR_ISSUER TRESOR_AUDIENCE TRESOR_MI_CLIENT_ID" ;;
mi_federated) login=federated required="TRESOR_URL TRESOR_ISSUER TRESOR_API_URI TRESOR_MI_CLIENT_ID" ;;
k8s_entra) login=federated required="TRESOR_URL TRESOR_ISSUER TRESOR_API_URI" ;;
k8s_keycloak) login=federated required="TRESOR_URL TRESOR_ISSUER" ;;
spiffe_keycloak) login=federated required="TRESOR_URL TRESOR_ISSUER TRESOR_SPIFFE_ID" ;;
*)
	echo "usage: run.sh managed_identity|mi_federated|k8s_entra|k8s_keycloak|spiffe_keycloak" >&2
	exit 2
	;;
esac
case "$check" in
mi_federated | k8s_entra | k8s_keycloak | spiffe_keycloak)
	if [ -z "${TRESOR_CLIENT_ID:-}" ] && [ -z "${TRESOR_ACL_CLIENT_ID:-}" ]; then
		echo "live $check: TRESOR_ACL_CLIENT_ID (or TRESOR_CLIENT_ID) is not set" >&2
		exit 2
	fi
	;;
esac
for name in $required; do
	if [ -z "${!name:-}" ]; then
		echo "live $check: $name is not set" >&2
		exit 2
	fi
done
duckdb="${TRESOR_DUCKDB:-/usr/local/bin/duckdb}"
ext="${TRESOR_EXTENSION:-/opt/tresor/tresor.duckdb_extension}"
for file in "$duckdb" "$ext" "$here/$check.sql"; do
	[ -f "$file" ] || { echo "live $check: no $file" >&2; exit 2; }
done
# a service's login never touches the OS credential store; keep a person's out of it too
export TRESOR_KEYCHAIN=memory

if [ -n "${TRESOR_ASSERTION_FILE:-}" ] || [ "$check" = k8s_entra ] || [ "$check" = k8s_keycloak ] ||
	[ "$check" = spiffe_keycloak ]; then
	token_file="${TRESOR_ASSERTION_FILE:-/var/run/secrets/tresor/token}"
	# what the pod mounted, never what it holds: the mode tells a projected volume's defaultMode
	if [ -e "$token_file" ]; then
		echo "live $check: assertion file $token_file mode $(stat -L -c %a "$token_file" 2>/dev/null || stat -L -f %Lp "$token_file")"
	else
		echo "live $check: assertion file $token_file does not exist" >&2
	fi
fi

echo "live $check: running"
out="$("$duckdb" -no-agent -unsigned -no-init -bail -list -noheader \
	-cmd "SET autoinstall_known_extensions = false; LOAD '$ext';" -f "$here/$check.sql" :memory: 2>&1)"
rc=$?
esc="$(printf '\033')"
out="$(printf '%s\n' "$out" | sed -E "s/eyJ[A-Za-z0-9._-]*/<token>/g; s/${esc}\[[0-9;]*m//g")"
if [ -n "${IDENTITY_HEADER:-}" ]; then
	out="${out//"$IDENTITY_HEADER"/<identity-header>}"
fi
printf '%s\n' "$out" | sed 's/^/  /'

failed=0
[ "$rc" = 0 ] || { echo "live $check: FAILED - duckdb exited $rc" >&2; failed=1; }
printf '%s\n' "$out" | grep -qE "^login=$login subject=" ||
	{ echo "live $check: FAILED - no login=$login line" >&2; failed=1; }
printf '%s\n' "$out" | grep -qx 'check=ok' || { echo "live $check: FAILED - no check=ok" >&2; failed=1; }
[ "$failed" = 0 ] && echo "live $check: PASSED"
exit "$failed"
