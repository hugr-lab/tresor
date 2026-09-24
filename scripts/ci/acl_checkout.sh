#!/usr/bin/env bash
# duckdb-acl at the commit tresor's actor test runs against (specs/008), checked out for the test build
# (extension_config.cmake builds it when TRESOR_TEST_ACL_DIR names the checkout). Move ACL_COMMIT with the
# pins: its duckdb submodule must be this repository's, or acl would not load into the test build - checked
# here, before anything is built.
#
#   scripts/ci/acl_checkout.sh <dir>
set -euo pipefail
ACL_COMMIT=8739e765a44af7477e33a18b59e3dda0ed0b757b # duckdb-acl main: secrets through the ACL, under the session (specs 082, 083), ACLC 2
root="$(cd "$(dirname "$0")/../.." && pwd)"
dest="${1:?usage: acl_checkout.sh <dir>}"

# a directory of its own: never the working tree, its parent or /
case "$(cd "$(dirname "$dest")" 2>/dev/null && pwd)/$(basename "$dest")" in
"$root" | "$root/." | "$(dirname "$root")" | / | //)
	echo "acl_checkout: refusing to replace $dest" >&2
	exit 1
	;;
esac
[ -e "$root/duckdb/.git" ] || {
	echo "acl_checkout: tresor's duckdb submodule is not checked out (git submodule update --init --recursive)" >&2
	exit 1
}
rm -rf "$dest"
git init -q "$dest"
git -C "$dest" remote add origin https://github.com/hugr-lab/duckdb-acl
git -C "$dest" fetch -q --depth 1 origin "$ACL_COMMIT"
git -C "$dest" checkout -q FETCH_HEAD

theirs="$(git -C "$dest" ls-tree HEAD duckdb | awk '{print $3}')"
ours="$(git -C "$root" ls-tree HEAD duckdb | awk '{print $3}')" # the pin, not whatever is checked out
if [ "$theirs" != "$ours" ]; then
	echo "acl_checkout: duckdb-acl $ACL_COMMIT pins duckdb $theirs, tresor $ours - move ACL_COMMIT with the pins" >&2
	exit 1
fi
theirs_common="$(git -C "$dest" ls-tree HEAD duckdb-ext-common | awk '{print $3}')"
ours_common="$(git -C "$root" ls-tree HEAD duckdb-ext-common | awk '{print $3}')"
if [ "$theirs_common" != "$ours_common" ]; then
	echo "acl_checkout: duckdb-acl $ACL_COMMIT pins duckdb-ext-common $theirs_common, tresor $ours_common - the" \
		"acl_connection contract would not match; move the pins together" >&2
	exit 1
fi
# the shared repository at acl's own pin; duckdb is ours (the same commit), linked rather than cloned again
git -C "$dest" submodule update -q --init --depth 1 duckdb-ext-common
rmdir "$dest/duckdb" 2>/dev/null || rm -rf "$dest/duckdb"
ln -s "$root/duckdb" "$dest/duckdb"
# the lean build (ACL_NO_FLIGHT) needs nothing from vcpkg: acl's manifest (arrow, flight) must not be merged
# into the test build's, which would build arrow for a door the actor test never opens
rm -f "$dest/vcpkg.json"
echo "acl_checkout: duckdb-acl $ACL_COMMIT in $dest (duckdb $ours)"
