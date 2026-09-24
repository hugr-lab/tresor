#!/usr/bin/env bash
# duckdb-acl at the commit tresor's actor test runs against (specs/008), checked out for the test build
# (extension_config.cmake builds it when TRESOR_TEST_ACL_DIR names the checkout). Move ACL_COMMIT with the
# pins: its duckdb submodule must be this repository's, or acl would not load into the test build - checked
# here, before anything is built.
#
#   scripts/ci/acl_checkout.sh <dir>
set -euo pipefail
ACL_COMMIT=72734f6debdffe01f9e3147d8e0ea30ae482b184 # duckdb-acl main: specs 082-086 (resource groups, ext-common v0.7.1), ACLC 2
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
# the shared repository at acl's own pin. The two pins may differ (a tag adding a contract only one side
# uses, a comment fixed), but every contract both use - acl's - must carry the same stamps: a contract bumps
# its version on any change to its layout (charter R4), so equal stamps are one layout
git -C "$dest" submodule update -q --init --depth 1 duckdb-ext-common
stamps() { grep -hoE '(MAGIC|VERSION) = (0x)?[0-9A-Fa-f]+' "$1"/contracts/acl_*.hpp | sort; }
theirs_stamps="$(stamps "$dest/duckdb-ext-common")"
ours_stamps="$(stamps "$root/duckdb-ext-common")"
if [ -z "$ours_stamps" ] || [ "$theirs_stamps" != "$ours_stamps" ]; then
	echo "acl_checkout: duckdb-acl $ACL_COMMIT's duckdb-ext-common stamps acl's contracts" $theirs_stamps \
		"- tresor's" $ours_stamps "- move the pins together" >&2
	exit 1
fi
rmdir "$dest/duckdb" 2>/dev/null || rm -rf "$dest/duckdb"
ln -s "$root/duckdb" "$dest/duckdb"
# the lean build (ACL_NO_FLIGHT) needs nothing from vcpkg: acl's manifest (arrow, flight) must not be merged
# into the test build's, which would build arrow for a door the actor test never opens
rm -f "$dest/vcpkg.json"
echo "acl_checkout: duckdb-acl $ACL_COMMIT in $dest (duckdb $ours)"
