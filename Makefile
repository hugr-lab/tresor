PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=tresor
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Build dependencies come from vcpkg, like every duckdb extension (openssl: specs/002, the https client).
# The merged-manifest step collects vcpkg.json. Bootstrap once with `make vcpkg-setup`, or point
# VCPKG_TOOLCHAIN_PATH at an existing vcpkg checkout.
USE_MERGED_VCPKG_MANIFEST := 1
VCPKG_TOOLCHAIN_PATH ?= $(PROJ_DIR)vcpkg/scripts/buildsystems/vcpkg.cmake

# Only the goals that configure cmake need the toolchain; checkout/CI helper goals (the distribution
# workflow's set_duckdb_version, configure_ci) run before any vcpkg exists - name ours, not theirs.
GOALS := $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
VCPKG_GOALS := all release debug reldebug relassert
ifeq ($(wildcard $(VCPKG_TOOLCHAIN_PATH)),)
ifneq ($(filter $(VCPKG_GOALS),$(GOALS)),)
$(error this build needs vcpkg: run 'make vcpkg-setup' first, or set VCPKG_TOOLCHAIN_PATH)
endif
endif

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

.PHONY: vcpkg-setup
# the commit extension-ci-tools' distribution build uses (its `vcpkg_commit` default): CI and releases
# build the same OpenSSL
VCPKG_COMMIT ?= cd61e1e26a038e82d6550a3ebbe0fbbfe7da78e3
vcpkg-setup:
	@test -d vcpkg || git clone https://github.com/microsoft/vcpkg.git vcpkg
	git -C vcpkg fetch -q origin $(VCPKG_COMMIT) 2>/dev/null || true
	git -C vcpkg checkout -q $(VCPKG_COMMIT)
	./vcpkg/bootstrap-vcpkg.sh -disableMetrics
