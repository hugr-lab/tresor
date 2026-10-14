# ghcr.io/hugr-lab/tresor-live (specs/027): the DuckDB CLI at the duckdb submodule's pin and tresor at the commit,
# for the live checks of a pipeline's login on Azure and Kubernetes. Built by .github/workflows/live-image.yml from
# binaries it built; the context is a staging directory holding duckdb, tresor.duckdb_extension and live/.
# The extension is unsigned: the CLI runs with -unsigned.
FROM ubuntu:24.04
LABEL org.opencontainers.image.source=https://github.com/hugr-lab/tresor \
	org.opencontainers.image.description="tresor live checks (specs/027): the DuckDB CLI, tresor, /live"
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
# tresor's https client is OpenSSL from vcpkg, whose compiled-in certificate directory is not Ubuntu's
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
	SSL_CERT_DIR=/etc/ssl/certs \
	TRESOR_KEYCHAIN=off
COPY duckdb /usr/local/bin/duckdb
COPY tresor.duckdb_extension /opt/tresor/tresor.duckdb_extension
COPY live/ /live/
RUN chmod 0755 /usr/local/bin/duckdb /live/check.sh /live/run.sh \
	&& chmod 0644 /opt/tresor/tresor.duckdb_extension /live/*.sql
# root, as the stand runs it: a projected token mounted 0440 root:root without an fsGroup is readable by root only
# (a non-root pod sets runAsUser/fsGroup, and the kubelet then owns the file accordingly)
WORKDIR /tmp
CMD ["/live/check.sh"]
