#!/bin/bash
# Smoke subset of .github/workflows/ca-basic-test.yml for local tmt.
# Expects: docker, pki-runner image, and tests/bin helpers from repo root.
set -euo pipefail

# tmt sets TMT_TREE to the metadata tree root (repo root when run from git)
REPO_ROOT="${TMT_TREE:-}"
if [[ -z "$REPO_ROOT" || ! -d "$REPO_ROOT/tests/bin" ]]; then
    # fallback: walk up from this script
    REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
fi
BIN="$REPO_ROOT/tests/bin"
# Match GHA: host workspace bind-mounted at $SHARED inside containers
export GITHUB_WORKSPACE="$REPO_ROOT"
export SHARED="${SHARED:-/tmp/workdir/pki}"

DS_IMAGE="${DS_IMAGE:-quay.io/389ds/dirsrv}"
PKI_IMAGE="${PKI_IMAGE:-pki-runner:latest}"

cleanup() {
    docker rm -f pki ds 2>/dev/null || true
    docker network rm example 2>/dev/null || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

if ! docker image inspect "$PKI_IMAGE" >/dev/null 2>&1; then
    cat >&2 <<EOF
ERROR: Docker image '$PKI_IMAGE' not found.

Build it from the pki repo (same as GHA):
  docker build -t pki-runner --target pki-runner .

Or load a GHA-produced pki-images.tar and retag.
EOF
    exit 1
fi

echo "==> Ensure network"
docker network inspect example >/dev/null 2>&1 || docker network create example
docker rm -f pki ds 2>/dev/null || true

echo "==> Start DS ($DS_IMAGE)"
"$BIN/ds-create.sh" \
    --image="$DS_IMAGE" \
    --hostname=ds.example.com \
    --network=example \
    --network-alias=ds.example.com \
    --password=Secret.123 \
    ds

echo "==> Start PKI runner ($PKI_IMAGE)"
"$BIN/runner-init.sh" \
    --image="$PKI_IMAGE" \
    --hostname=pki.example.com \
    --network=example \
    --network-alias=pki.example.com \
    pki

echo "==> pkispawn CA"
docker exec pki pkispawn \
    -f /usr/share/pki/server/examples/installation/ca.cfg \
    -s CA \
    -D pki_ds_url=ldap://ds.example.com:3389 \
    --debug

echo "==> Import CA signing + admin PKCS#12 into client NSS db (GHA steps)"
docker exec pki pki-server cert-export ca_signing --cert-file ca_signing.crt
docker exec pki pki nss-cert-import \
    --cert ca_signing.crt \
    --trust CT,C,C \
    ca_signing
docker exec pki pki pkcs12-import \
    --pkcs12 /root/.dogtag/pki-tomcat/ca_admin_cert.p12 \
    --pkcs12-password Secret.123

echo "==> ca-profile-find / ca-cert-find"
docker exec pki pki -n caadmin ca-profile-find
docker exec pki pki -n caadmin ca-cert-find

echo "==> pkidestroy CA"
docker exec pki pkidestroy -s CA --debug

echo "==> CA basic smoke PASSED"
