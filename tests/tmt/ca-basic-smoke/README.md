# ca-basic-smoke (TMT)

Smoke subset of [`.github/workflows/ca-basic-test.yml`](../../../.github/workflows/ca-basic-test.yml)
for [IDM-8254](https://redhat.atlassian.net/browse/IDM-8254).

## What it covers

| Step | GHA counterpart |
|------|-----------------|
| DS + pki-runner containers | Set up DS / PKI container |
| `pkispawn -s CA` | Install CA |
| `pki -n caadmin ca-profile-find` / `ca-cert-find` | Check CA profiles (+ cert list) |
| `pkidestroy -s CA` | Remove CA |

Full GHA also checks filesystem layout, audit, DS entries, custom profile add, etc. Those stay for later expansion.

## Prerequisites

- Docker
- Local image `pki-runner:latest` (or set `PKI_IMAGE`)
- Optional: `DS_IMAGE` (default `quay.io/389ds/dirsrv`)
- Local run: `tmt --feeling-safe …` (required for `provision: how: local`)

## Run locally

```bash
# from pki repo root, after building pki-runner
tmt lint /plans/ca-basic-smoke /tests/tmt/ca-basic-smoke
tmt --feeling-safe run -vvv plan --name ca-basic-smoke
```

## IPACTA parity

Same smoke intent lives in freeipa branch `idm-8254-tmt-ca-basic`
(`plans/ca-basic-smoke.fmf`) using IPACTA instead of Dogtag/`pkispawn`.
