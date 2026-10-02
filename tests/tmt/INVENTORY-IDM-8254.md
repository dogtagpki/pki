# IDM-8254 — Dogtag GHA → TMT / IPACTA coverage inventory

Goal: prove IPACTA can replace Dogtag for **CA / KRA / ACME** without feature loss.
Coverage map = Dogtag **standalone** GHA. Dual repos: this tree (Dogtag TMT) + freeipa (IPACTA TMT).

## Tier 1 — core (implement first)

| GHA | Status | Notes |
|-----|--------|-------|
| `ca-basic-test.yml` | **Pilot in progress** — `plans/ca-basic-smoke.fmf` | Smoke subset; expand later |
| `kra-basic-test.yml` | Next | |
| `acme-basic-test.yml` | Next | |

## Tier 2 — Dogtag required; IPACTA attempt + gap-log

| Area | GHA (examples) | Dogtag TMT | IPACTA TMT |
|------|----------------|------------|------------|
| PQC | `ca-pqc-test.yml`, `kra-pqc-test.yml` | Required | Attempt / gap-log |
| HSM | `ca-softhsm-test.yml`, `kra-softhsm-test.yml`, `ca-hsm-operation-test.yml` | Required | Attempt / gap-log |
| Clone | `ca-clone-test.yml`, `kra-clone-test.yml`, `acme-clone-test.yml` | Required | Attempt / gap-log |
| Profiles | `ca-profile-*.yml` | Required | Attempt / gap-log |
| Lifecycle | `ca-cert-revocation-test.yml`, `ca-crl-test.yml`, `ca-renewal-*-test.yml` | Required | Attempt / gap-log |
| Sub-CA / LWCA | `subca-basic-test.yml`, `lwca-basic-test.yml` | Required | Attempt / gap-log |
| OCSP | `ocsp-basic-test.yml` | Required | Attempt / gap-log |

## Tier 3 — out of IPACTA replacement scope

| Area | Why |
|------|-----|
| TPS / TKS | Smart-card token stack; not FreeIPA CA replacement |
| EST | Separate enrollment protocol; not in IPACTA |
| Container / HSM-hardware / Kryoptic / PQC-clone matrix sprawl | Defer unless Tier 1–2 gap forces |
| `ipa-*.yml` IPA-integrated workflows | IdM integration track (parallel), not standalone map |
| NSS CLI / server-https / java unit / … | Not CA/KRA/ACME replacement |

## Three-env check (pilot)

| Env | How | Status |
|-----|-----|--------|
| Dogtag GHA | `.github/workflows/ca-basic-test.yml` | Existing baseline |
| Dogtag TMT | `plans/ca-basic-smoke.fmf` (this repo) | **PASS** local (`tmt --feeling-safe`, pki-runner:latest) |
| IPACTA TMT | freeipa `plans/ca-basic-smoke.fmf` | **PASS** local (`freeipa-ipacta:latest`) |
