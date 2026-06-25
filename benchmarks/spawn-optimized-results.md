# pkispawn validation — after optimizations

Measured **2026-06-01** on local `pki` + `ds` containers (same setup as baseline).

Optimizations in this build:

- `ca-group-member-add-batch` (11 group adds → 1 JVM)
- `ca-cert-create` with `--csr` + `--import-cert` (replaces per-cert `ca-cert-request-import` + `ca-cert-create` + `ca-cert-import`)
- Java CLI longest-match fix for `add-batch` routing

## Clean spawn procedure

`pkidestroy -s CA` leaves the instance NSS DB and CSR files in place. For a fair timing comparison with the baseline (fresh cert creation), wipe before each run:

```bash
docker exec pki pkidestroy -s CA --force
docker exec pki bash -c '
  rm -rf /var/lib/pki/pki-tomcat/conf/alias/*
  rm -rf /var/lib/pki/pki-tomcat/conf/certs/*
  rm -rf /root/.dogtag/pki-tomcat/ca/alias/* 2>/dev/null || true
  rm -f /root/.dogtag/pki-tomcat/ca_admin.cert /root/.dogtag/pki-tomcat/ca_admin_cert.p12 2>/dev/null || true
'
```

## Total wall time (clean runs)

| Run | Baseline | Optimized | Δ |
|-----|----------|-----------|---|
| `pkispawn --debug` | **137.3 s** | **109.3 s** | **−28.0 s (−20%)** |
| `pkispawn -v` | **138.0 s** | **109.6 s** | **−28.4 s (−21%)** |
| `pki-spawn.sh` (full script) | **157.5 s** | **113.8 s** | **−43.7 s (−28%)** |

**Note:** One early run at **82.2 s** reused NSS certs/CSRs from a prior install (no `ca-cert-create` calls). It is **not** comparable to baseline; use the clean runs above.

Raw logs: `benchmarks/spawn-debug-timestamped-optimized.log`, `benchmarks/spawn-debug-analysis-optimized.txt`, `benchmarks/spawn-optimized-summary.txt`.

---

## Phase breakdown (INFO markers, 1 s resolution)

| Phase | Baseline | Optimized | Δ |
|-------|----------|-----------|---|
| DB configure + create + init | ~26 s | ~23 s | ~−3 s |
| System certs (signing → subsystem) | ~64 s | ~48 s | **−16 s** |
| Admin cert | ~5 s | ~9 s | +4 s† |
| Admin user (+ groups) | ~29 s | ~16 s | **−13 s** |
| Tomcat start + ready | ~12 s | ~12 s | ~0 s |

†Admin cert phase includes more key/CSR work on clean NSS; cert LDAP is folded into one `ca-cert-create` per cert.

---

## Subprocess inventory (`pkispawn --debug`, clean run)

| Type | Baseline | Optimized | Δ |
|------|----------|-----------|---|
| **pki-server** | **32** | **20** | **−12** |
| pki CLI | 36 | 28 | −8 |
| filesystem | 26 | 27 | +1 |
| **Total DEBUG commands** | **99** | **81** | **−18** |

### pki-server — cert / admin path

| Subcommand | Baseline | Optimized |
|------------|----------|-----------|
| `ca-group-member-add` | 11 | 1 (subsystem group only) |
| `ca-group-member-add-batch` | — | **1** |
| `ca-cert-request-import` | 4 | **0** |
| `ca-cert-import` | 4 | **0** |
| `ca-cert-create` | (not logged separately) | **5** (4 system + admin, each with `--csr --import-cert`) |

### pki-server — per-invocation span (gap to next call)

| Subcommand | Baseline total | Optimized total |
|------------|----------------|-----------------|
| `ca-group-member-add` | 26.0 s (11×) | 2.0 s (1×) |
| `ca-group-member-add-batch` | — | 12.0 s (1×) |
| `ca-cert-request-import` | 10.0 s (4×) | — |
| `ca-cert-import` | 38.0 s (4×) | — |
| `ca-cert-create` | — | 41.0 s (5×) |

**Net group-admin LDAP:** ~26 s → ~14 s (~12 s saved).

**Net cert LDAP:** 4×(request-import + create + import) → 5× single `ca-cert-create`; fewer JVM starts and less duplicated init (roughly **~16 s** in system-cert phase).

---

## Reproduce

```bash
cd /path/to/pki
# clean wipe (see above), then:
/usr/bin/time docker exec pki pkispawn \
  -f /usr/share/pki/server/examples/installation/ca.cfg \
  -s CA \
  -D pki_audit_signing_nickname= \
  -D pki_ds_url=ldap://ds.example.com:3389 \
  --debug 2>&1 | ts '%Y-%m-%dT%H:%M:%S.%s' \
  | tee benchmarks/spawn-debug-timestamped-optimized.log

python3 benchmarks/analyze-spawn-debug.py benchmarks/spawn-debug-timestamped-optimized.log
```
