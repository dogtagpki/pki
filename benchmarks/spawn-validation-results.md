# pkispawn validation results

Measured **2026-06-01** on local `pki` + `ds` containers (`pki-create.sh -s`, Fedora 44 / PKI 11.10.0 alpha).

## Total wall time

| Run | Time |
|-----|------|
| `pkispawn --debug` (timestamped log) | **137.3 s** |
| `pkispawn -v` (repeat, CA destroyed between) | **138.0 s** |

Repro logs: `benchmarks/spawn-debug-timestamped.log`, `benchmarks/spawn-debug-analysis.txt`, `benchmarks/spawn-validation-summary.txt`.

---

## Phase breakdown (from INFO markers, 1 s log resolution)

| Phase | Duration | % of ~137 s |
|-------|----------|-------------|
| Instance prep → CA subsystem created | ~1 s | 1% |
| Configure / create / **init database** | **~26 s** | **19%** |
| *(profile import marker missing in log; included in DB window)* | | |
| Deploy CA webapp → start system certs | ~0 s | — |
| **System certs** (signing → … → subsystem) | **~64 s** | **47%** |
| **Admin cert + admin user** (9 group adds, etc.) | **~34 s** | **25%** |
| **Tomcat start + readiness** | **~12 s** | **9%** |
| Final manifest / summary | ~0 s | — |

The dominant cost is **certificate + admin LDAP work** (~72 s, ~53%), then **database init/index** (~26 s), then **Tomcat** (~12 s).

---

## Subprocess inventory (`pkispawn --debug`)

| Type | Count |
|------|------|
| **pki-server** | **32** |
| **pki CLI** (`pki nss-*`, etc.) | **36** |
| filesystem (cp/mkdir/ln) | 26 |
| systemctl | 3 |
| certutil | 1 |
| other | 37 |
| **Total `DEBUG: Command:`** | **99** |

### pki-server subcommands (spawn)

| Subcommand | Count | Est. span until next pki-server call* |
|------------|------:|--------------------------------------:|
| ca-group-member-add | 11 | **26 s** (med ~2 s each) |
| ca-cert-import | 4 | 38 s† |
| ca-cert-request-import | 4 | 10 s |
| ca-user-add | 2 | 6 s |
| ca-user-cert-add | 2 | 4 s |
| ca-db-init | 1 | 11 s |
| ca-profile-import | 1 | 6 s |
| ca-db-index-rebuild | 1 | 3 s |
| ca-db-remove/create/index-add | 3 | 7 s |
| ca-sd-create / ca-sd-subsystem-add | 2 | 9 s |
| ca-range-update | 1 | 13 s |

\*From timestamp gaps in `spawn-debug-timestamped.log` (1 s resolution; includes NSS/LDAP work between CLI calls).

†`ca-cert-import` gaps include preceding `pki nss-*` work, not just import.

### pki CLI (spawn)

| Command | Count |
|---------|------:|
| nss-cert-export | 16 |
| nss-cert-show | 14 |
| other | 6 |

Each system cert does export/show validation loops in addition to keygen/request/create.

---

## Micro-benchmarks: cost of one `pki-server` invocation (CA already running)

5 runs, stdout discarded, time from GNU `time` on stderr:

| Command | Avg (s) |
|---------|--------:|
| `pki-server --help` | **0.58** |
| `pki-server … ca-cert-request-find` | **0.60** |
| `pki-server … ca-db-index-rebuild` | **1.08** |
| `pki-server … ca-group-find` | **1.98** |
| `pki-server … ca-user-show` | **1.92** |
| `pki-server … ca-group-member-add` | **2.44** |

| Command | Avg (s) |
|---------|--------:|
| `pki nss-key-create --help` | **0.84** |

**Interpretation:** Every `pki-server` call pays roughly **0.6–1.0 s** fixed cost (Python + JVM + config load) plus **~1–1.5 s** LDAP/admin work for typical mutating commands.

**Spawn math (pki-server only):**

- 11 × `ca-group-member-add` @ 2.44 s ≈ **27 s** — matches log span (~26 s).
- If group adds were one batched API/CLI: ~2.5 s → **~24 s saved** on this path alone.
- 32 invocations × ~0.7 s fixed overhead ≈ **22 s** of pure process/JVM churn (upper bound if work were in-process).

---

## Other facts

- **105** CA profile `.cfg` files under `/usr/share/pki/ca/profiles/ca`; `ca-profile-import` runs once per spawn (~6 s in phase log).
- **Random** cert/request ID generators (default): Tomcat starts **once** at end (no legacy double-start).
- `strace` not available inside `pki` image; host-side strace not run.

---

## Conclusions for optimization

1. **`pki-server` batching is the highest-leverage spawn change** — confirmed by micro-benchmarks (~2 s × 11 group adds, ~32 JVM startups per spawn).
2. **System cert path** — 4 certs × (key + request + 2× pki-server import/create + many nss export/show) ≈ **64 s**; reduce round-trips and redundant nss export/show validation.
3. **Database** — init + index rebuild ≈ **19–26 s**; consider skip flags for CI/dev or pre-seeded DS.
4. **Profile import** — 105 profiles / ~6 s; import subset or defer for test configs.
5. **Tomcat** — ~12 s; tune readiness polling and startup, secondary to CLI/LDAP.

Suggested next implementation targets (when coding):

- `ca-group-member-add-many` or LDAP modify in one `pki-server` process session.
- Reuse one `pki-server` / in-process deployment API for cert create + import sequence.
- Drop redundant `nss-cert-export`/`nss-cert-show` pairs during spawn when not needed.
