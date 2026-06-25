# PKI startup baseline

Recorded on **StartupOptimization** branch for comparing spawn/install optimizations.

## Environment

| Field | Value |
|-------|-------|
| Date | 2026-06-01 |
| Host | agaragna-thinkpadp1gen7.rmtit.csb |
| Git commit | `60dc2ac8e0` |
| Scripts | `../IDM-CI/bash/pki-create.sh`, `../IDM-CI/bash/pki-spawn.sh` |
| Config | `/usr/share/pki/server/examples/installation/ca.cfg` |
| PKI image | `pki-builder:latest` (pre-existing; full rebuild attempted separately) |

Commands were run from the PKI repo root with `-x` (trace) as requested.

## Results

| Step | Command | Wall time | Notes |
|------|---------|-----------|-------|
| **pki-create (with build)** | `pki-create.sh -x` | **639.8 s** (~10.7 min) | **Failed** at `docker build` export (containerd mount lock). RPM build inside image completed. Not representative of build speed on fast CI. |
| **pki-create (skip build)** | `pki-create.sh -x -s` | **34.0 s** | DS + `runner-init` + `dnf install build/RPMS/*`. Used existing `pki-builder` image. |
| **pki-spawn (full script)** | `pki-spawn.sh -x …/ca.cfg` | **157.5 s** (~2.6 min) | `pkispawn` + `cert-export` + `nss-cert-import` + `pkcs12-import` |
| **pkispawn only** | `docker exec pki pkispawn …` | **119.6 s** (~2.0 min) | Warm container, same CA config; post-spawn steps ≈ **38 s** |

### pki-spawn breakdown (approximate)

| Phase | Time |
|-------|------|
| `pkispawn` (CA install) | ~120 s |
| Post-spawn (`cert-export`, `nss-cert-import`, `pkcs12-import`) | ~38 s |
| **Total `pki-spawn.sh`** | **~158 s** |

## Reproduce

```bash
cd /path/to/pki

# Full log (trace) appended to benchmarks/startup-baseline.log
benchmarks/run-startup-baseline.sh

# Or manually:
/usr/bin/time ../IDM-CI/bash/pki-create.sh -x -s    # use -s if image already built
/usr/bin/time ../IDM-CI/bash/pki-spawn.sh -x /usr/share/pki/server/examples/installation/ca.cfg
```

## Notes

- **Build time** is dominated by network downloads on this host; treat `pki-create` **without** `-s` as informational only until a successful local image export exists.
- **Spawn baseline** to track for optimization work: **~120 s** (`pkispawn`) / **~158 s** (`pki-spawn.sh` end-to-end) on this setup.
- Raw trace log: `benchmarks/startup-baseline.log`
