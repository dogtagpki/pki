#!/usr/bin/env python3
"""Analyze timestamped pkispawn --debug output."""

import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

LINE_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)")
DEBUG_CMD = re.compile(r"DEBUG: Command: (.+)$")
INFO_LINE = re.compile(r"INFO: (.+)$")

PHASE_MARKERS = [
    ("1_instance_start", "Preparing pki-tomcat instance"),
    ("2_ca_subsystem", "Creating CA subsystem"),
    ("3_system_keys", "Generating system keys"),
    ("4_configure_db", "Configuring CA database"),
    ("5_create_db", "Creating database"),
    ("6_init_db", "Initializing database"),
    ("7_profile_import", "Importing profiles"),
    ("8_deploy_ca", "Deploying ca web application"),
    ("9_system_certs", "Setting up system certs"),
    ("10_signing_cert", "Setting up signing cert"),
    ("11_admin_cert", "Setting up admin cert"),
    ("12_admin_user", "Setting up admin user"),
    ("13_ca_done", "CA configuration complete"),
    ("14_tomcat_start", "Starting PKI server"),
    ("15_tomcat_up", "PKI server started"),
    ("16_subsystem_up", "Subsystem status: running"),
]

PKI_SERVER_SUB = re.compile(r"pki-server -i \S+ (\S+)")


def parse_line_ts(line: str):
    m = LINE_TS.match(line)
    if not m:
        return None
    sec = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    frac = int(m.group(2)[:6].ljust(6, "0"))  # use first 6 digits as microseconds
    return sec.replace(microsecond=frac)


def strip_prefix(line: str) -> str:
    m = LINE_TS.match(line)
    if m:
        rest = line[m.end() :].lstrip()
        return rest
    return line


def classify_pki_server(cmd: str) -> str:
    m = PKI_SERVER_SUB.search(cmd)
    return m.group(1) if m else "pki-server (other)"


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "benchmarks/spawn-debug-timestamped.log")
    lines = path.read_text(errors="replace").splitlines()

    commands = []  # (ts, cmd)
    phases = []  # (ts, name, info)
    for line in lines:
        ts = parse_line_ts(line)
        body = strip_prefix(line)

        m = DEBUG_CMD.search(body)
        if m and ts:
            cmd = m.group(1).strip()
            commands.append((ts, cmd))
            continue

        for key, needle in PHASE_MARKERS:
            if needle in body:
                phases.append((ts, key, needle))
                break

    t0 = parse_line_ts(lines[0]) if lines else None
    t1 = parse_line_ts(lines[-1]) if lines else None

    print(f"Log: {path}")
    if t0 and t1:
        print(f"Wall clock: {(t1 - t0).total_seconds():.1f}s")
    print(f"DEBUG Command: lines: {len(commands)}")
    print()

    pki_cli_counts = defaultdict(int)
    for line in lines:
        body = strip_prefix(line)
        if "DEBUG: Command: pki " in body:
            cmd = body.split("DEBUG: Command: ", 1)[1]
            if "nss-key-create" in cmd:
                pki_cli_counts["nss-key-create"] += 1
            elif "nss-cert-request" in cmd:
                pki_cli_counts["nss-cert-request"] += 1
            elif "nss-cert-export" in cmd:
                pki_cli_counts["nss-cert-export"] += 1
            elif "nss-cert-show" in cmd:
                pki_cli_counts["nss-cert-show"] += 1
            else:
                pki_cli_counts["pki other"] += 1

    by_type = defaultdict(int)
    for _, cmd in commands:
        if cmd.startswith("pki-server"):
            by_type["pki-server"] += 1
        elif cmd.startswith("pki "):
            by_type["pki CLI"] += 1
        elif " runuser " in cmd and " pki " in cmd:
            by_type["pki CLI (runuser)"] += 1
        elif cmd.startswith("certutil"):
            by_type["certutil"] += 1
        elif cmd.startswith("systemctl"):
            by_type["systemctl"] += 1
        elif cmd.startswith(("cp ", "mkdir", "ln ")):
            by_type["filesystem"] += 1
        else:
            by_type["other"] += 1

    print("=== Command counts by type ===")
    for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {k:<25} {v:4}")
    print(f"  {'TOTAL':<25} {len(commands):4}")
    if pki_cli_counts:
        print()
        print("=== pki CLI (DEBUG: Command: pki ...) ===")
        for k, v in sorted(pki_cli_counts.items(), key=lambda x: -x[1]):
            print(f"  {k:<25} {v:4}")
        print(f"  {'TOTAL pki CLI':<25} {sum(pki_cli_counts.values()):4}")
    print()

    print("=== pki-server subcommand counts ===")
    ps_counts = defaultdict(int)
    for _, cmd in commands:
        if "pki-server" in cmd:
            ps_counts[classify_pki_server(cmd)] += 1
    total_ps = sum(ps_counts.values())
    for sub, cnt in sorted(ps_counts.items(), key=lambda x: -x[1]):
        print(f"  {sub:<35} count={cnt:3}")
    print(f"  {'(all pki-server)':<35} count={total_ps:3}")
    print()

    print("=== Phase timeline (INFO markers, 1s resolution from ts) ===")
    prev = None
    phase_durations = []
    for ts, key, label in phases:
        if prev and ts and prev[0]:
            d = (ts - prev[0]).total_seconds()
            phase_durations.append((prev[1], d))
            print(f"  {prev[1]:<22} {d:6.1f}s  ({prev[2]})")
        prev = (ts, key, label)
    if prev and t1 and prev[0]:
        d = (t1 - prev[0]).total_seconds()
        print(f"  {prev[1]:<22} {d:6.1f}s  ({prev[2]} -> end)")
    print()

    # Sum time in cert-related pki-server ops (rough)
    cert_ops = [
        "ca-cert-create",
        "ca-cert-request-import",
        "ca-cert-import",
        "ca-user-add",
        "ca-group-member-add",
        "ca-user-cert-add",
        "ca-profile-import",
    ]
    cert_count = sum(ps_counts.get(o, 0) for o in cert_ops)
    print(f"pki-server cert/admin/LDAP ops (listed types): {cert_count} invocations")
    print()

    # Time each pki-server invocation by pairing consecutive command timestamps
    print("=== pki-server per-invocation duration (ts delta to next Command:) ===")
    ps_cmds = [(t, c) for t, c in commands if "pki-server" in c]
    inv_durations = defaultdict(list)
    for i, (t, c) in enumerate(ps_cmds):
        sub = classify_pki_server(c)
        if i + 1 < len(ps_cmds):
            dt = (ps_cmds[i + 1][0] - t).total_seconds()
        elif t1:
            dt = (t1 - t).total_seconds()
        else:
            dt = 0
        if 0 <= dt < 60:
            inv_durations[sub].append(dt)

    total_ps_time = 0.0
    for sub in sorted(inv_durations.keys(), key=lambda s: -sum(inv_durations[s])):
        durs = inv_durations[sub]
        s = sum(durs)
        total_ps_time += s
        med = sorted(durs)[len(durs) // 2]
        print(
            f"  {sub:<35} n={len(durs):3}  total={s:6.1f}s  "
            f"avg={s/len(durs):5.2f}s  med={med:5.2f}s"
        )
    print(f"  {'SUM (overlapping gaps)':<35}      total={total_ps_time:6.1f}s")
    print("  (Durations are gaps until next pki-server call; includes work between calls.)")


if __name__ == "__main__":
    main()
