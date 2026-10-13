#!/usr/bin/env python3
"""Scoped AD/CTF inventory and evidence organizer.

The only active network operation is an explicitly confirmed, single-IP TCP
service inventory via a fixed Nmap profile. No credential attacks, directory
collection, relay, exploitation, remote execution, or secret dumping are run.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import uuid
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

APP_NAME = "autopwn"
STAGES = ("recon", "foothold", "priv_esc", "flags", "lessons_learned")
STAGE_LABELS = {
    "recon": "Recon",
    "foothold": "Foothold",
    "priv_esc": "Privilege escalation",
    "flags": "Flags",
    "lessons_learned": "Lessons learned",
}
STAGE_STATES = ("not_started", "in_progress", "complete", "blocked")
SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_XML_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_LOG_CHARS = 100_000
AUTH_PHRASE = "I am authorized to test this target"
RESTORE_PHRASE = "RESTORE AUTOPWN DATABASE"
# Fixed, TCP-only AD/service inventory. No NSE scripts, UDP, port ranges,
# user-supplied Nmap flags, target lists, CIDRs, or address expansion.
AD_TCP_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985,9389"

_SECRET_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|hash|ntlm_hash)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_KERBEROS_HASH = re.compile(r"(?i)\$krb5(?:asrep|tgs)\$[^\s]+")
_LONG_HEX = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])")
_BH_CATEGORIES = {
    "users", "computers", "groups", "domains", "ous", "gpos",
    "containers", "sessions", "acls", "trusts", "localgroups",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_db_path() -> Path:
    root = Path(os.environ.get("AUTOPWN_HOME", str(Path.home() / ".local" / "share" / APP_NAME)))
    return root / "state.sqlite3"


def redact(text: str) -> str:
    """Best-effort redaction for common pasted secret/hash formats."""
    text = _KERBEROS_HASH.sub("[REDACTED KERBEROS HASH]", text)
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    return _LONG_HEX.sub("[REDACTED HEX VALUE]", text)


def safe_text(value: object, limit: int = 1000) -> str:
    text = str(value or "—")
    return "".join(ch if ch.isprintable() else " " for ch in text)[:limit]


def connect_db(path: Path) -> sqlite3.Connection:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS targets (
            target TEXT PRIMARY KEY,
            domain TEXT,
            dc TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scopes (
            target TEXT PRIMARY KEY REFERENCES targets(target) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            reference TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stages (
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (target, name)
        );
        CREATE TABLE IF NOT EXISTS hosts (
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            address TEXT NOT NULL,
            hostname TEXT,
            state TEXT,
            PRIMARY KEY (target, address)
        );
        CREATE TABLE IF NOT EXISTS services (
            target TEXT NOT NULL,
            address TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT,
            name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            PRIMARY KEY (target, address, protocol, port),
            FOREIGN KEY (target, address) REFERENCES hosts(target, address) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            stage TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            stage TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            at TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            source_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL REFERENCES targets(target) ON DELETE CASCADE,
            command_json TEXT NOT NULL,
            xml_path TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            return_code INTEGER,
            stdout TEXT,
            stderr TEXT
        );
        """
    )
    return db


def require_target(db: sqlite3.Connection, target: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM targets WHERE target = ?", (target,)).fetchone()
    if row is None:
        raise ValueError(f"Target {target!r} is not in the local store; run: autopwn.py add-target {target!r}")
    return row


def record_event(db: sqlite3.Connection, target: str, kind: str, message: str) -> None:
    db.execute(
        "INSERT INTO events(target, at, kind, message) VALUES (?, ?, ?, ?)",
        (target, now_utc(), kind, safe_text(redact(message))),
    )


def cmd_add_target(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    target = args.target.strip()
    if not target or any(ch.isspace() for ch in target):
        raise ValueError("Target must be a non-empty IP address, hostname, or domain without whitespace")
    existed = db.execute("SELECT 1 FROM targets WHERE target = ?", (target,)).fetchone() is not None
    stamp = now_utc()
    db.execute(
        "INSERT INTO targets(target, created_at, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(target) DO UPDATE SET updated_at = excluded.updated_at",
        (target, stamp, stamp),
    )
    for stage in STAGES:
        db.execute(
            "INSERT OR IGNORE INTO stages(target, name, status, updated_at) VALUES (?, ?, ?, ?)",
            (target, stage, "not_started", stamp),
        )
    record_event(db, target, "target", "Target record updated" if existed else "Target record created")
    print(f"{'Updated' if existed else 'Added'} local workspace for {target}")


def cmd_set_domain(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    db.execute("UPDATE targets SET domain = ?, updated_at = ? WHERE target = ?", (args.domain, now_utc(), args.target))
    record_event(db, args.target, "metadata", f"Domain set to {args.domain}")
    print(f"Domain recorded for {args.target}: {args.domain}")


def cmd_set_dc(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    db.execute("UPDATE targets SET dc = ?, updated_at = ? WHERE target = ?", (args.hostname, now_utc(), args.target))
    record_event(db, args.target, "metadata", f"DC identity set to {args.hostname}")
    print(f"DC identity recorded for {args.target}: {args.hostname}")


def validate_scan_ip(target: str) -> str:
    """Limit active scanning to one literal unicast IP, never a range or hostname."""
    if not target or target != target.strip() or "%" in target:
        raise ValueError("For scan-ad, supply one literal IPv4/IPv6 address (no whitespace or scope suffix)")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("For scan-ad, supply one literal IP address; hostnames, CIDRs, ranges, and lists are not accepted") from exc
    if address.is_multicast or address.is_unspecified or getattr(address, "is_reserved", False):
        raise ValueError("Refusing multicast, unspecified, or reserved scan targets")
    return str(address)


def cmd_scope_add(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    target = validate_scan_ip(args.target)
    if target != args.target:
        raise ValueError(f"Use the canonical IP spelling for this workspace: {target}")
    try:
        expires_on = date.fromisoformat(args.expires)
    except ValueError as exc:
        raise ValueError("--expires must be a date in YYYY-MM-DD format") from exc
    if expires_on < datetime.now(timezone.utc).date():
        raise ValueError("Scope expiry must be today or a future UTC date")
    expires_at = datetime.combine(expires_on, datetime.min.time(), tzinfo=timezone.utc).replace(
        hour=23, minute=59, second=59
    ).isoformat(timespec="seconds")
    reference = safe_text(redact((args.reference or "self-attested lab authorization").strip()), 240).strip()
    if not reference or reference == "—":
        reference = "self-attested lab authorization"
    stamp = now_utc()
    db.execute(
        "INSERT INTO scopes(target,expires_at,reference,created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(target) DO UPDATE SET expires_at=excluded.expires_at,reference=excluded.reference,created_at=excluded.created_at",
        (target, expires_at, reference, stamp),
    )
    record_event(db, target, "scope", f"Authorized single-IP inventory scope until {expires_at}; reference: {reference}")
    print(f"Scope recorded for {target} through {expires_at} (UTC). The per-scan confirmation is still required.")


def cmd_scope_list(db: sqlite3.Connection, _args: argparse.Namespace) -> None:
    rows = db.execute("SELECT target,expires_at,reference FROM scopes ORDER BY target").fetchall()
    if not rows:
        print("No authorized scan scopes recorded.")
        return
    now = datetime.now(timezone.utc)
    for row in rows:
        active = datetime.fromisoformat(row["expires_at"]) > now
        print(f"{safe_text(row['target'])}  {'ACTIVE' if active else 'EXPIRED'} through {safe_text(row['expires_at'])}  [{safe_text(row['reference'], 240)}]")


def cmd_scope_revoke(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    existing = db.execute("SELECT 1 FROM scopes WHERE target=?", (args.target,)).fetchone()
    if existing is None:
        print(f"No scope entry exists for {args.target}")
        return
    db.execute("DELETE FROM scopes WHERE target=?", (args.target,))
    record_event(db, args.target, "scope", "Authorized scan scope revoked")
    print(f"Revoked scan scope for {args.target}")


def require_active_scope(db: sqlite3.Connection, target: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM scopes WHERE target=?", (target,)).fetchone()
    if row is None:
        raise PermissionError(f"No scope authorization recorded for {target}; add one with scope-add before scanning")
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
        raise PermissionError(f"Scope authorization for {target} has expired; renew it before scanning")
    return row


def confirm_authorization(target: str) -> None:
    print(f"\nActive TCP service inventory will be run only against {target}.")
    print("It checks a fixed list of common AD TCP ports using Nmap service detection.")
    if not sys.stdin.isatty():
        raise PermissionError("Interactive authorization confirmation is required; no scan was started")
    try:
        response = input(f'Type exactly "{AUTH_PHRASE}" to continue: ')
    except EOFError as exc:
        raise PermissionError("No authorization confirmation received; no scan was started") from exc
    if response != AUTH_PHRASE:
        raise PermissionError("Authorization phrase did not match; hard stop, no scan was started")


def nmap_address(host: ET.Element) -> str | None:
    addresses = host.findall("address")
    for preferred in ("ipv4", "ipv6", "mac"):
        for address in addresses:
            if address.get("addrtype") == preferred and address.get("addr"):
                return address.get("addr")
    return None


def nmap_hostname(host: ET.Element) -> str | None:
    for name in host.findall("./hostnames/hostname"):
        if name.get("name"):
            return name.get("name")
    return None


def import_nmap_xml(db: sqlite3.Connection, target: str, source: Path, *, log_event: bool = True) -> tuple[int, int]:
    source = source.expanduser()
    if not source.is_file():
        raise ValueError(f"Nmap XML file does not exist: {source}")
    if source.stat().st_size > MAX_XML_BYTES:
        raise ValueError(f"Nmap XML exceeds the {MAX_XML_BYTES // (1024 * 1024)} MiB import limit")
    try:
        root = ET.parse(source).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Expected an Nmap XML document with an <nmaprun> root")

    hosts_seen = 0
    services_seen = 0
    for host in root.findall("host"):
        address = nmap_address(host)
        if not address:
            continue
        hostname = nmap_hostname(host)
        status_element = host.find("status")
        host_state = status_element.get("state") if status_element is not None else None
        db.execute(
            "INSERT INTO hosts(target, address, hostname, state) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(target, address) DO UPDATE SET "
            "hostname = COALESCE(excluded.hostname, hosts.hostname), state = COALESCE(excluded.state, hosts.state)",
            (target, address, hostname, host_state),
        )
        hosts_seen += 1
        for port_node in host.findall("./ports/port"):
            protocol = port_node.get("protocol", "unknown")
            try:
                port = int(port_node.get("portid", ""))
            except ValueError:
                continue
            if not 0 <= port <= 65535:
                continue
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state") if state_node is not None else None
            attrs = service_node.attrib if service_node is not None else {}
            db.execute(
                """INSERT INTO services(target, address, protocol, port, state, name, product, version, extra_info)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(target, address, protocol, port) DO UPDATE SET
                   state=excluded.state, name=excluded.name, product=excluded.product,
                   version=excluded.version, extra_info=excluded.extra_info""",
                (
                    target, address, protocol, port, state,
                    attrs.get("name"), attrs.get("product"), attrs.get("version"), attrs.get("extrainfo"),
                ),
            )
            services_seen += 1
    if log_event:
        record_event(db, target, "import", f"Imported Nmap XML {source.name}: {hosts_seen} hosts, {services_seen} service records")
    return hosts_seen, services_seen


def cmd_import_nmap(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    hosts, services = import_nmap_xml(db, args.target, args.xml)
    print(f"Imported {hosts} host(s) and {services} service record(s) from {args.xml.name}")


def clipped_log(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = redact(value)
    if len(value) > MAX_LOG_CHARS:
        value = value[:MAX_LOG_CHARS] + "\n[log truncated]"
    return value


def update_scan_run(
    db: sqlite3.Connection,
    run_id: str,
    status: str,
    *,
    return_code: int | None = None,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
) -> None:
    db.execute(
        "UPDATE scan_runs SET status = ?, finished_at = ?, return_code = ?, stdout = ?, stderr = ? WHERE id = ?",
        (status, now_utc(), return_code, clipped_log(stdout), clipped_log(stderr), run_id),
    )


def cmd_scan_ad(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    target = validate_scan_ip(args.target)
    if target != args.target:
        raise ValueError(f"Use the canonical IP spelling for this workspace: {target}")
    require_active_scope(db, target)
    confirm_authorization(target)
    nmap = shutil.which("nmap")
    if not nmap:
        raise ValueError("Nmap is not installed. On Kali, install it with: sudo apt install nmap")
    pending = db.execute(
        "SELECT id FROM scan_runs WHERE target = ? AND status = 'running' ORDER BY started_at DESC LIMIT 1",
        (target,),
    ).fetchone()
    if pending:
        raise ValueError(f"An unfinished scan run ({pending['id']}) exists; use resume before starting another")

    run_id = uuid.uuid4().hex[:12]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target_slug = target.replace(":", "_").replace(".", "_")
    scan_dir = args.db.expanduser().resolve().parent / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    xml_path = (scan_dir / f"{stamp}_{target_slug}_{run_id}.xml").resolve()
    command = [
        nmap, "-n", "-sT", "-sV", "-T2", "--max-retries", "1",
        "--host-timeout", "12m", "-p", AD_TCP_PORTS, "-oX", str(xml_path), target,
    ]
    started = now_utc()
    db.execute(
        "INSERT INTO scan_runs(id,target,command_json,xml_path,status,started_at) VALUES(?,?,?,?,?,?)",
        (run_id, target, json.dumps(command), str(xml_path), "running", started),
    )
    record_event(db, target, "scan-start", f"Started guarded Nmap inventory run {run_id}")
    # Commit the checkpoint before starting the external process so a killed
    # orchestrator can still find the run and its expected XML file.
    db.commit()
    print(f"Starting Nmap inventory run {run_id} for {target} (TCP AD/service ports only).")
    print(f"Checkpoint: {xml_path}")

    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        stdout, stderr = process.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = "", ""
        update_scan_run(db, run_id, "timed_out", stdout=stdout, stderr=stderr)
        record_event(db, target, "scan-timeout", f"Nmap inventory run {run_id} timed out; use resume to recover a complete XML checkpoint if present")
        print(f"Scan timed out. Logs/checkpoint are local; try `autopwn.py resume {target}` to recover complete output.")
        return
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
        else:
            stdout, stderr = "", ""
        update_scan_run(db, run_id, "interrupted", stdout=stdout, stderr=stderr)
        record_event(db, target, "scan-interrupted", f"Nmap inventory run {run_id} interrupted; use resume to recover a complete XML checkpoint if present")
        print(f"Scan interrupted. No later stage was run; use `autopwn.py resume {target}` to check its local checkpoint.")
        return
    except OSError as exc:
        update_scan_run(db, run_id, "failed", stderr=str(exc))
        record_event(db, target, "scan-failed", f"Nmap inventory run {run_id} could not start")
        raise ValueError(f"Could not start Nmap: {exc}") from exc

    if not xml_path.exists():
        update_scan_run(db, run_id, "failed", return_code=process.returncode, stdout=stdout, stderr=stderr)
        record_event(db, target, "scan-failed", f"Nmap inventory run {run_id} produced no XML checkpoint")
        raise ValueError("Nmap produced no XML output; inspect `history` and `scan-log` for this run")
    try:
        hosts, services = import_nmap_xml(db, target, xml_path, log_event=False)
    except ValueError as exc:
        update_scan_run(db, run_id, "partial", return_code=process.returncode, stdout=stdout, stderr=stderr)
        record_event(db, target, "scan-partial", f"Nmap run {run_id} left XML that is not yet importable; use resume after checking the local file")
        print(f"Nmap ended with an incomplete checkpoint: {exc}")
        return

    status = "complete" if process.returncode == 0 else "partial"
    update_scan_run(db, run_id, status, return_code=process.returncode, stdout=stdout, stderr=stderr)
    stamp = now_utc()
    recon_status = "complete" if status == "complete" else "in_progress"
    db.execute(
        "INSERT INTO stages(target,name,status,updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(target,name) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at",
        (target, "recon", recon_status, stamp),
    )
    db.execute("UPDATE targets SET updated_at=? WHERE target=?", (stamp, target))
    record_event(db, target, "scan-complete" if status == "complete" else "scan-partial",
                 f"Nmap inventory run {run_id} {status}: {hosts} host(s), {services} service record(s)")
    print(f"Nmap {status}: {hosts} host(s), {services} service record(s). Run ID: {run_id}")


def cmd_resume(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    rows = db.execute(
        "SELECT * FROM scan_runs WHERE target=? AND status IN ('running','timed_out','interrupted','partial','failed') ORDER BY started_at DESC",
        (args.target,),
    ).fetchall()
    if not rows:
        print("No interrupted or incomplete local scan checkpoints to recover.")
        return
    recovered = 0
    for run in rows:
        path = Path(run["xml_path"])
        if not path.is_file():
            continue
        try:
            hosts, services = import_nmap_xml(db, args.target, path, log_event=False)
        except (ValueError, OSError):
            continue
        recovered_at = now_utc()
        db.execute("UPDATE scan_runs SET status='recovered',finished_at=? WHERE id=?", (recovered_at, run["id"]))
        db.execute(
            "INSERT INTO stages(target,name,status,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(target,name) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at",
            (args.target, "recon", "in_progress", recovered_at),
        )
        record_event(db, args.target, "scan-recovered", f"Recovered local Nmap XML checkpoint from run {run['id']}: {hosts} host(s), {services} service record(s)")
        recovered += 1
        print(f"Recovered run {run['id']}: {hosts} host(s), {services} service record(s). Review the partial-run status before relying on it.")
    if recovered == 0:
        print("No complete, parseable XML checkpoint found. No scan was restarted; run scan-ad again only after confirming scope.")


def cmd_scan_log(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    row = db.execute("SELECT * FROM scan_runs WHERE id=? AND target=?", (args.run_id, args.target)).fetchone()
    if row is None:
        raise ValueError(f"No local scan run {args.run_id!r} for {args.target}")
    print(f"Run: {row['id']}\nStatus: {row['status']}\nStarted: {row['started_at']}\nFinished: {row['finished_at'] or '—'}\nReturn code: {row['return_code']}")
    print(f"XML checkpoint: {row['xml_path']}\nCommand: {row['command_json']}")
    print("\n--- stdout ---\n" + (row["stdout"] or ""))
    print("\n--- stderr ---\n" + (row["stderr"] or ""))


def read_nmap_service_map(source: Path) -> dict[tuple[str, str, int], tuple[str | None, str | None, str | None, str | None, str | None]]:
    source = source.expanduser()
    if not source.is_file() or source.stat().st_size > MAX_XML_BYTES:
        raise ValueError(f"Missing or oversized Nmap XML checkpoint: {source}")
    try:
        root = ET.parse(source).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse Nmap XML checkpoint {source.name}: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"Not an Nmap XML checkpoint: {source.name}")
    services: dict[tuple[str, str, int], tuple[str | None, str | None, str | None, str | None, str | None]] = {}
    for host in root.findall("host"):
        address = nmap_address(host)
        if not address:
            continue
        for port_node in host.findall("./ports/port"):
            try:
                port = int(port_node.get("portid", ""))
            except ValueError:
                continue
            if not 0 <= port <= 65535:
                continue
            state_node, service_node = port_node.find("state"), port_node.find("service")
            attrs = service_node.attrib if service_node is not None else {}
            services[(address, port_node.get("protocol", "unknown"), port)] = (
                state_node.get("state") if state_node is not None else None,
                attrs.get("name"), attrs.get("product"), attrs.get("version"), attrs.get("extrainfo"),
            )
    return services


def terminal_text(value: object) -> str:
    return safe_text(value, 240)


def cmd_scan_diff(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    runs = []
    for run_id in (args.older_run_id, args.newer_run_id):
        row = db.execute("SELECT * FROM scan_runs WHERE id=? AND target=?", (run_id, args.target)).fetchone()
        if row is None:
            raise ValueError(f"No local scan run {run_id!r} for {args.target}")
        if row["status"] not in {"complete", "partial", "recovered"}:
            raise ValueError(f"Scan run {run_id!r} is not a finished, importable checkpoint (status: {row['status']})")
        runs.append((row, read_nmap_service_map(Path(row["xml_path"]))))
    older, newer = runs
    record_event(db, args.target, "scan-diff", f"Compared local inventory runs {older[0]['id']} and {newer[0]['id']}")
    before, after = older[1], newer[1]
    added, removed = sorted(after.keys() - before.keys()), sorted(before.keys() - after.keys())
    changed = sorted(key for key in before.keys() & after.keys() if before[key] != after[key])
    print(f"Offline inventory diff: {older[0]['id']} -> {newer[0]['id']}")
    if not added and not removed and not changed:
        print("No service inventory changes.")
        return
    for label, keys, mapping in (("Added", added, after), ("Removed", removed, before)):
        for address, protocol, port in keys:
            state, name, product, version, extra = mapping[(address, protocol, port)]
            description = " ".join(filter(None, (name, product, version, extra)))
            print(f"{label}: {terminal_text(address)} {terminal_text(protocol)}/{port} [{terminal_text(state)}] {terminal_text(description)}")
    for address, protocol, port in changed:
        before_values, after_values = before[(address, protocol, port)], after[(address, protocol, port)]
        print(f"Changed: {terminal_text(address)} {terminal_text(protocol)}/{port}")
        print(f"  Before: {terminal_text(' '.join(filter(None, before_values)))}")
        print(f"  After:  {terminal_text(' '.join(filter(None, after_values)))}")


def count_items(value: object) -> int:
    if isinstance(value, (list, dict)):
        return len(value)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    return 0


def summarize_offline_json(payload: object, requested_kind: str) -> tuple[str, dict[str, int | str]]:
    """Return counts/category only; never retain object names, edges, or raw JSON."""
    if requested_kind == "auto":
        if isinstance(payload, dict) and isinstance(payload.get("meta"), dict) and isinstance(payload.get("data"), list):
            kind = "bloodhound"
        elif isinstance(payload, dict) and any("certificate" in str(k).lower() or "vulnerab" in str(k).lower() for k in payload):
            kind = "certipy"
        else:
            kind = "json-summary"
    else:
        kind = requested_kind

    summary: dict[str, int | str] = {}
    if kind == "bloodhound":
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
            raw_category = str(meta.get("type", "records")).lower()
            category = raw_category if raw_category in _BH_CATEGORIES else "records"
            summary[f"{category}_records"] = len(payload["data"])
        elif isinstance(payload, list):
            summary["records"] = len(payload)
        else:
            raise ValueError("Expected a BloodHound JSON data array; no object details were imported")
    elif kind == "certipy":
        if isinstance(payload, dict):
            for key, value in payload.items():
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if "template" in normalized and ("cert" in normalized or normalized.endswith("templates")):
                    summary["certificate_template_records"] = count_items(value)
                elif "authority" in normalized or normalized in {"cas", "certificateauthorities"}:
                    summary["certificate_authority_records"] = count_items(value)
                elif "vulnerab" in normalized:
                    summary["items_marked_vulnerable"] = count_items(value)
        elif isinstance(payload, list):
            summary["records"] = len(payload)
        else:
            raise ValueError("Expected a Certipy JSON object or array; no object details were imported")
        if not summary:
            summary["recognized_sections"] = 0
    else:
        if isinstance(payload, dict):
            summary["top_level_sections"] = len(payload)
        elif isinstance(payload, list):
            summary["records"] = len(payload)
        else:
            summary["scalar_values"] = 1
    return kind, summary


def cmd_import_report(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    source = args.json_file.expanduser()
    if not source.is_file():
        raise ValueError(f"JSON file does not exist: {source}")
    if source.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON file exceeds the {MAX_JSON_BYTES // (1024 * 1024)} MiB import limit")
    raw = source.read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"JSON file exceeds the {MAX_JSON_BYTES // (1024 * 1024)} MiB import limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse UTF-8 JSON: {exc}") from exc
    kind, summary = summarize_offline_json(payload, args.kind)
    fingerprint = hashlib.sha256(raw).hexdigest()
    stamp = now_utc()
    db.execute(
        "INSERT INTO imports(target,source_name,kind,sha256,summary_json,created_at) VALUES(?,?,?,?,?,?)",
        (args.target, source.name, kind, fingerprint, json.dumps(summary, sort_keys=True), stamp),
    )
    record_event(db, args.target, "offline-import", f"Imported metadata-only {kind} summary from {source.name}; raw JSON was not stored")
    print(f"Imported {kind} summary from {source.name}; raw JSON and object-level details were not stored.")
    print(json.dumps(summary, indent=2, sort_keys=True))


def cmd_add_note(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    title, body = redact(args.title), redact(args.body)
    db.execute(
        "INSERT INTO notes(target, stage, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (args.target, args.stage, title, body, now_utc()),
    )
    record_event(db, args.target, "note", f"Added note in {args.stage}: {title}")
    print("Note saved locally (common secret/hash patterns are redacted on a best-effort basis).")


def cmd_add_finding(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    title, detail = redact(args.title), redact(args.detail)
    db.execute(
        "INSERT INTO findings(target, stage, title, detail, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (args.target, args.stage, title, detail, args.severity, args.status, now_utc()),
    )
    record_event(db, args.target, "finding", f"Added {args.severity} finding in {args.stage}: {title}")
    print("Finding saved locally.")


def cmd_set_stage(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    stamp = now_utc()
    db.execute(
        "INSERT INTO stages(target, name, status, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(target, name) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
        (args.target, args.stage, args.status, stamp),
    )
    db.execute("UPDATE targets SET updated_at = ? WHERE target = ?", (stamp, args.target))
    record_event(db, args.target, "stage", f"{args.stage} marked {args.status}")
    print(f"{STAGE_LABELS[args.stage]} marked {args.status}")


def cmd_list(db: sqlite3.Connection, _args: argparse.Namespace) -> None:
    rows = db.execute("SELECT target, domain, dc, updated_at FROM targets ORDER BY target").fetchall()
    if not rows:
        print("No local workspaces. Add one with: autopwn.py add-target <IP-or-hostname>")
        return
    print(f"{'TARGET':<32} {'DOMAIN':<28} {'DC':<28} UPDATED (UTC)")
    for row in rows:
        print(f"{row['target']:<32} {(row['domain'] or '—'):<28} {(row['dc'] or '—'):<28} {row['updated_at']}")


def target_summary(db: sqlite3.Connection, target: str) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    row = require_target(db, target)
    stages = db.execute("SELECT name, status, updated_at FROM stages WHERE target = ? ORDER BY rowid", (target,)).fetchall()
    return row, stages


def cmd_status(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    row, stages = target_summary(db, args.target)
    host_count = db.execute("SELECT COUNT(*) FROM hosts WHERE target = ?", (args.target,)).fetchone()[0]
    service_count = db.execute("SELECT COUNT(*) FROM services WHERE target = ?", (args.target,)).fetchone()[0]
    finding_count = db.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (args.target,)).fetchone()[0]
    note_count = db.execute("SELECT COUNT(*) FROM notes WHERE target = ?", (args.target,)).fetchone()[0]
    import_count = db.execute("SELECT COUNT(*) FROM imports WHERE target = ?", (args.target,)).fetchone()[0]
    last_scan = db.execute("SELECT status,started_at,id FROM scan_runs WHERE target=? ORDER BY started_at DESC LIMIT 1", (args.target,)).fetchone()
    print(f"Target: {row['target']}\nDomain: {row['domain'] or 'not recorded'}\nDC: {row['dc'] or 'not recorded'}")
    print(f"Inventory: {host_count} host(s), {service_count} service record(s); {finding_count} finding(s), {note_count} note(s), {import_count} offline summary import(s)")
    print(f"Last Nmap inventory: {last_scan['status']} ({last_scan['id']})" if last_scan else "Last Nmap inventory: none")
    scope = db.execute("SELECT expires_at FROM scopes WHERE target=?", (args.target,)).fetchone()
    if scope:
        active = datetime.fromisoformat(scope["expires_at"]) > datetime.now(timezone.utc)
        print(f"Scan scope: {'active' if active else 'expired'} through {scope['expires_at']} UTC")
    else:
        print("Scan scope: not recorded")
    print("Stages:")
    for stage in stages:
        print(f"  {STAGE_LABELS.get(stage['name'], stage['name']):<24} {stage['status']:<12} {stage['updated_at']}")


def cmd_history(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    require_target(db, args.target)
    rows = db.execute(
        "SELECT at,kind,message FROM events WHERE target=? ORDER BY id DESC LIMIT ?",
        (args.target, args.limit),
    ).fetchall()
    if not rows:
        print("No history recorded.")
        return
    for row in reversed(rows):
        print(f"{row['at']}  {row['kind']:<18} {row['message']}")


def md_cell(value: str | None) -> str:
    return (value or "—").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def make_report(db: sqlite3.Connection, target: str) -> str:
    row, _ = target_summary(db, target)
    lines = [
        f"# Lab notes: {target}",
        "",
        "> Generated locally by autopwn. Active scanning, when explicitly requested, is limited to a single IP and a fixed TCP inventory profile.",
        "",
        f"- **Domain:** {row['domain'] or 'Not recorded'}",
        f"- **Domain controller:** {row['dc'] or 'Not recorded'}",
        f"- **Updated (UTC):** {row['updated_at']}",
        "",
        "## Recon inventory",
        "",
        "| Host | Hostname | State | Protocol | Port | Service | Product / version |",
        "|---|---|---|---|---:|---|---|",
    ]
    scope = db.execute("SELECT expires_at,reference FROM scopes WHERE target=?", (target,)).fetchone()
    lines += ["", "## Scan scope", ""]
    if scope:
        lines.append(f"- **Authorization record:** through {scope['expires_at']} UTC; reference: {md_cell(scope['reference'])}")
    else:
        lines.append("_No active scan scope recorded._")

    hosts = db.execute("SELECT * FROM hosts WHERE target = ? ORDER BY address", (target,)).fetchall()
    for host in hosts:
        services = db.execute(
            "SELECT * FROM services WHERE target = ? AND address = ? ORDER BY protocol, port",
            (target, host["address"]),
        ).fetchall()
        if not services:
            lines.append(f"| {md_cell(host['address'])} | {md_cell(host['hostname'])} | {md_cell(host['state'])} | — | — | — | — |")
        for service in services:
            product_version = " ".join(filter(None, (service["product"], service["version"], service["extra_info"])))
            lines.append(
                f"| {md_cell(host['address'])} | {md_cell(host['hostname'])} | {md_cell(host['state'])} | "
                f"{md_cell(service['protocol'])} | {service['port']} | {md_cell(service['name'])} | {md_cell(product_version)} |"
            )
    if not hosts:
        lines.append("| No host inventory | — | — | — | — | — | — |")

    scans = db.execute("SELECT id,status,started_at,finished_at FROM scan_runs WHERE target=? ORDER BY started_at", (target,)).fetchall()
    lines += ["", "### Inventory scan checkpoints", ""]
    if scans:
        for scan in scans:
            lines.append(f"- `{scan['id']}` — {scan['status']}; started {scan['started_at']}; finished {scan['finished_at'] or 'not finished'}")
    else:
        lines.append("_No Nmap scan runs recorded._")

    imports = db.execute("SELECT source_name,kind,sha256,summary_json,created_at FROM imports WHERE target=? ORDER BY id", (target,)).fetchall()
    lines += ["", "## Offline AD report summaries", ""]
    if imports:
        for item in imports:
            counts = json.loads(item["summary_json"])
            lines.append(f"- **{item['kind']} · {item['source_name']}** ({item['created_at']}, SHA-256 `{item['sha256'][:12]}…`): `{json.dumps(counts, sort_keys=True)}`")
        lines.append("")
        lines.append("_Only summary counts and file fingerprints are retained; object names, relationships, raw JSON, and attack paths are not imported._")
    else:
        lines.append("_No offline JSON summaries imported._")

    for stage in STAGES:
        label = STAGE_LABELS[stage]
        stage_row = db.execute("SELECT status FROM stages WHERE target = ? AND name = ?", (target, stage)).fetchone()
        lines += ["", f"## {label}", "", f"**Status:** {stage_row['status'] if stage_row else 'not_started'}", ""]
        findings = db.execute(
            "SELECT title, detail, severity, status, created_at FROM findings WHERE target = ? AND stage = ? ORDER BY id",
            (target, stage),
        ).fetchall()
        notes = db.execute(
            "SELECT title, body, created_at FROM notes WHERE target = ? AND stage = ? ORDER BY id",
            (target, stage),
        ).fetchall()
        if findings:
            lines.append("### Findings")
            for finding in findings:
                lines.extend([
                    f"- **[{finding['severity'].upper()} · {finding['status']}] {finding['title']}** — {finding['detail']}",
                    f"  - Recorded: {finding['created_at']}",
                ])
            lines.append("")
        if notes:
            lines.append("### Notes")
            for note in notes:
                lines.extend([f"#### {note['title']}", "", note["body"], "", f"_Recorded: {note['created_at']}_", ""])
        if not findings and not notes:
            lines.append("_No notes or findings recorded._")
    return "\n".join(lines).rstrip() + "\n"


def cmd_report(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    content = make_report(db, args.target)
    if args.out:
        destination = args.out.expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        print(f"Wrote local report: {destination}")
    else:
        sys.stdout.write(content)


def cmd_export_json(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    row = require_target(db, args.target)
    scope = db.execute("SELECT expires_at,reference,created_at FROM scopes WHERE target=?", (args.target,)).fetchone()
    data: dict[str, object] = {
        "target": dict(row),
        "scope": dict(scope) if scope else None,
        "stages": [dict(r) for r in db.execute("SELECT name,status,updated_at FROM stages WHERE target=? ORDER BY rowid", (args.target,))],
        "hosts": [],
        "notes": [dict(r) for r in db.execute("SELECT stage,title,body,created_at FROM notes WHERE target=? ORDER BY id", (args.target,))],
        "findings": [dict(r) for r in db.execute("SELECT stage,title,detail,severity,status,created_at FROM findings WHERE target=? ORDER BY id", (args.target,))],
        "offline_import_summaries": [],
    }
    hosts = []
    for host in db.execute("SELECT * FROM hosts WHERE target=? ORDER BY address", (args.target,)):
        item = dict(host)
        item["services"] = [dict(s) for s in db.execute(
            "SELECT protocol,port,state,name,product,version,extra_info FROM services WHERE target=? AND address=? ORDER BY protocol,port",
            (args.target, host["address"]),
        )]
        hosts.append(item)
    data["hosts"] = hosts
    data["offline_import_summaries"] = [
        {"source_name": r["source_name"], "kind": r["kind"], "sha256": r["sha256"], "summary": json.loads(r["summary_json"]), "created_at": r["created_at"]}
        for r in db.execute("SELECT * FROM imports WHERE target=? ORDER BY id", (args.target,))
    ]
    output = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        destination = args.out.expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output, encoding="utf-8")
        print(f"Wrote local JSON export: {destination}")
    else:
        sys.stdout.write(output)


def cmd_backup(db: sqlite3.Connection, args: argparse.Namespace) -> None:
    destination = args.out.expanduser()
    source_path = args.db.expanduser().resolve()
    if destination.resolve() == source_path:
        raise ValueError("Backup destination must differ from the active database")
    if destination.exists() and not args.overwrite:
        raise ValueError(f"Backup file already exists: {destination}; pass --overwrite to replace it")
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup_db = sqlite3.connect(destination)
    try:
        db.backup(backup_db)
    finally:
        backup_db.close()
    print(f"Created SQLite backup: {destination}")


def verify_db_file(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"Database file not found: {path}")
    with closing(sqlite3.connect(path)) as check:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise ValueError(f"SQLite integrity check failed: {result}")
        tables = {r[0] for r in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"targets", "stages", "hosts", "services", "notes", "findings", "events"}
        if not required.issubset(tables):
            raise ValueError("File is not a compatible autopwn SQLite backup")


def restore_database(source: Path, destination: Path) -> Path | None:
    source, destination = source.expanduser().resolve(), destination.expanduser().resolve()
    if source == destination:
        raise ValueError("Backup source and active database path must differ")
    verify_db_file(source)
    if not sys.stdin.isatty():
        raise PermissionError("Interactive confirmation is required to replace the local database")
    try:
        response = input(f"This replaces {destination}. Type exactly {RESTORE_PHRASE}: ")
    except EOFError as exc:
        raise PermissionError("No restore confirmation received") from exc
    if response != RESTORE_PHRASE:
        raise PermissionError("Restore phrase did not match; database was not changed")

    pre_restore: Path | None = None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        pre_restore = destination.with_name(destination.name + f".pre-restore-{suffix}")
        with closing(sqlite3.connect(destination)) as current, closing(sqlite3.connect(pre_restore)) as backup:
            current.backup(backup)
    with closing(sqlite3.connect(source)) as source_db, closing(sqlite3.connect(destination)) as destination_db:
        source_db.backup(destination_db)
    verify_db_file(destination)
    with connect_db(destination) as restored:
        for target_row in restored.execute("SELECT target FROM targets").fetchall():
            record_event(restored, target_row["target"], "restore", f"Restored database from {source.name}")
    return pre_restore


def cmd_verify(db: sqlite3.Connection, _args: argparse.Namespace) -> None:
    result = db.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise ValueError(f"SQLite integrity check failed: {result}")
    print("SQLite integrity check: ok")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autopwn.py",
        description="Scoped AD/CTF inventory and evidence organizer. The only active network action is a confirmed single-IP Nmap inventory.",
        epilog="No credential attacks, BloodHound/Certipy collection, relay, exploitation, remote execution, or secret dumping are implemented.",
    )
    parser.add_argument("--db", type=Path, default=default_db_path(), help="SQLite path (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add-target", help="create a local workspace for an IP, hostname, or domain")
    p.add_argument("target")
    p.set_defaults(func=cmd_add_target)

    p = sub.add_parser("set-domain", help="record a domain name manually")
    p.add_argument("target")
    p.add_argument("domain")
    p.set_defaults(func=cmd_set_domain)

    p = sub.add_parser("set-dc", help="record a domain controller hostname manually")
    p.add_argument("target")
    p.add_argument("hostname")
    p.set_defaults(func=cmd_set_dc)

    p = sub.add_parser("scope-add", help="record an expiring single-IP authorization scope for Nmap inventory")
    p.add_argument("target")
    p.add_argument("--expires", required=True, help="last authorized UTC date in YYYY-MM-DD format")
    p.add_argument("--reference", help="local CTF room or authorization reference (no secrets)")
    p.set_defaults(func=cmd_scope_add)

    p = sub.add_parser("scope-list", help="list recorded scan scopes and expiry status")
    p.set_defaults(func=cmd_scope_list)

    p = sub.add_parser("scope-revoke", help="revoke a recorded scan scope")
    p.add_argument("target")
    p.set_defaults(func=cmd_scope_revoke)

    p = sub.add_parser("scan-ad", help="run a consent-gated TCP inventory on one literal IP using a fixed Nmap profile")
    p.add_argument("target")
    p.add_argument("--timeout", type=int, default=900, help="overall timeout in seconds (30-1800; default 900)")
    p.set_defaults(func=cmd_scan_ad)

    p = sub.add_parser("import-nmap", help="import an existing Nmap XML file; does not run Nmap")
    p.add_argument("target")
    p.add_argument("xml", type=Path)
    p.set_defaults(func=cmd_import_nmap)

    p = sub.add_parser("resume", help="recover parseable local XML from an interrupted Nmap inventory; never restarts a scan")
    p.add_argument("target")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("scan-log", help="show saved command and output for a local inventory run")
    p.add_argument("target")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_scan_log)

    p = sub.add_parser("scan-diff", help="compare two saved Nmap inventories offline")
    p.add_argument("target")
    p.add_argument("older_run_id")
    p.add_argument("newer_run_id")
    p.set_defaults(func=cmd_scan_diff)

    p = sub.add_parser("import-report", help="import counts only from an existing BloodHound/Certipy-style JSON file")
    p.add_argument("target")
    p.add_argument("json_file", type=Path)
    p.add_argument("--kind", choices=("auto", "bloodhound", "certipy"), default="auto")
    p.set_defaults(func=cmd_import_report)

    p = sub.add_parser("note", help="save a writeup note")
    p.add_argument("target")
    p.add_argument("stage", choices=STAGES)
    p.add_argument("title")
    p.add_argument("body")
    p.set_defaults(func=cmd_add_note)

    p = sub.add_parser("finding", help="record a manually verified finding")
    p.add_argument("target")
    p.add_argument("stage", choices=STAGES)
    p.add_argument("title")
    p.add_argument("detail")
    p.add_argument("--severity", choices=SEVERITIES, default="info")
    p.add_argument("--status", choices=("open", "confirmed", "resolved"), default="open")
    p.set_defaults(func=cmd_add_finding)

    p = sub.add_parser("stage", help="update a writeup stage's local status")
    p.add_argument("target")
    p.add_argument("stage", choices=STAGES)
    p.add_argument("status", choices=STAGE_STATES)
    p.set_defaults(func=cmd_set_stage)

    p = sub.add_parser("status", help="show local inventory and stage status")
    p.add_argument("target")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("history", help="show local audit events")
    p.add_argument("target")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("list", help="list local target workspaces")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("report", help="render the recon → foothold → priv esc → flags → lessons writeup")
    p.add_argument("target")
    p.add_argument("--out", type=Path, help="write Markdown to this local path instead of stdout")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("export-json", help="export local inventory, notes, and summary counts as JSON")
    p.add_argument("target")
    p.add_argument("--out", type=Path, help="write JSON to this local path instead of stdout")
    p.set_defaults(func=cmd_export_json)

    p = sub.add_parser("backup", help="create a local SQLite backup")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("restore", help="restore a local SQLite backup (requires interactive confirmation)")
    p.add_argument("backup", type=Path)

    p = sub.add_parser("verify", help="check local SQLite integrity")
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "restore":
            prior = restore_database(args.backup, args.db)
            print("Database restored and verified.")
            if prior:
                print(f"Previous database preserved at: {prior}")
            return 0
        if args.command == "scan-ad" and not 30 <= args.timeout <= 1800:
            raise ValueError("--timeout must be between 30 and 1800 seconds")
        if args.command == "history" and not 1 <= args.limit <= 500:
            raise ValueError("--limit must be between 1 and 500")
        with connect_db(args.db) as db:
            args.func(db, args)
    except (OSError, sqlite3.Error, ValueError, PermissionError, ET.ParseError) as exc:
        print(f"autopwn: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
