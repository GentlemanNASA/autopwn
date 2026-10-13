# `autopwn` — scoped AD/CTF inventory and evidence organizer

This is a deliberately limited, local-first tool. It now has one active network operation: an explicit-confirmation Nmap inventory of a **single literal IP**, over a fixed list of common Active Directory/service TCP ports. It does not run an attack chain.

## Safety boundary

The only command that contacts a target is `scan-ad`. It:

- requires an unexpired local scope entry for the exact IP and an interactive exact-phrase confirmation before starting;
- accepts one canonical IPv4/IPv6 address only (not a hostname, CIDR, range, wildcard, or list);
- uses a fixed TCP port list and Nmap connect/version detection, with a conservative timing profile;
- does not use UDP, NSE scripts, vulnerability scripts, evasion flags, or user-supplied Nmap arguments;
- saves a local XML checkpoint, records status/output, and does not launch follow-on actions.

There is **no** Kerberos/LDAP/SMB account enumeration, roasting, password spraying, cracking, Responder/relay, credential reuse, remote execution, secrets dumping, BloodHound/Certipy collection, attack-path analysis, or automatic privilege escalation. The tool has no credential/hash/session fields. Note redaction is heuristic, not a guarantee; do not paste secrets into notes.

Existing BloodHound/Certipy-style JSON can be imported with `import-report`. The importer stores only aggregate counts, source filename, and a SHA-256 fingerprint—not raw JSON, object names, relationships, or attack paths. It never runs BloodHound or Certipy.

## Requirements

- Python 3.10 or later
- Standard library only
- Nmap is required only for `scan-ad`; on Kali install it with `sudo apt install nmap`

## Offline installation and quick start

Install without pip, apt, or network access:

```bash
./install.sh                  # installs ~/.local/bin/autopwn
./install.sh /some/local/bin  # optional custom destination
```

Then create a workspace and record metadata:

```bash
autopwn add-target 10.10.10.10
autopwn set-domain 10.10.10.10 example.htb
autopwn set-dc 10.10.10.10 dc01.example.htb

# Add an exact-IP scope record with a short expiry; dates are UTC.
EXPIRY=$(date -u -d '+7 days' +%F)
autopwn scope-add 10.10.10.10 --expires "$EXPIRY" --reference "HTB lab"

# Requires an active scope record and the exact confirmation phrase.
autopwn scan-ad 10.10.10.10

# Optional offline imports; neither command runs a scanner or collector.
autopwn import-nmap 10.10.10.10 ./existing-scan.xml
autopwn import-report 10.10.10.10 ./bloodhound-users.json --kind bloodhound
autopwn import-report 10.10.10.10 ./certipy-find.json --kind certipy

autopwn status 10.10.10.10
autopwn history 10.10.10.10
autopwn report 10.10.10.10 --out ./writeup.md
```

For an active scan, type exactly:

```text
I am authorized to test this target
```

Anything else—or non-interactive input—is a hard stop. A scope record is also required: `scope-add` accepts one literal IP and a UTC expiry date, and `scan-ad` refuses missing or expired entries. Revoke a record with `scope-revoke TARGET`. Hostnames are accepted as local workspace identifiers, but scanning deliberately requires a single literal IP so DNS cannot expand the scope.

## Recovery and local data

Each Nmap run creates a local XML checkpoint and a SQLite run record before starting. If the process is interrupted, `resume TARGET` attempts to ingest a complete, parseable checkpoint; **it never restarts a scan**. A new scan always requires the confirmation prompt again. Use `scan-log TARGET RUN_ID` to inspect the saved command and output, `history TARGET` for the event timeline, and `scan-diff TARGET OLD_RUN_ID NEW_RUN_ID` to compare two saved inventories offline.

The SQLite database defaults to:

```text
~/.local/share/autopwn/state.sqlite3
```

Use `AUTOPWN_HOME` to change the data directory, or pass `--db PATH` before the subcommand:

```bash
AUTOPWN_HOME="$PWD/lab-state" autopwn add-target 10.10.10.10
autopwn --db ./lab.sqlite3 list
```

Back up and verify the database locally:

```bash
autopwn --db ./lab.sqlite3 backup --out ./lab-backup.sqlite3
autopwn --db ./lab.sqlite3 verify
```

Restore requires the exact interactive phrase `RESTORE AUTOPWN DATABASE` and preserves an existing database as a pre-restore backup:

```bash
autopwn --db ./lab.sqlite3 restore ./lab-backup.sqlite3
```

## Commands

```text
add-target TARGET
set-domain TARGET DOMAIN
set-dc TARGET HOSTNAME
scope-add TARGET --expires YYYY-MM-DD [--reference LABEL]
scope-list
scope-revoke TARGET
scan-ad TARGET [--timeout SECONDS]
import-nmap TARGET FILE.xml
resume TARGET
scan-log TARGET RUN_ID
scan-diff TARGET OLD_RUN_ID NEW_RUN_ID
import-report TARGET FILE.json [--kind auto|bloodhound|certipy]
note TARGET STAGE TITLE BODY
finding TARGET STAGE TITLE DETAIL [--severity ...] [--status ...]
stage TARGET STAGE STATUS
status TARGET
history TARGET [--limit N]
list
report TARGET [--out FILE.md]
export-json TARGET [--out FILE.json]
backup --out FILE.sqlite3 [--overwrite]
restore FILE.sqlite3
verify
```

Writeup stages are `recon`, `foothold`, `priv_esc`, `flags`, and `lessons_learned`. Their statuses and notes are local bookkeeping; they do not trigger commands.
