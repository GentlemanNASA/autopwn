import contextlib
import io
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

import autopwn


class AutopwnSafeFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "state.sqlite3"
        self.db = autopwn.connect_db(self.db_path)
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_add_target(self.db, SimpleNamespace(target="10.10.10.10"))
        self.db.execute(
            "INSERT INTO scopes(target,expires_at,reference,created_at) VALUES(?,?,?,?)",
            ("10.10.10.10", "2099-12-31T23:59:59+00:00", "test-only lab scope", autopwn.now_utc()),
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.tempdir.cleanup()

    def test_scan_scope_accepts_one_literal_ip_only(self):
        self.assertEqual(autopwn.validate_scan_ip("10.10.10.10"), "10.10.10.10")
        for target in (
            "10.10.10.0/24",
            "10.10.10.10,10.10.10.11",
            "example.htb",
            "-Pn",
            "224.0.0.1",
            "0.0.0.0",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                autopwn.validate_scan_ip(target)

    def test_scan_requires_active_scope_before_prompt_or_nmap(self):
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_add_target(self.db, SimpleNamespace(target="10.10.10.11"))

        class TTY(io.StringIO):
            def isatty(self):
                return True

        with (
            patch.object(autopwn.sys, "stdin", TTY()),
            patch("builtins.input", return_value=autopwn.AUTH_PHRASE) as prompt,
            patch.object(autopwn.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "No scope authorization"):
                autopwn.cmd_scan_ad(
                    self.db,
                    SimpleNamespace(target="10.10.10.11", timeout=30, db=self.db_path),
                )
        prompt.assert_not_called()
        popen.assert_not_called()

    def test_scope_add_records_expiry_and_reference(self):
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_scope_add(
                self.db,
                SimpleNamespace(target="10.10.10.10", expires="2099-12-30", reference="THM room 42"),
            )
        row = autopwn.require_active_scope(self.db, "10.10.10.10")
        self.assertEqual(row["reference"], "THM room 42")
        self.assertTrue(row["expires_at"].startswith("2099-12-30"))

    def test_scope_add_rejects_expired_date(self):
        with self.assertRaisesRegex(ValueError, "future UTC date"):
            autopwn.cmd_scope_add(
                self.db,
                SimpleNamespace(target="10.10.10.10", expires="2000-01-01", reference="lab"),
            )

    def test_wrong_authorization_phrase_stops_before_nmap(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True

        with (
            patch.object(autopwn.sys, "stdin", TTY()),
            patch("builtins.input", return_value="yes"),
            patch.object(autopwn.subprocess, "Popen") as popen,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(PermissionError):
                autopwn.cmd_scan_ad(
                    self.db,
                    SimpleNamespace(target="10.10.10.10", timeout=30, db=self.db_path),
                )
        popen.assert_not_called()

    def test_guarded_scan_uses_fixed_profile_without_network_in_tests(self):
        xml_text = (
            '<nmaprun><host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"><state state="open"/>'
            '<service name="microsoft-ds" product="Windows SMB" version="10"/></port></ports></host></nmaprun>'
        )
        class FakePopen:
            command = None
            def __init__(self, command, **kwargs):
                FakePopen.command = command
                xml_path = Path(command[command.index("-oX") + 1])
                xml_path.write_text(xml_text, encoding="utf-8")
                self.returncode = 0
            def communicate(self, timeout=None):
                return ("Nmap inventory simulation", "")

        class TTY(io.StringIO):
            def isatty(self):
                return True

        with (
            patch.object(autopwn.sys, "stdin", TTY()),
            patch("builtins.input", return_value=autopwn.AUTH_PHRASE),
            patch.object(autopwn.shutil, "which", return_value="/usr/bin/nmap"),
            patch.object(autopwn.subprocess, "Popen", FakePopen),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            autopwn.cmd_scan_ad(
                self.db,
                SimpleNamespace(target="10.10.10.10", timeout=30, db=self.db_path),
            )
        command = FakePopen.command
        self.assertIn("-sT", command)
        self.assertIn("-sV", command)
        self.assertIn(autopwn.AD_TCP_PORTS, command)
        self.assertNotIn("-sU", command)
        self.assertFalse(any("--script" in item for item in command))
        self.assertEqual(self.db.execute("SELECT status FROM scan_runs").fetchone()[0], "complete")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM services").fetchone()[0], 1)

    def test_inventory_diff_compares_saved_xml_offline(self):
        older_xml = self.root / "older.xml"
        newer_xml = self.root / "newer.xml"
        older_xml.write_text(
            '<nmaprun><host><address addr="10.10.10.10" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="445"><state state="open"/><service name="smb" version="10"/></port>'
            '</ports></host></nmaprun>', encoding="utf-8",
        )
        newer_xml.write_text(
            '<nmaprun><host><address addr="10.10.10.10" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="445"><state state="open"/><service name="smb" version="11"/></port>'
            '<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>'
            '</ports></host></nmaprun>', encoding="utf-8",
        )
        for run_id, path in (("oldrun", older_xml), ("newrun", newer_xml)):
            self.db.execute(
                "INSERT INTO scan_runs(id,target,command_json,xml_path,status,started_at) VALUES(?,?,?,?,?,?)",
                (run_id, "10.10.10.10", "[]", str(path), "complete", autopwn.now_utc()),
            )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            autopwn.cmd_scan_diff(
                self.db,
                SimpleNamespace(target="10.10.10.10", older_run_id="oldrun", newer_run_id="newrun"),
            )
        self.assertIn("Added: 10.10.10.10 tcp/389", output.getvalue())
        self.assertIn("Changed: 10.10.10.10 tcp/445", output.getvalue())

    def test_nmap_xml_import_is_local_and_repeatable(self):
        xml = self.root / "scan.xml"
        xml.write_text(
            """<nmaprun><host><status state="up"/>
            <address addr="10.10.10.10" addrtype="ipv4"/>
            <hostnames><hostname name="dc01.example.htb" type="PTR"/></hostnames>
            <ports><port protocol="tcp" portid="445"><state state="open"/>
            <service name="microsoft-ds" product="Windows SMB" version="10"/>
            </port></ports></host></nmaprun>""",
            encoding="utf-8",
        )
        first = autopwn.import_nmap_xml(self.db, "10.10.10.10", xml)
        second = autopwn.import_nmap_xml(self.db, "10.10.10.10", xml)
        self.assertEqual(first, (1, 1))
        self.assertEqual(second, (1, 1))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM services").fetchone()[0], 1)

    def test_offline_summary_retains_counts_not_objects(self):
        payload = {
            "meta": {"type": "users"},
            "data": [{"name": "secret-user"}, {"name": "another-user"}],
        }
        kind, summary = autopwn.summarize_offline_json(payload, "auto")
        self.assertEqual(kind, "bloodhound")
        self.assertEqual(summary, {"users_records": 2})
        self.assertNotIn("secret-user", json.dumps(summary))

    def test_certipy_summary_is_aggregate_only(self):
        payload = {
            "Certificate Templates": [{"name": "TemplateA"}, {"name": "TemplateB"}],
            "Certificate Authorities": [{"name": "CA01"}],
            "Vulnerabilities": ["ESC1", "ESC8"],
        }
        kind, summary = autopwn.summarize_offline_json(payload, "certipy")
        self.assertEqual(kind, "certipy")
        self.assertEqual(summary["certificate_template_records"], 2)
        self.assertEqual(summary["certificate_authority_records"], 1)
        self.assertEqual(summary["items_marked_vulnerable"], 2)
        self.assertNotIn("TemplateA", json.dumps(summary))
        self.assertNotIn("ESC1", json.dumps(summary))

    def test_redaction_and_report(self):
        self.assertIn("[REDACTED]", autopwn.redact("password=hunter2"))
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_add_note(
                self.db,
                SimpleNamespace(target="10.10.10.10", stage="recon", title="Reminder", body="token=abc123"),
            )
        report = autopwn.make_report(self.db, "10.10.10.10")
        self.assertIn("token=[REDACTED]", report)
        self.assertNotIn("abc123", report)

    def test_sqlite_backup_integrity(self):
        backup = self.root / "backup.sqlite3"
        args = SimpleNamespace(db=self.db_path, out=backup, overwrite=False)
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_backup(self.db, args)
        autopwn.verify_db_file(backup)

    def test_restore_requires_confirmation_and_preserves_old_database(self):
        backup = self.root / "backup.sqlite3"
        with contextlib.redirect_stdout(io.StringIO()):
            autopwn.cmd_backup(self.db, SimpleNamespace(db=self.db_path, out=backup, overwrite=False))
        self.db.execute("UPDATE targets SET domain='changed.example' WHERE target='10.10.10.10'")
        self.db.commit()
        self.db.close()

        class TTY(io.StringIO):
            def isatty(self):
                return True

        with (
            patch.object(autopwn.sys, "stdin", TTY()),
            patch("builtins.input", return_value=autopwn.RESTORE_PHRASE),
        ):
            prior = autopwn.restore_database(backup, self.db_path)
        self.assertIsNotNone(prior)
        self.assertTrue(prior.is_file())
        self.db = autopwn.connect_db(self.db_path)
        self.assertIsNone(self.db.execute("SELECT domain FROM targets WHERE target='10.10.10.10'").fetchone()[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
