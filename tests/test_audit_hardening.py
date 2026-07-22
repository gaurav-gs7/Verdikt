from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from verdikt.audit import AuditStore


def _record(store: AuditStore) -> None:
    store.record(
        correlation_id="corr-1",
        server="platform-ops",
        tool="platform.health",
        allowed=True,
        rule="allow",
        reason="allowed by policy",
        arguments={"service": "payments-api"},
        result={"status": "healthy"},
        duration_ms=1.25,
    )


class AuditHardeningTest(unittest.TestCase):
    def test_signature_required_fails_closed_without_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true", "VERDIKT_AUDIT_HMAC_SECRET": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires VERDIKT_AUDIT_HMAC_SECRET"):
                AuditStore(Path(directory) / "audit.db")

    def test_verify_on_startup_rejects_tampered_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(
                os.environ,
                {"VERDIKT_AUDIT_HMAC_SECRET": "test-key"},
                clear=False,
            ):
                store = AuditStore(path)
                _record(store)
                store.close()
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET rule = 'tampered' WHERE id = 1")
            connection.commit()
            connection.close()

            with patch.dict(
                os.environ,
                {
                    "VERDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "VERDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "audit integrity verification failed"):
                    AuditStore(path)

    def test_signed_chain_verifies_in_required_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "VERDIKT_AUDIT_HMAC_SECRET": "test-key",
                "VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            },
            clear=False,
        ):
            store = AuditStore(Path(directory) / "audit.db")
            try:
                _record(store)
                report = store.verify_chain()
                self.assertTrue(report["valid"])
                self.assertTrue(report["signed"])
                self.assertTrue(report["signature_required"])
            finally:
                store.close()

    def test_multiple_events_form_one_contiguous_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            store = AuditStore(Path(directory) / "audit.db")
            try:
                for index in range(4):
                    _record(store)
                events = list(reversed(store.recent()))
                report = store.verify_chain()
                self.assertEqual(report["checked_events"], 4)
                self.assertEqual(report["head_hash"], events[-1]["event_hash"])
                self.assertEqual(events[0]["previous_hash"], "")
                for previous, current in zip(events, events[1:]):
                    self.assertEqual(current["previous_hash"], previous["event_hash"])
            finally:
                store.close()

    def test_wrong_signing_key_is_detected_on_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "first-key"}, clear=False):
                store = AuditStore(path)
                _record(store)
                store.close()
            with patch.dict(
                os.environ,
                {
                    "VERDIKT_AUDIT_HMAC_SECRET": "wrong-key",
                    "VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "VERDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "signature_mismatch"):
                    AuditStore(path)

    def test_signature_and_link_tampering_are_reported_precisely(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            path = Path(directory) / "audit.db"
            store = AuditStore(path)
            _record(store)
            _record(store)
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET signature = 'bad' WHERE id = 1")
            connection.execute("UPDATE audit_events SET previous_hash = 'bad' WHERE id = 2")
            connection.commit()
            connection.close()
            report = store.verify_chain()
            errors = {(item["id"], item["error"]) for item in report["errors"]}
            self.assertIn((1, "signature_mismatch"), errors)
            self.assertIn((2, "previous_hash_mismatch"), errors)
            self.assertIn((2, "event_hash_mismatch"), errors)
            store.close()

    def test_strict_startup_rejects_legacy_unsigned_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                    correlation_id TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
                    allowed INTEGER NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL,
                    arguments_json TEXT NOT NULL, result_json TEXT, duration_ms REAL NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO audit_events (created_at, correlation_id, server, tool, allowed, rule, reason, arguments_json, result_json, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("2026-01-01T00:00:00+00:00", "legacy", "s", "t", 1, "allow", "ok", "{}", None, 1),
            )
            connection.commit()
            connection.close()
            with patch.dict(
                os.environ,
                {
                    "VERDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
                    "VERDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "legacy_unsigned_event"):
                    AuditStore(path)

    def test_concurrent_writers_preserve_chain_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
        ):
            store = AuditStore(Path(directory) / "audit.db")
            threads = [threading.Thread(target=_record, args=(store,)) for _ in range(24)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            report = store.verify_chain()
            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(report["checked_events"], 24)
            store.close()

    def test_malformed_stored_json_is_reported_and_fails_verified_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            with patch.dict(
                os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "test-key"}, clear=False
            ):
                store = AuditStore(path)
                _record(store)
                store.close()
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET arguments_json = '{bad-json' WHERE id = 1")
            connection.commit()
            connection.close()
            with patch.dict(
                os.environ,
                {
                    "VERDIKT_AUDIT_HMAC_SECRET": "test-key",
                    "VERDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "malformed_event_payload"):
                    AuditStore(path)


if __name__ == "__main__":
    unittest.main()
