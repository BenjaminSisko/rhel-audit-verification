#!/usr/bin/env python3
"""Offline regression tests. All records are fixtures, never source evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1]/"package/TA_au2_linux/bin/aulx_review.py"
spec = importlib.util.spec_from_file_location("review", path)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class FixtureClient:
    def __init__(self):
        self.jobs = []
        self.rows = [{"_time": "150", "_indextime": "210", "host": "fixture.invalid", "index": "fixture", "sourcetype": "linux:audit", "record_fingerprint": "fp", "_raw": "TEST ONLY <script>bad</script>"}]
        self.events = [{"event_key": "test-event", "event_fingerprint": "event-fp", "record_fingerprint": ["fp"], "event_time": "150", "ingest_time": "210", "event_host": "fixture.invalid", "application": "fixture-app", "actor": "=NOT_A_FORMULA", "case_id": "TEST-S", "event_action": "Sign-in", "outcome": "success", "field_check_complete": "0", "verification_status": "Not yet verified"}]
        self.inventory = [{"event_host":"fixture.invalid","index":"fixture","sourcetype":"linux:audit","owner":"fixture owner","max_silence_seconds":"60","enabled":"1"}, {"event_host":"missing.invalid","index":"fixture","sourcetype":"linux:audit","owner":"fixture owner","max_silence_seconds":"60","enabled":"1"}]

    def configuration(self):
        return {"version": review.VERSION, "macros": {"aulx_source": "FIXTURE ONLY"}}

    def search(self, label, query, start, end, limit, timeout):
        self.jobs.append({"label": label, "search":query})
        if label.startswith("expected") or label == "inventory_recheck":
            return self.inventory
        if label in ("case_catalog", "catalog_recheck"):
            return [{"record_id":"TEST-S", "event_action":"Sign-in", "required_outcome":"success"}]
        if label == "source_records":
            return self.rows
        if label == "normalized_events":
            return self.events
        return []


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.client = FixtureClient()

    def tearDown(self):
        self.temp.cleanup()

    def export(self):
        return review.export(self.client, 100, 200, 220, self.root/"bundle", 100, 10, "TEST FIXTURE — NOT EVIDENCE")

    def test_export_preserves_sources_and_unsigned_review(self):
        meta = self.export()
        self.assertEqual(meta["raw_records"], 1)
        self.assertEqual(meta["configured_expected_feeds"], 2)
        self.assertFalse((self.root/"bundle/review-completion.json").exists())
        self.assertNotIn("<script>", (self.root/"bundle/report.html").read_text())
        self.assertIn("'=NOT_A_FORMULA", (self.root/"bundle/event-details.csv").read_text())
        self.assertIn("=NOT_A_FORMULA", (self.root/"bundle/normalized-events.ndjson").read_text())
        self.assertEqual((self.root/"bundle").stat().st_mode & 0o777, 0o700)

    def test_missing_feed_is_not_zero_event_pass(self):
        rows = review.coverage(self.client.rows, self.client.inventory, 200)
        self.assertEqual(rows[1]["status"], "No records in selected event-time window")

    def test_stale_feed(self):
        rows = review.coverage(self.client.rows, self.client.inventory, 300)
        self.assertTrue(rows[0]["status"].startswith("Stale"))

    def test_splunk_iso_time_is_supported(self):
        self.client.rows[0]["_time"] = "1970-01-01T00:02:30.000+00:00"
        self.assertEqual(review.coverage(self.client.rows, self.client.inventory, 200)[0]["last_event"], 150)

    def test_indexed_host_survives_extraction_contract(self):
        extract = (path.parents[3]/"searches/aulx_extract.spl").read_text()
        projection = extract.rsplit("| fields ", 1)[1].split()
        self.assertIn("host", projection)
        self.assertIn("host", review.RAW_FIELDS.split())

    def test_missing_indexed_host_fails_export(self):
        del self.client.rows[0]["host"]
        with self.assertRaisesRegex(ValueError, "missing indexed host"):
            self.export()
        self.assertTrue((self.root/"bundle/FAILED.json").exists())

    def test_indexed_host_not_replaced_by_normalized_host(self):
        self.client.rows[0]["event_host"] = "different-normalized-identity.invalid"
        rows = review.coverage(self.client.rows, self.client.inventory, 200)
        self.assertEqual(rows[0]["event_host"], "fixture.invalid")
        self.assertTrue(rows[0]["expected"])
        self.assertEqual(rows[0]["events"], 1)

    def test_nan_threshold_rejected(self):
        self.client.inventory[0]["max_silence_seconds"] = "NaN"
        with self.assertRaises(ValueError):
            review.validate_inventory(self.client.inventory)

    def test_future_cutoff_rejected(self):
        with self.assertRaises(ValueError):
            review.export(self.client, 100, 200, time.time()+100, self.root/"bundle", 100, 10, "TEST")

    def test_unexpected_feed(self):
        rows = review.coverage(self.client.rows, [], 200)
        self.assertFalse(rows[0]["expected"])

    def test_empty_inventory_scope_unknown(self):
        self.client.inventory = []
        self.export()
        self.assertIn("SCOPE UNKNOWN", (self.root/"bundle/report.html").read_text())

    def test_duplicate_inventory_rejected(self):
        with self.assertRaises(ValueError):
            review.validate_inventory(self.client.inventory*2)

    def test_invalid_inventory_rejected(self):
        self.client.inventory[0]["max_silence_seconds"] = "0"
        with self.assertRaises(ValueError):
            review.validate_inventory(self.client.inventory)

    def test_wildcard_inventory_rejected(self):
        self.client.inventory[0]["event_host"] = "*"
        with self.assertRaises(ValueError):
            review.validate_inventory(self.client.inventory)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            review.epoch("2026-09-21T12:00:00")

    def test_invalid_period_rejected(self):
        with self.assertRaises(ValueError):
            review.export(self.client, 200, 100, 220, self.root/"bundle", 100, 10, "TEST")

    def test_source_reconciliation_fails_closed(self):
        self.client.events[0]["record_fingerprint"] = ["not-preserved"]
        with self.assertRaises(ValueError):
            self.export()
        self.assertTrue((self.root/"bundle/FAILED.json").exists())
        self.assertFalse((self.root/"bundle/manifest.json").exists())

    def test_output_not_overwritten(self):
        self.export()
        with self.assertRaises(FileExistsError):
            self.export()

    def test_warning_is_not_success(self):
        with self.assertRaises(ValueError):
            review.check_messages([{"type":"WARN","text":"truncated"}])

    def test_remote_tls_exception_rejected(self):
        with self.assertRaises(ValueError):
            review.Client("https://fixture.invalid:8089", loopback_insecure=True)

    def test_embedded_credentials_rejected(self):
        with self.assertRaises(ValueError):
            review.Client("https://name:secret@127.0.0.1:8089")

    def test_http_rejected(self):
        with self.assertRaises(ValueError):
            review.Client("http://127.0.0.1:8089")

    def test_review_template_cannot_be_signed(self):
        self.export()
        with self.assertRaises(ValueError):
            review.record_review(self.root/"bundle", self.root/"bundle/review-template.json")

    def test_review_records_claim_without_mutating_manifest(self):
        self.export()
        before = (self.root/"bundle/manifest.json").read_bytes()
        claim = {"reviewer":"TEST REVIEWER", "completed_at":review.utc(), "disposition":"reviewed-with-findings", "scope_reviewed":True, "coverage_gaps_reviewed":True, "content_gaps_reviewed":True, "activity_reviewed":True, "summary":"TEST ONLY", "findings":[{"finding":"Missing fixture host", "owner":"TEST", "ticket":"TEST"}]}
        (self.root/"claim.json").write_text(json.dumps(claim))
        result = review.record_review(self.root/"bundle", self.root/"claim.json")
        self.assertEqual(before, (self.root/"bundle/manifest.json").read_bytes())
        self.assertEqual(result["manifest_sha256"], review.sha(before))
        with self.assertRaises(FileExistsError):
            review.record_review(self.root/"bundle", self.root/"claim.json")

    def test_tampered_evidence_rejected(self):
        self.export()
        (self.root/"bundle/source-records.ndjson").write_text("tampered")
        with self.assertRaises(ValueError):
            review.record_review(self.root/"bundle", self.root/"bundle/review-template.json")

    def test_pagination_loss_rejected(self):
        client = object.__new__(review.Client)
        client.namespace = "/fixture"
        client.jobs = []
        client.call = lambda path, params=None: {"sid":"fixture"} if params else ({"entry":[{"content":{"dispatchState":"DONE", "resultCount":"2"}}]} if "/results?" not in path else {"results":[]})
        with self.assertRaises(ValueError):
            client.search("fixture", "| makeresults", 100, 200, 10, 1)

    def test_row_cap_rejected(self):
        client = object.__new__(review.Client)
        client.namespace = "/fixture"
        client.jobs = []
        client.call = lambda path, params=None: {"sid":"fixture"} if params else {"entry":[{"content":{"dispatchState":"DONE", "resultCount":"11"}}]}
        with self.assertRaises(ValueError):
            client.search("fixture", "| makeresults", 100, 200, 10, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
