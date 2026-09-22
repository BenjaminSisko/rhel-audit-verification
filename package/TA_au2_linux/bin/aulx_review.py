#!/usr/bin/env python3
"""Manual, fixed-window RHEL evidence export. Python standard library only.

No scheduled input, automatic attestation, indexing, account or policy changes.
Run with a search-capable account and approved index/configuration read access.
"""
import argparse
import base64
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import html
import io
import json
import math
import os
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from aulx_provenance import verify_session_provenance

APP = "TA_au2_linux"
VERSION = "1.4.7"
RAW_FIELDS = "_time _indextime event_time ingest_time host index source sourcetype _raw _bkt _cd splunk_server record_fingerprint event_key"
EVENT_FIELDS = "event_key event_fingerprint record_fingerprint event_time ingest_time event_host application case_id event_action outcome actor login_user login_uid process_user process_uid effective_user effective_uid target_account identity_basis initiator completer object source_ip terminal privilege process_id correlation_id reason raw_records native_kind index source sourcetype missing_fields au3_complete au3_1_complete app_context_complete field_check_complete verification_status receipt_id source_evidence_ref correlation_state clock_status protection_status audit_session remote_access session_remote_access session_source_ip session_context_status session_context_basis session_context_fingerprints session_context_record_fingerprints"


def utc(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def epoch(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Use an explicit time zone, for example 2026-09-14T00:00:00Z")
    return int(parsed.timestamp())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def numeric_time(value):
    try:
        result = float(value)
    except ValueError:
        result = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    if not math.isfinite(result):
        raise ValueError("Non-finite timestamp")
    return result


def as_list(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def true(value):
    return str(value).lower() in ("1", "true", "yes")


def check_messages(messages):
    for message in messages or []:
        if message.get("type", "").upper() in ("WARN", "ERROR", "FATAL"):
            raise ValueError("Search warning/error: export cannot establish completeness. Inspect the recorded job in Splunk.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("API redirect refused; credentials remain on the configured endpoint")


class Client:
    def __init__(self, url, owner="nobody", ca_file=None, loopback_insecure=False):
        target = urllib.parse.urlsplit(url)
        if target.scheme != "https" or target.username or target.password or target.query or target.fragment or target.path not in ("", "/"):
            raise ValueError("Use an HTTPS management origin without credentials, path, query or fragment")
        if loopback_insecure and target.hostname not in ("127.0.0.1", "::1"):
            raise ValueError("TLS verification exception is restricted to literal loopback")
        self.base = url.rstrip("/")
        self.context = ssl._create_unverified_context() if loopback_insecure else ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
        token = os.environ.get("SPLUNK_TOKEN")
        password = os.environ.get("SPLUNK_PASSWORD")
        username = os.environ.get("SPLUNK_USERNAME")
        if token:
            self.auth = "Bearer " + token
        elif username and password:
            self.auth = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
        else:
            raise ValueError("Supply SPLUNK_TOKEN or SPLUNK_USERNAME and SPLUNK_PASSWORD through an approved secret mechanism; never command-line arguments")
        self.namespace = "/servicesNS/" + urllib.parse.quote(owner, safe="") + "/" + APP
        self.jobs = []

    def call(self, path, params=None):
        data = urllib.parse.urlencode(params).encode() if params is not None else None
        request = urllib.request.Request(self.base + path, data=data, headers={"Authorization": self.auth})
        try:
            with self.opener.open(request, timeout=60) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            raise ValueError("Splunk API HTTP " + str(exc.code) + "; response body withheld") from None
        check_messages(result.get("messages"))
        return result

    def configuration(self):
        macros = self.call(self.namespace + "/configs/conf-macros?output_mode=json&count=0")
        transforms = self.call(self.namespace + "/configs/conf-transforms?output_mode=json&count=0")
        version = self.call("/services/apps/local/" + APP + "?output_mode=json")["entry"][0]["content"]["version"]
        return {"version": version, "macros": {r["name"]: r["content"]["definition"] for r in macros["entry"] if r["name"].startswith("aulx_")}, "lookups": {r["name"]: {k:v for k,v in r["content"].items() if k in ("filename", "case_sensitive_match", "match_type")} for r in transforms["entry"] if r["name"].startswith("aulx_")}}

    def search(self, label, query, start, end, limit, timeout):
        endpoint = self.namespace + "/search/jobs"
        job = self.call(endpoint, {"search": query, "earliest_time": str(start), "latest_time": str(end), "exec_mode": "normal", "max_count": str(limit + 1), "output_mode": "json"})
        sid = job["sid"]
        record = {"label": label, "sid": sid, "search": query, "earliest_epoch": start, "latest_epoch_exclusive": end}
        self.jobs.append(record)
        path = endpoint + "/" + urllib.parse.quote(sid, safe="")
        deadline = time.monotonic() + timeout
        while True:
            state = self.call(path + "?output_mode=json")["entry"][0]["content"]
            check_messages(state.get("messages"))
            if true(state.get("isFailed")) or true(state.get("isFinalized")) or state.get("dispatchState") in ("FAILED", "BAD_INPUT_CANCEL", "USER_CANCEL", "INTERNAL_CANCEL"):
                raise ValueError("Search failed or was finalized early: " + label)
            if state.get("dispatchState") == "DONE":
                break
            if time.monotonic() >= deadline:
                self.call(path + "/control", {"action": "cancel", "output_mode": "json"})
                raise ValueError("Search timed out: " + label)
            time.sleep(1)
        total = int(state["resultCount"])
        if total > limit:
            raise ValueError("Export row limit exceeded for " + label + "; narrow the review interval or approve a larger limit")
        rows = []
        while len(rows) < total:
            result = self.call(path + "/results?" + urllib.parse.urlencode({"output_mode": "json", "count": min(1000, total-len(rows)), "offset": len(rows)}))
            if true(result.get("preview")):
                raise ValueError("Preview results are not evidence exports")
            page = result.get("results", [])
            if not page or len(rows) + len(page) > total:
                raise ValueError("Incomplete or inconsistent result pagination: " + label)
            rows.extend(page)
        record.update({"dispatch_state": state["dispatchState"], "result_count": total, "expanded_search": state.get("eventSearch"), "messages": state.get("messages", [])})
        return rows


def validate_inventory(rows):
    seen = set()
    for row in rows:
        if row.get("enabled") not in ("0", "1"):
            raise ValueError("Inventory enabled must be 0 or 1")
        key = tuple(row.get(k, "") for k in ("event_host", "index", "sourcetype"))
        if any(not value or any(ch in value for ch in "*?\r\n") for value in key):
            raise ValueError("Expected feeds require exact host/index/sourcetype values, without wildcards")
        if key in seen:
            raise ValueError("Duplicate expected feed: " + repr(key))
        seen.add(key)
        threshold = float(row.get("max_silence_seconds", 0))
        if not math.isfinite(threshold) or threshold <= 0 or not row.get("owner", "").strip():
            raise ValueError("Expected feeds require an owner and a positive freshness threshold")


def coverage(raw, inventory, end):
    validate_inventory(inventory)
    expected = {tuple(r[k] for k in ("event_host", "index", "sourcetype")): r for r in inventory if r["enabled"] == "1"}
    observed = {}
    for row in raw:
        key = tuple(row.get(k, "") for k in ("host", "index", "sourcetype"))
        if any(not isinstance(value, str) or not value.strip() for value in key):
            raise ValueError("Source record is missing indexed host/index/sourcetype metadata")
        item = observed.setdefault(key, {"events": 0, "last_event": 0, "last_ingest": 0})
        item["events"] += 1
        item["last_event"] = max(item["last_event"], numeric_time(row.get("event_time", row["_time"])))
        item["last_ingest"] = max(item["last_ingest"], numeric_time(row.get("ingest_time", row["_indextime"])))
    output = []
    for key in sorted(set(expected) | set(observed)):
        item = observed.get(key, {"events": 0, "last_event": None, "last_ingest": None})
        contract = expected.get(key, {})
        status = "Observed — not in expected inventory"
        if contract:
            status = "No records in selected event-time window" if not item["events"] else ("Stale at end of selected window" if end-item["last_event"] > float(contract["max_silence_seconds"]) else "Records present — content/continuity still require review")
        output.append(dict(zip(("event_host", "index", "sourcetype"), key), **item, expected=bool(contract), owner=contract.get("owner", ""), max_silence_seconds=contract.get("max_silence_seconds", ""), status=status))
    return output


def case_summary(events, catalog):
    output = []
    for case in catalog + [{"record_id": "UNMAPPED", "event_action": "Unmapped", "required_outcome": "unknown"}]:
        matches = [e for e in events if e.get("case_id") == case["record_id"]]
        output.append({"case_id": case["record_id"], "action": case["event_action"], "outcome": case["required_outcome"], "candidate_events": len({e["event_key"] for e in matches}), "strict_content_complete": sum(true(e.get("field_check_complete")) for e in matches), "reviewed_receipts": sum(e.get("verification_status") == "Verified test receipt" for e in matches), "hosts": sorted({h for e in matches for h in as_list(e.get("event_host"))}), "applications": sorted({a for e in matches for a in as_list(e.get("application"))})})
    return output


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def write_csv(path, rows):
    columns = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            safe = {}
            for key, value in row.items():
                value = json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value if value is not None else "")
                # Human spreadsheet views only. JSON evidence retains exact values.
                safe[key] = "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
            writer.writerow(safe)


def table(rows, keys):
    return "<table><thead><tr>" + "".join("<th>"+html.escape(k)+"</th>" for k in keys) + "</tr></thead><tbody>" + "".join("<tr>"+"".join("<td>"+html.escape(str(r.get(k, "")))+"</td>" for k in keys)+"</tr>" for r in rows)+"</tbody></table>"


def export(client, start, end, cutoff, destination, limit, timeout, label):
    if not start < end <= cutoff <= time.time() or end-start > 8*86400:
        raise ValueError("Require start < end <= ingest cutoff; export at most eight days per package")
    os.umask(0o077)
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        config = client.configuration()
        if config["version"] != VERSION:
            raise ValueError("Exporter and installed app versions differ")
        inventory = client.search("expected_inventory", "| inputlookup aulx_expected_sources", start, end, limit, timeout)
        validate_inventory(inventory)
        catalog = client.search("case_catalog", "| inputlookup au2_linux_event_catalog.csv | inputlookup append=true aulx_usb_catalog.csv", start, end, limit, timeout)
        lookup_queries = {"actions": "| inputlookup aulx_action_catalog.csv", "syscalls": "| inputlookup aulx_syscalls.csv", "reviewed_receipts": "| inputlookup aulx_verification_receipts"}
        lookup_snapshot = {k: client.search(k, q, start, end, limit, timeout) for k,q in lookup_queries.items()}
        prefix = '| `aulx_source` | where _indextime<=' + str(cutoff) + ' AND _time>='+str(start)+' AND _time<'+str(end)+' | `aulx_extract`'
        raw = client.search("source_records", prefix + ' | table ' + RAW_FIELDS, start, end, limit, timeout)
        events = client.search("normalized_events", prefix + ' | `aulx_correlate` | `aulx_session_context` | `aulx_classify` | `aulx_content` | table ' + EVENT_FIELDS, start, end, limit, timeout)
        if config != client.configuration():
            raise ValueError("App/macro configuration changed during export")
        if inventory != client.search("inventory_recheck", "| inputlookup aulx_expected_sources", start, end, limit, timeout):
            raise ValueError("Expected inventory changed during export")
        if catalog != client.search("catalog_recheck", "| inputlookup au2_linux_event_catalog.csv | inputlookup append=true aulx_usb_catalog.csv", start, end, limit, timeout):
            raise ValueError("Case catalog changed during export")
        for name, query in lookup_queries.items():
            if lookup_snapshot[name] != client.search(name+"_recheck", query, start, end, limit, timeout):
                raise ValueError("Lookup changed during export: " + name)
        # Every normalized row must point to source records preserved in this package.
        fingerprints = Counter(r.get("record_fingerprint") for r in raw)
        represented = set()
        for event in events:
            refs = as_list(event.get("record_fingerprint"))
            if not refs or any(ref not in fingerprints for ref in refs):
                raise ValueError("A normalized event has no matching preserved source record")
            represented.update(refs)
        if set(fingerprints) != represented:
            raise ValueError("Source/normalized record reconciliation failed")
        session_proof = verify_session_provenance(raw, events)
        feeds = coverage(raw, inventory, end)
        write_json(destination/"session-provenance.json", session_proof)
        cases = case_summary(events, catalog)
        for name, rows in (("source-records.ndjson", raw), ("normalized-events.ndjson", events)):
            with (destination/name).open("x", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False)+"\n")
        for name, data in (("source-coverage.json", feeds), ("case-summary.json", cases), ("expected-inventory.json", inventory), ("case-catalog.json", catalog), ("lookup-snapshot.json", lookup_snapshot), ("search-jobs.json", client.jobs), ("configuration.json", config)):
            write_json(destination/name, data)
        write_csv(destination/"source-coverage.csv", feeds)
        write_csv(destination/"case-summary.csv", cases)
        write_csv(destination/"event-details.csv", [{"event_time_utc": utc(float(e["event_time"])), "ingest_time_utc": utc(float(e["ingest_time"])), **e} for e in events])
        worksheet = {"reviewer": "", "completed_at": "", "disposition": "", "scope_reviewed": False, "coverage_gaps_reviewed": False, "content_gaps_reviewed": False, "activity_reviewed": False, "summary": "", "findings": [], "instructions": "Copy this template outside the package. Record findings with owner/ticket or reason for no action. Run record-review; do not imply full-control acceptance."}
        write_json(destination/"review-template.json", worksheet)
        meta = {"schema": "rhel-review-1", "label": label, "app": APP, "app_version": VERSION, "start_inclusive_utc": utc(start), "end_exclusive_utc": utc(end), "ingest_cutoff_inclusive_utc": utc(cutoff), "generated_utc": utc(), "raw_records": len(raw), "normalized_category_rows": len(events), "unique_correlated_events": len({e["event_key"] for e in events}), "configured_expected_feeds": sum(r["enabled"] == "1" for r in inventory), "export_status": "COMPLETED — REVIEW PENDING", "coverage_scope": "Explicit indexed host/index/sourcetype contracts only; application/case applicability and continuity not established", "limitations": ["No automatic compliance or reviewer acceptance", "Source timestamps, human identity, retention, integrity and restore are not established by export", "Fixed event-time window can omit audit counterparts across its boundaries", "Events received after cutoff are excluded; create a new edition for late arrivals", "Receipt status reflects review lookup at export time, not historical compliance", "An empty expected inventory means scope unknown", "SIDs may expire; source records and normalized fingerprints are preserved here", "Raw source data is sensitive; restrict access and use approved retention/storage", "Checksums detect file changes, not source authenticity"], "files": {}}
        esc = html.escape
        report = '<!doctype html><html lang="en"><meta charset="utf-8"><title>RHEL audit review</title><style>body{font:16px system-ui;max-width:1250px;margin:40px auto;padding:0 24px;color:#172b3a}h1,h2{color:#12465b}.status{background:#fff0cc;padding:18px;border-left:5px solid #b98000}table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;border:1px solid #ccd7de;padding:8px;overflow-wrap:anywhere}th{background:#e9f0f4}@media print{body{margin:0}tr{break-inside:avoid}}</style><h1>RHEL audit review</h1><p>'+esc(label)+'</p><div class="status"><strong>Export completed. Human review pending.</strong> This is not an automatic control pass. Expected feeds: '+str(meta["configured_expected_feeds"])+'. '+('SCOPE UNKNOWN: configure expected inventory.' if not meta["configured_expected_feeds"] else '')+'</div><p>Event period: '+esc(meta["start_inclusive_utc"])+' to '+esc(meta["end_exclusive_utc"])+' (end exclusive). Ingest cutoff: '+esc(meta["ingest_cutoff_inclusive_utc"])+'.</p><p>'+str(len(raw))+' source records; '+str(meta["unique_correlated_events"])+' correlated events; '+str(len(events))+' category rows. One event may match several categories.</p><h2>Source coverage</h2>'+table(feeds, ["event_host","sourcetype","events","status","owner"])+ '<h2>Event categories — starter profile</h2>'+table(cases,["case_id","action","outcome","candidate_events","strict_content_complete","reviewed_receipts"])+ '<h2>Review procedure</h2><ol><li>Confirm scope and expected feeds. Investigate missing or stale sources.</li><li>Inspect event-details.csv and preserved source records. The dashboard latest-five samples are not the evidence set.</li><li>Investigate activity and content gaps; record findings and follow-up tickets.</li><li>Copy review-template.json outside this package and complete it. Use record-review to attach the review after checksum verification.</li></ol><h2>Limitations</h2><ul>'+''.join('<li>'+esc(x)+'</li>' for x in meta["limitations"])+'</ul></html>'
        (destination/"report.html").write_text(report, encoding="utf-8")
        meta["files"] = {p.name: sha(p.read_bytes()) for p in sorted(destination.iterdir()) if p.is_file()}
        write_json(destination/"manifest.json", meta)
        (destination/"SHA256SUMS").write_text(''.join(d+'  '+n+'\n' for n,d in {**meta["files"], "manifest.json": sha((destination/"manifest.json").read_bytes())}.items()), encoding="utf-8")
        return meta
    except Exception as exc:
        write_json(destination/"FAILED.json", {"status": "FAILED — DO NOT USE AS COMPLETED EVIDENCE", "error": str(exc), "jobs": client.jobs, "time": utc()})
        raise


def record_review(bundle, review_file):
    manifest_bytes = (bundle/"manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if (bundle/"FAILED.json").exists():
        raise ValueError("Failed export cannot be reviewed as a completed package")
    if not manifest["export_status"].startswith("COMPLETED"):
        raise ValueError("Export is not complete")
    for name, digest in manifest["files"].items():
        if Path(name).name != name or (bundle/name).is_symlink() or sha((bundle/name).read_bytes()) != digest:
            raise ValueError("Evidence checksum/path verification failed")
    review = json.loads(review_file.read_text())
    if not all(review.get(k) is True for k in ("scope_reviewed", "coverage_gaps_reviewed", "content_gaps_reviewed", "activity_reviewed")):
        raise ValueError("All review areas require explicit acknowledgment")
    if not str(review.get("reviewer", "")).strip() or not str(review.get("summary", "")).strip() or review.get("disposition") not in ("reviewed-no-findings", "reviewed-with-findings"):
        raise ValueError("Reviewer, summary and explicit disposition required")
    if epoch(review["completed_at"]) > time.time() or epoch(review["completed_at"]) < epoch(manifest["generated_utc"]):
        raise ValueError("Review completion must be after export and not in the future")
    if not isinstance(review.get("findings"), list) or (review["disposition"] == "reviewed-with-findings" and not review["findings"]) or (review["disposition"] == "reviewed-no-findings" and review["findings"]):
        raise ValueError("Findings and disposition disagree")
    review.update({"manifest_sha256": sha(manifest_bytes), "recorded_utc": utc(), "attestation": "User-entered review record, not a cryptographic signature or control authorization"})
    os.umask(0o077)
    write_json(bundle/"review-completion.json", review)
    (bundle/"review-completion.sha256").write_text(sha((bundle/"review-completion.json").read_bytes())+'  review-completion.json\n')
    return review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("export")
    run.add_argument("--url", default="https://127.0.0.1:8089")
    run.add_argument("--owner", default="nobody")
    run.add_argument("--ca-file")
    run.add_argument("--loopback-insecure", action="store_true")
    run.add_argument("--start", required=True)
    run.add_argument("--end", required=True)
    run.add_argument("--ingest-cutoff", help="Default: the preceding complete second at invocation")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--label", default="Weekly review — operator-selected period")
    run.add_argument("--max-rows", type=int, default=100000)
    run.add_argument("--timeout", type=int, default=300)
    review = commands.add_parser("record-review")
    review.add_argument("--bundle", type=Path, required=True)
    review.add_argument("--review-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "record-review":
            result = record_review(args.bundle, args.review_file)
            print(json.dumps({"review_recorded": True, "disposition": result["disposition"]}))
        else:
            if not 1 <= args.max_rows <= 1000000 or not 1 <= args.timeout <= 1800:
                raise ValueError("Row limit must be 1..1000000 and timeout 1..1800 seconds")
            client = Client(args.url, args.owner, args.ca_file, args.loopback_insecure)
            result = export(client, epoch(args.start), epoch(args.end), epoch(args.ingest_cutoff) if args.ingest_cutoff else int(time.time())-1, args.output, args.max_rows, args.timeout, args.label)
            print(json.dumps({k: result[k] for k in ("export_status", "raw_records", "unique_correlated_events", "configured_expected_feeds")}))
        return 0
    except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print("FAILED: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
