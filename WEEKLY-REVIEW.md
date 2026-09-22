---
type: documentation
status: release-candidate
last_verified: 2026-09-22
---

# Weekly audit review

This is a manual evidence-review workflow. The app does not schedule reviews or
decide whether activity was authorized. The shipped
`package/TA_au2_linux/README/REVIEW-GUIDE.txt` contains the detailed export contract.

## Review the period

1. Select fixed start/end times with a timezone and confirm approved host,
   application and event scope. Preserve exclusions and their rationale.
2. Inspect expected-feed coverage and source health first. Investigate missing
   or stale feeds, audit loss/backlog, queue drops, time skew and transport gaps.
3. Review each applicable tile's count, newest samples, users, applications,
   outcomes and missing fields. Five samples are not the complete event set.
4. Inspect original records for privileged actions, account changes, failures,
   policy changes and other locally required activity. Record findings and
   owners; successful activity is not automatically authorized activity.
5. Export the fixed period, preserve the evidence and record the human review.

## Export the evidence

Run the helper with Python 3 on an approved machine with access to the existing
Splunk management API. Use an approved read/search account and provide
`SPLUNK_TOKEN`, or `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`, through your secret
mechanism. Never put credentials in command arguments, source control or reports.
Certificate verification is enabled; use `--ca-file` for an enterprise CA.

From the final repository root, replace the example endpoint, dates and path:

```sh
python3 package/TA_au2_linux/bin/aulx_review.py export \
  --url https://splunk.example.invalid:8089 \
  --start 2026-09-14T00:00:00Z --end 2026-09-21T00:00:00Z \
  --output /approved/evidence/rhel-week-2026-09-14
```

Start is inclusive and end exclusive. The ingest cutoff identifies which
arrivals were available to that export; later arrivals require a separately
named new edition. Exports cover at most eight days. The default limit is
100,000 rows per result set. A failed export or `FAILED.json` is not a completed
review. Do not silently ignore warnings, truncation, missing pages or failed
source-record reconciliation.

The bundle includes `report.html`, original and normalized NDJSON records,
`event-details.csv`, source-coverage and case-summary files, inventory/catalog/
configuration snapshots, search metadata, a manifest, `SHA256SUMS` and an
unsigned `review-template.json`. Store it as sensitive evidence with approved
access, retention and backup. Do not upload bundles to GitHub.

Keep `aulx_review.py` and `aulx_provenance.py` together if copying the exporter
outside the app. `session-provenance.json` reports whether all supporting
session-event and record references resolve in the same evidence export.
Missing, ambiguous or mismatched support fails the export. A matching checksum
and resolved references do not establish boot continuity or semantic acceptance.
No derived context is reported as `NO_DERIVED_CONTEXT`, not a passed test.

## Record the human decision

Copy `review-template.json` outside the bundle. Complete reviewer identity,
timezone-qualified completion time, summary, required acknowledgments,
findings and disposition. Then run:

```sh
python3 package/TA_au2_linux/bin/aulx_review.py record-review \
  --bundle /approved/evidence/rhel-week-2026-09-14 \
  --review-file /approved/reviews/completed-review.json
```

The helper verifies checksums and writes a separate review record linked to the
manifest. It does not alter original evidence or automatically sign or accept
controls. Hashes detect later file changes; they do not prove source authenticity
or that every event was captured. Weekly review completion and controlled-test
verification receipts are separate records with different purposes.

Track unresolved collection, identity, mapping and content gaps into the next
review. Close them only with supporting evidence, not by hiding empty tiles.
