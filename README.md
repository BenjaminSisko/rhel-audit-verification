---
type: documentation
status: release-candidate
last_verified: 2026-09-22
---

# RHEL Audit Verification

A Splunk app for reviewing Red Hat Enterprise Linux audit evidence collected
by existing Universal Forwarders. It organizes supported records into event
categories, displays source-reported identities and application context, and
helps an analyst identify missing evidence before completing a weekly review.

**Release status: validation in progress.** Version 1.4.8 is a tested software
build, not a fully accepted end-to-end audit solution. A reference source had
historical loss; later controlled RHEL 10 windows reconciled source to index.
Those bounded checks do not establish lossless operation or full event coverage.
Do not use candidate counts or passing software fixtures as control acceptance.

Parent-only native PATH records do not satisfy the exact target-object field.
The current semantic regressions ensure audit-rule labels and command launches
do not masquerade as completed printing, media transfer or privilege changes.
All event cases remain in scope; native adapter and source-content gaps remain
explicit. A bounded live export has reconciled original and normalized records,
but full weekly, fleet-wide and per-control acceptance is not yet established.

## What you get

- Separate action/outcome tiles, including successful and failed authentication.
- Full-window candidate counts and up to five newest samples per tile.
- Recorded user, process user, host and application, with detailed login and
  effective identities, target account, object, outcome and missing content.
- Separate, source-backed SSH-session origin/source columns when an unambiguous
  closed session is available; direct event fields are not overwritten.
- AU-2 event-catalog mapping and AU-3 content checks, with a separately identified
  stricter context profile that requires local applicability review.
- Expected-feed readiness checks and explicit missing/stale-feed results.
- A manual weekly export with original indexed records, normalized events,
  readable report, search metadata, checksums and a reviewer worksheet, including
  a check that every record supporting derived session context is preserved.
- Source, build tools, tests and disabled RHEL collection examples.
- Optional source-side command-recorder library and offline tests. This is
  explicit application instrumentation, not an automatic collector.

The starter catalog contains 57 baseline action/outcome cases and two
supplemental USB-presence cases. It is an editable baseline, not a universal
statement of which events every organization must audit.

## How it fits

RHEL and applications generate records; Universal Forwarders collect configured
inputs; Splunk indexes them; this app classifies, displays and exports them.
Installing the app does **not** enable endpoint audit rules, collect arbitrary
application logs, create indexes or receivers, configure retention or TLS, or
recover records that were never generated or were dropped in transit.

Begin with [quick start](QUICKSTART.md) and [installation](INSTALLATION.md), then follow the
[weekly review guide](WEEKLY-REVIEW.md). The app also includes detailed source,
USB and review guides under `package/TA_au2_linux/README/` in the final repository.
For application-completion evidence, read [OPTIONAL-RECORDER.md](OPTIONAL-RECORDER.md).
Installing this library alone does not instrument applications.

## Validation boundaries

The current build has static/package tests and 33 offline exporter/review tests.
The latest classification suite passed 111 candidate and 111 deployed checks.
Live integration has used Splunk Enterprise 10.4.3, RHEL 8.10 and RHEL 10.2
x86_64 audit/auth records. Full RHEL 9/10 source coverage, other architectures, arbitrary
applications, distributed deployments and production scale remain unvalidated.
Source loss, missing cases and incomplete fields remain release gates.

The reference plan has **57 required cases evaluated:55 supported category
checks and2 confirmed USB-content gaps**. The55 include49 explicitly wrapped
operations, two two-phase lifecycle checks, two exact native login/logout
events and two OS Restart aliases of Reboot. Aliases reuse the same evidence;
they are not additional operations. These are not55 automatically covered
native event types. The rotated-audit collection repair recovered the exact
Shutdown records. USB presence is captured, but physical identity is absent. See the
[full matrix](VALIDATION-MATRIX.csv) and [validation details](VALIDATION.md).

USB kernel observations establish device presence, not the physical person's
identity, access authorization or a file transfer. Failed-login account names
identify the attempted account, not necessarily the person making the attempt.
Unknown identities remain unknown; field presence alone is not semantic proof.

Version1.4.8 shows overlapping closed SSH sessions alongside USB observations
when complete same-host session anchors are in the selected window. It does
not infer open/local-console sessions or identify the person at the connector.
No qualifying session means insufficient evidence, not that nobody was logged
in. Exported context includes supporting references and a reference-closure
check. OS Restart tiles explicitly say they alias Reboot; use unique event keys
when totaling activity across categories.

No Splunk AppInspect certification, independent assessment, automatic compliance
pass or affiliation with Splunk or Red Hat is claimed.

## Building and testing

The bundle includes the `package/`, `searches/` and `tools/` layout.
With Python 3 and Bash available, run from its root:

```sh
bash tools/build_app.sh
python3 tools/validate_app.py package/TA_au2_linux --archive dist/TA_au2_linux-1.4.8.spl
python3 tools/test_review.py
python3 tools/test_operation_audit.py
python3 tools/test_usb_provenance.py
```

These are software checks, not controlled source-event tests. This bundle
includes the exact build, checksum and [sanitized validation summary](VALIDATION.md).
Use the tested artifact for installation; do not install development candidates.

## Security and licensing

Keep production records, evidence exports, inventories, reviewed receipts,
credentials and local configuration out of the public repository. Report issues
with redacted examples or clearly labeled synthetic fixtures.

No open-source license has been selected or granted. Public visibility does not
grant reuse or redistribution rights; see [NOTICE](NOTICE.md). License selection
remains an owner decision, separate from technical validation.
