---
type: documentation
status: release-candidate
last_verified: 2026-09-22
---

# Start here — RHEL Audit Verification 1.4.7

**Installable now; complete control validation is not claimed.**
This app works with logs already indexed from Universal Forwarders. It does
not turn on missing RHEL audit rules or create application audit records.

1. Unzip the handoff bundle. In its dist folder run
   `sha256sum -c SHA256SUMS` on Linux or `shasum -a 256 -c SHA256SUMS` on macOS.
2. In Splunk Web: **Apps → Manage Apps → Install app from file**. Select
   **dist/TA_au2_linux-1.4.7.spl**. Back up an older app and site lookups before
   selecting an upgrade. Follow your site's reload/restart process if requested.
3. Set the **aulx_source** search macro to your real RHEL index and sourcetypes.
   See [INSTALLATION.md](INSTALLATION.md) for the local/macros.conf example.
   Do not leave the broad starter index scope in place for production.
4. Configure the expected host/index/sourcetype inventory described in the
   installation guide. A blank inventory means **unknown coverage**, not pass.
5. Open **RHEL Audit Verification** and **Review readiness**. Choose a short
   time range and one known host first. Each event/outcome tile shows a count
   and up to five recent samples; inspect the user, application and gaps.
6. Compare an actual known event with its source record. Do not interpret
   a green-looking count, an empty tile or a software test as control acceptance.
7. Use [WEEKLY-REVIEW.md](WEEKLY-REVIEW.md) to export a fixed review period and
   record the human review. Preserve original records in protected storage.

Use **RHEL Audit Verification** for evidence checking. The older broad
overview is retained for compatibility; its keyword candidates are not
verified events and must not be used as control-validation proof.

## What is in the handoff

- dist/TA_au2_linux-1.4.7.spl: install this in Splunk, not on the forwarder.
- package/: the complete portable app source and packaged source-onboarding,
  USB, input-example and review instructions.
- searches/: readable search logic.
- tools/: reproducible build, static validation and offline review tests.
- OPTIONAL-RECORDER.md and tools/operation_audit.py: explicit source integration,
  not an automatic all-application collector; separate offline tests included.
- VALIDATION.md and VALIDATION-MATRIX.csv: honest current boundaries.
- INSTALLATION.md and WEEKLY-REVIEW.md: setup and ongoing use.

## If the dashboard is empty

First confirm the original records exist in your Splunk index, the source macro
matches their actual sourcetypes, and your role can search that index. Expand
the time range only after checking timestamps. Missing audit rules, unreadable
source files, dropped logs and unsupported application formats require source
work; this app cannot manufacture the missing records.

Do not mark required events excluded just because the app cannot currently
verify them. Scope exclusions require the system owner's approval.
