---
type: documentation
status: release-candidate-not-fully-validated
last_verified: 2026-09-22
---

# Validation status — 1.4.4 release candidate

This is a usable installation and review toolkit, **not a completed compliance
attestation or a claim that every required source event has been validated**.

## Verified software and bounded integration

- Installed and tested in Splunk Enterprise10.4.3 with RHEL8.10 x86_64 sources.
- Static package checks and the33-member install archive passed.
-89 candidate and89 deployed semantic checks passed without indexing fixtures.
-14 deployed native/identity fixtures and27 offline exporter tests passed.
- Four controlled file events were compared with16 primary audit records;
  normalized transport/body hashes matched the preserved indexed evidence.
- A bounded one-minute real export preserved10052source records and2741
  correlated events; all payload/manifest checksums passed. Human review was
  not fabricated, and this was not a full weekly-volume benchmark.
- Real USB disconnect/reconnect records were captured. Presence does not prove
  a physical person's identity, usable storage, authorization or file transfer.

## Per-case status and outstanding work

The reference test plan contains59cases:57baseline action/outcome cases and
two USB-presence cases. Its owner excluded the two physical-print outcomes,
leaving57required checks. That exclusion is specific to the reference test
plan and is not automatically valid at another organization.

In the fixed bounded validation window,34/57required cases had candidates,
23had no matching candidates, and **zero had full-content or accepted
verification status**. Candidate counts include background activity.
VALIDATION-MATRIX.csv lists every case without personal or host information.

Outstanding gates include remaining native event adapters and real success/
failure tests, source application context, lifecycle/security-policy tests on
an approved safe target, approved media-transfer tests, successful print-to-file
evidence, wider RHEL9/10 and architecture compatibility, distributed/production
scale and a full weekly review at the intended volume. Site-specific TLS,
retention and backup/restore must also be validated.

Remote session context was found for the four file tests. Experimental
correlation remains outside this release; it does not silently fill direct
event fields or create acceptance. The latest experimental boot-boundary test
did not pass its search-state gate and is intentionally not included.

## Interpretation rules

AU-2 selects required event types; AU-3 concerns the content of those records.
The catalog and strict additional-context profile are starting points requiring
local applicability review. Field presence, semantic accuracy, pipeline
continuity and formal acceptance are separate. Kernel/device records may lack
human identity. Do not replace missing values with guessed users or applications.

This release is not Splunk AppInspect-certified and makes no claim of
independent assessment, automatic compliance or vendor affiliation.
