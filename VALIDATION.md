---
type: documentation
status: release-candidate-known-content-gaps
last_verified: 2026-09-22
---

# Validation status — 1.4.8 release candidate

This is a tested installation and review toolkit, not a compliance attestation
or a promise that default forwarded logs cover every required event.

## Case results

The reference plan has 59 cases: 57 baseline action/outcome cases plus 2 USB
presence cases. The reference owner excludes 2 physical-print outcomes, leaving
57 required. Another organization must decide its own applicability.

**All 57 required cases have been evaluated: 55 supported category checks,
2 confirmed USB-content gaps, 0 untested.** The 55 comprise 49 explicitly wrapped
operation cases, 2 two-phase lifecycle cases, 2 exact native login/logout cases,
and 2 OS Restart aliases of already verified Reboot evidence. These are not 55
distinct real operations or 55 automatic native event adapters. Alias rows
keep the original event identity so cross-category totals can deduplicate them.

[VALIDATION-MATRIX.csv](VALIDATION-MATRIX.csv) shows every case and its actual
scope. No private users, hosts, raw logs or evidence identifiers are published.
No independent acceptance receipts have been issued.

## Confirmed USB gaps — do not mark these as content passes

Physical attachment and disconnection were confirmed against the reference
owner's unplug/replug, source times/port and indexed event fingerprints.
The kernel records identify the device observation, not the human at the port.
The configured strict profile therefore still reports missing actor,
initiator/completer, terminal, access context and privilege.

Version 1.4.8 adds separate overlapping closed-SSH-session context. It uses
same-host successful LOGIN/sshd USER_LOGIN/USER_LOGOUT anchors with matching
session identity and rejects observed lifecycle boundaries. Multiple sessions
remain multiple candidates. No match is not proof that no users were logged
in. The physical test window had no qualifying complete closed-session set.
Open sessions and local-console sessions are not covered by this adapter.
Changing the selected time window can change available contextual evidence.

Context never fills direct identity fields or changes their AU-3 pass/fail
status. An operator statement, controlled media workflow or additional
endpoint telemetry would be separately attributed evidence, not a retroactive
kernel-record field. Adding such collection needs site design/authorization.

## Verified software and integration

- App 1.4.8 installed on Splunk Enterprise 10.4.3; 22 packaged files matched the
  archive, 5 site-specific files and existing shared/private scopes preserved.
- 111 candidate and 111 installed semantic checks; 11 new context fixtures before
  and after install; fixtures are search-only and never indexed.
- 33 offline exporter/review tests plus 7 USB-provenance checks. The 11 existing
  optional-recorder tests cover its separate source-library contract.
- Real OS Restart success/failure labels reuse the exact verified Reboot
  success/denial fingerprints and content, with 2 distinct events across 4 rows.
  A service restart is not an OS restart.
- Both native Shutdown/Boot records were recovered after the approved
  audit-rotation input repair; their raw hashes and timestamps match source.
  A 2-minute post-repair sample had 9,221 rows/9,221 unique hashes. This is not a
  guarantee of all-time deduplication or lossless delivery.
- Earlier bounded windows reconciled 2,797 native records, 11,086 media-test
  records and 2,451 PDF-test records. Record counts are not operation counts.
- A prior bounded export preserved 950 original records and 367 unique events;
  derived session references were closed. The full weekly-volume exercise is
  owner-excluded, but the exporter and weekly-review workflow are included.
- A fresh 1.4.8 bounded export completed with 562 original records and
  157 unique correlated events. This five-second regression is not a weekly
  exercise, full fleet audit or human review.

## Remaining deployment and acceptance boundaries

Other-role execution and final browser rendering are not independently
verified. Tests use authenticated administrator API access, including shared
app namespace checks; shared definitions do not themselves prove analyst
permissions. No account, role or index permission was changed for these tests.

Automatic arbitrary-application coverage, full RHEL 9/10 coverage, other
architectures, distributed deployments and production scale are unvalidated.
Integration used RHEL 8.10 and RHEL 10.2 x86_64 native records. The optional
Python 3.9+ recorder is a library for explicitly integrated calls; installing
the Splunk app does not activate it or instrument applications.

Missing session or lifecycle records can conceal boundaries. Exported
reference closure proves supporting indexed records were preserved, not that
the source is authentic or complete. Retention, source protection, TLS,
backups/restore, time synchronization and assessment acceptance remain
separate responsibilities. No AppInspect certification, vendor affiliation,
automatic compliance pass or independent assessment is claimed.
