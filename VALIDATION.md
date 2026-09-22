---
type: documentation
status: release-candidate-not-fully-validated
last_verified: 2026-09-22
---

# Validation status — 1.4.7 release candidate

This is an installation and review toolkit, not a completed compliance
attestation or a claim that default forwarded logs cover all required events.

## Current per-case evidence

The reference plan contains59 cases:57 baseline action/outcome cases plus two
USB-presence cases. The owner excluded the two physical-print outcomes,
leaving57 required. That exclusion does not automatically apply to another site.

**52/57 required cases have technical evidence; five remain incomplete.**
The52 consist of49 explicitly wrapped commands, one explicitly observed
two-phase reboot, and two exact native login/logout events. Source/index
hashes, normalized content and operation-specific checks support those cases.
They are not52 automatically supported native event types and are not
independent control acceptance.

[VALIDATION-MATRIX.csv](VALIDATION-MATRIX.csv) contains all59 cases, reference
applicability, technical status, evidence scope and acceptance state. It
replaces the historical candidate-count snapshot in the previous release.
No users, hosts, raw records or private evidence identifiers are published.
No independent acceptance receipts have been issued.

Remaining required cases:

- Successful shutdown: actual guest shutdown/off/recovery and helper receipt
  passed, but the supporting native records were in audit.log.1, outside the
  exact-file Universal Forwarder monitor. Native reconciliation failed; the
  collection repair is pending approval/testing, so this case is not credited.
- Restart success and failure: the required distinction from Reboot needs
  the reference owner's definition; do not double-count one test.
- USB attachment and disconnection content: source/index device-presence
  evidence exists, but physical human identity is not provided by kernel
  observations. Any operator testimony must be separate from log-derived fields.

## Verified software and bounded integration

- Installed app1.4.7 on Splunk Enterprise10.4.3; source integration has used
  RHEL8.10 and RHEL10.2 x86_64 audit/auth records.
- Static package/archive checks,111 candidate and111 deployed semantic checks,
  and33 offline exporter/review tests passed. Fixtures were not indexed.
- Source-reported authentication target identity is now distinct from login
  and process identities; one native login/logout pair matched exact source
  hashes and all configured content fields.
- Eleven offline optional-recorder contract tests passed. The recorder was
  exercised on the reference guest for explicit file, account, configuration,
  media/PDF, privilege and authentication operations.
- Actual unprivileged reboot/shutdown requests were denied and left the boot
  unchanged. Successful reboot used a two-phase observation and separately
  reconciled both underlying native transition records in Splunk.
- Earlier bounded source windows reconciled2797 native records,11086 records
  for media operations and2451 for PDF operations. These are record counts,
  not operation counts or proof of continuous lossless delivery.
- A bounded live export preserved950 original records and367 unique correlated
  events; all16 payload checksums matched and284 derived category rows had
  complete supporting references.
- Session integration passed51 correlation fixtures and eight real-event
  checks. Derived SSH-session context remains separate from direct fields.

## What is not established

The optional recorder is included as a library, not enabled by installing the
app. It covers only explicitly integrated calls. The environment-specific
validation harness and lifecycle controller are deliberately not distributed.
Native exec/open records alone do not prove successful media transfer, PDF
creation, application startup completion or privilege use.

Automatic arbitrary-application coverage, full RHEL9/10 coverage, other
architectures, distributed deployments and production scale are unvalidated.
The recorder requires Python3.9 or later and was exercised on RHEL10.2.
Test other interpreter/OS combinations before deployment.

Reference tests used administrator search scope. Other-role/shared-macro
behavior and final upgraded browser rendering remain pending; the reference
browser session expired. A healthy service or fresh record does not establish
complete ingestion. The rotation gap is an explicit counterexample.

The owner removed the full weekly-volume exercise from the completion gate;
the manual exporter, reviewer worksheet and weekly workflow remain included.
Size and validate each deployment's workload. Site TLS, source protection,
retention, backups, demonstrated restore and time synchronization are separate
operational responsibilities, not proven by field presence.

Session correlation requires an unambiguous closed SSH session and supporting
record references. Known boot/shutdown boundaries are rejected; missing native
records can conceal a boundary. Review continuity before accepting derived
context. Session origin does not prove that every operation used the network.

## Interpretation

AU-2 selects the event types to log; AU-3 concerns record content. The catalog
and stricter additional-context profile require local applicability review.
Field presence, correct meaning, pipeline continuity and acceptance are
separate decisions. Attempted account names do not establish a physical
person's identity. Unknowns stay unknown.

No Splunk AppInspect certification, independent assessment, automatic compliance
pass or vendor affiliation is claimed.
