---
type: documentation
status: release-candidate-not-fully-validated
last_verified: 2026-09-22
---

# Validation status — 1.4.6 release candidate

This is a usable installation and review toolkit, **not a completed compliance
attestation or a claim that every required source event has been validated**.

## Verified software and bounded integration

- Installed and tested in Splunk Enterprise 10.4.3; bounded integration uses
  RHEL 8.10 and RHEL 10.2 x86_64 audit/auth records.
- Static package checks and the 34-member install archive passed.
- 103 candidate and 103 deployed semantic checks passed without indexing fixtures.
- 33 offline exporter/review tests passed. The session integration passed 51
  deployed correlation fixtures and eight source-reconciled real-event checks.
- A controlled RHEL 10 action window reconciled all 2,797 native audit records
  to indexed records after documented transport/enrichment normalization.
- Four further RHEL 10 operations have 21 matched target/support records and
  separately reported SSH-session origin. Direct event fields remain unchanged.
- A bounded live session export preserved 950 source records and 367 unique
  correlated events. All 16 payload checksums matched; 284 derived category
  rows had complete supporting references. Human acceptance was not fabricated.
- Two native failures now map correctly: denied access to a known security-log
  target and failed non-root sudo USER_CMD. Exact source-event fingerprints,
  identities and outcomes matched before and after the classification change.
- Four disposable virtual-media copy actions and two actual PDF-generation
  actions produced the expected source results. Their bounded windows reconciled
  11,086 and 2,451 records respectively. These are record counts, not operation
  counts. Application-completion mapping and full content acceptance remain open.
- An approved isolated RHEL guest reboot and separate shutdown/start were
  performed, with postboot forwarding recovery. Native lifecycle records exist;
  per-case lifecycle mapping, failed-operation tests and content remain incomplete.
- Real USB disconnect/reconnect records were captured. Presence does not prove
  a physical person's identity, usable storage, authorization or file transfer.

## Per-case status and outstanding work

The reference test plan contains59cases:57baseline action/outcome cases and
two USB-presence cases. Its owner excluded the two physical-print outcomes,
leaving57required checks. That exclusion is specific to the reference test
plan and is not automatically valid at another organization.

The CSV contains a clearly labelled **historical 1.4.4 fixed-window snapshot**:
34/57 required checks had candidates and 23 had none. Those counts are not a
fresh census of the 1.4.6 deployment and include background activity. Later
bounded work above is separate evidence, not retroactive revision of that window.
**No full end-to-end acceptance receipt has been issued.**
VALIDATION-MATRIX.csv retains every case without personal or host information,
with an explicit snapshot version, interval and unresolved verification state.

Outstanding work includes remaining native adapters and real success/failure
tests, complete application/session context, lifecycle/security-policy semantics,
and mapping media/PDF completion into reviewable application evidence. Native
open/exec records alone do not prove completed transfers or PDF output. An
optional source-side operation logger is proposed but is **not included or
deployed** by this release. It would not cover arbitrary bypassing applications.

Wider RHEL/architecture compatibility, distributed deployments and production
scale are not established. The reference owner removed a full weekly-volume
exercise from this project's completion scope; the exporter and weekly workflow
remain included and require workload sizing at each deployment. Site-specific
TLS, retention, backups and demonstrated restore also remain deployment duties.

Bounded session correlation is included starting with 1.4.5. It requires an
unambiguous closed SSH session and preserves supporting event/record references.
Observed boot/shutdown boundaries are rejected, but absent lifecycle records can
conceal a boundary; boot continuity still requires review. Session origin is not
proof that the individual operation used the network and does not silently fill
direct fields or create acceptance. Final browser rendering after the upgrade
has not been reverified because the reference browser session expired.

Known exact RHEL log paths and reviewed collection keys require an actual access
syscall/target for the security-log category. A label on exec is insufficient.
Failed sudo USER_CMD maps denied administrative access only under the documented
native/non-root guard; authorization success is not completed elevation.

## Interpretation rules

AU-2 selects required event types; AU-3 concerns the content of those records.
The catalog and strict additional-context profile are starting points requiring
local applicability review. Field presence, semantic accuracy, pipeline
continuity and formal acceptance are separate. Kernel/device records may lack
human identity. Do not replace missing values with guessed users or applications.

This release is not Splunk AppInspect-certified and makes no claim of
independent assessment, automatic compliance or vendor affiliation.
