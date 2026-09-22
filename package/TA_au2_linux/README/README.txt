RHEL Audit Verification 1.4.4
============================

Purpose
-------
Version 1.4.4 excludes PATH records marked PARENT from the exact target-object
field. Parent-only evidence remains available in the original records, but
does not satisfy target content. A correlated CREATE/NORMAL target is retained.
This corrects an observed failed-create case; it does not reconstruct missing
targets from arbitrary process arguments or infer remote/local context.

Version 1.4.3 removes unsupported completion inferences from rule keys,
identity-change syscalls and standalone boot records. Originating applications
come from native exe/comm, not the audispd relay prefix. Events lacking proof
remain visible as unmapped or as the actual recorded lower-level action.
Printing, media transfer, account-disable, restart/reboot and privilege elevation
still require outcome-bearing native adapters or reviewed application records;
their catalog tiles remain required and are not marked passed or excluded.

The parser also recognizes quoted native op fields and selected RHEL USER_MGMT,
GRP_MGMT and ACCT_LOCK operations observed during controlled source tests.
An expiration-date change is a user modification, not automatically a disable.
Native operations/outcomes and target account IDs remain visible; missing
fields and absent error records are not fabricated.

Universal Forwarder onboarding, expected-feed readiness and the manual weekly
evidence export/review procedure are in REVIEW-GUIDE.txt. RHEL-SOURCE-ONBOARDING.txt
explains the source rule, forwarding and rotation layer that must exist before
the dashboard can show evidence. This version preserves source-enriched
login/process/effective usernames and numeric audit IDs, with account roles
kept separate and explicit missing-user labels. It also accepts RHEL audit
numeric result values, preserves native operation/target context, recognizes
open/openat access and native SYSTEM_SHUTDOWN candidates. SYSTEM_BOOT is
retained as an unmapped boot observation until lifecycle evidence establishes
that it belongs to a reboot. Audit keys identify rule matches, not completion.
Search already-indexed Red Hat Enterprise Linux audit/authentication records,
correlate native audit records by host and audit event identifier, classify
event actions/outcomes, and check AU-3 record content plus application context.
The dashboard has 57 individual action/outcome tiles in 13 sections. Successful
sign-in, failed sign-in, and sign-out have separate tiles. This is an editable
baseline catalog, not a universal assertion that every organization requires
exactly these 57 cases. Reconcile it with the approved system event catalog.
Two supplemental USB attachment/disconnection tiles are separate from that
baseline and excluded from its 57-case captured-coverage score.

Each tile shows the full-window candidate count and up to five most recent
matching events (time, user, host, application), newest first. The sample is
not the total: a tile can show a count of 211 while listing five events.
Each tile distinguishes captured candidates, required-field presence, missing
information, and reviewed test receipts. Missing events remain visible. A zero
count is no evidence in this search window, not proof logging is disabled.
Field presence is not semantic accuracy or a compliance pass.

Installation and scope
----------------------
Install the .spl through Manage Apps / Install app from file, on the search
head. Back up existing local configuration and lookups before upgrading.
No source agents, indexes, inputs, listeners, users, roles, scheduled searches,
alerts, collection rules, or network paths are created by installing the .spl.
Data must already be indexed and readable by the user's Splunk role. The source
onboarding guide and disabled/reference configurations are deliverables, but
an administrator must review and deploy them separately on each RHEL host.
Existing forwarding alone cannot supply records or application fields that the
source never generated.

The default aulx_source macro discovers common Linux audit, secure, syslog,
journald and Wazuh sourcetypes in searchable noninternal indexes. In a mixed
estate constrain this macro in local/macros.conf to approved RHEL hosts,
indexes and sourcetypes; generic syslog and hostnames do not prove OS identity.
The legacy overview uses its separate au2_linux_source macro. Do not edit
default/macros.conf because an upgrade replaces it.

Example local/macros.conf (replace the illustrative values):
[aulx_source]
definition = search index=rhel_audit (sourcetype="linux:audit" OR sourcetype="linux:secure" OR sourcetype="linux_app_audit")
iseval = 0

USB kernel observations
-----------------------
Optional source recipe: README/USB-COLLECTION.txt. The dashboard install does
not enable collection. The USB adapter accepts native journal JSON or the plain
kernel message produced by some Universal Forwarder journald configurations.
Both require the exact sourcetype linux:kernel:usb; a present _TRANSPORT field
must equal kernel. Explicit JSON paths retain journal fields whose leading
underscores can be lost by automatic extraction. Only this collector-stamped
kernel source contract is mapped, not wrong-sourcetype userspace lookalikes.
Plain records may lack boot identity; the five-second same-host/same-port/
device-number boundary remains conservative but requires installed-forwarder
validation. Device-found and disconnect observations have their own
tiles; success means the kernel observation, not storage authorization.
Boot enumeration as well as hot-plug can produce these messages; they do not
by themselves prove a new human insertion or identify the person involved.
No USB serial numbers are required by the supplied collector filter.

The adapter groups the start/device-found/product/manufacturer records only
within the same host, boot, port and device-number sequence and within five
seconds. One sequence is one attachment candidate. Orphan context remains
unmapped; partial windows and late records may yield incomplete context.
User/physical actor, terminal, initiator/completer and privilege are not filled
with guesses. Device presence does not prove reading/writing/import/export,
and the adapter does not determine whether storage policy blocked access.

Supported evidence and content
------------------------------
Native audit parsing supports common type=... msg=audit(epoch:serial) records,
selected x86_64 syscall numbers, explicit audit keys, SSH Accepted/Failed and
PAM session messages. It also unwraps Wazuh full_log. Unrecognized events stay
unmapped rather than being marked compliant. Numeric syscall mapping is
x86_64 only. An executable name alone does not prove an application operation
succeeded. Account target names are not substituted for the acting identity.

Base content checks: action, event time, host/location, source, acting identity,
and outcome. The included stricter profile also checks terminal/workstation,
remote/local indicator, initiating/completing identities, application, object,
correlation identifier, privilege context, and failure reason where relevant.
These additional fields are profile requirements, not all universal AU-3 base
requirements. Review the selected control enhancements and application scope.
Timestamp presence does not verify clock synchronization or time correctness.

For unsupported application formats, add a reviewed extraction/classification
mapping or forward normalized JSON with sourcetype linux_app_audit. Example
schema, not production evidence:
{"timestamp":"2026-01-01T12:00:00Z","service":{"name":"example-app"},"user":{"name":"example-user","effective":{"id":"1000"}},"object":{"name":"example-object"},"terminal":{"id":"example-terminal"},"event":{"action":"Sign-in","outcome":"success","id":"example-unique-id","initiator":"example-user","completer":"example-service","remote":true,"reason":"authenticated"}}
Use an action exactly matching the catalog and explicit success/failure.
Do not put passwords, tokens, private keys or unnecessary sensitive content in
audit events. Source/application owners must enable the relevant audit events.

Verification receipts
---------------------
The shipped aulx_verification_receipts.csv contains headers only. No passed
receipts are manufactured. A receipt associates an event fingerprint, host,
application and case with controlled test evidence, reviewer, review decisions
and expiry. Field completeness is still required. The fingerprint is an event
reference, not a tamper-evident signature. Reviewers must validate timestamps,
semantics and source evidence independently before accepting a receipt.

Keep real receipts in a separately named lookup, backed up with appropriate
access controls. Override [aulx_verification_receipts] in local/transforms.conf
with filename = your_reviewed_receipts.csv and case_sensitive_match = true.
Retain the shipped column schema. This prevents app upgrades from overwriting
the operational receipt file with the empty template. No receipt-entry UI or
automatic proof generation is included.

Limits and validation
---------------------
Bound searches by time, host and application. The tiles share one transforming
base search. A second shared search retains five recent events per
case/host/application and supplies every sample table. The detailed evidence
table displays at most 500 rows from that sample cache, not a complete export.
Counts are category matches, not guaranteed unique fleet events.
Audit records crossing a time-window boundary may correlate incompletely.
Log duplicates, late arrival, source identity and timestamp accuracy require
independent validation. Multi-host results do not establish complete fleet
coverage; maintain an authoritative expected-host/application inventory.

Tested in Splunk Enterprise 10.4.3 with actual RHEL 8 x86_64 forwarded data and
nonindexed synthetic fixtures covering all 57 catalog cases. RHEL 9/10 source
coverage, other CPU architectures, arbitrary applications, distributed search
head deployments and production scale remain unvalidated. The test server's
RHEL version does not establish coverage for that version's source logs.
No AppInspect certification, universal plug-and-play claim, or assessor
acceptance is implied. The legacy overview remains available for comparison;
use the new RHEL Audit Verification view for explicit content/proof gaps.
The USB collector was configured on a RHEL 10.2 test host with UF 10.4.3;
nonindexed fixtures test two insertions, one disconnection, boot/time boundaries
and a userspace false positive. Fresh physical-test receipt is a separate gate;
installation, connected sockets and fixtures alone do not prove that receipt.

Rollback: restore the prior app, local configuration and backed-up lookups
using your deployment procedure. Indexed source records are not modified.
