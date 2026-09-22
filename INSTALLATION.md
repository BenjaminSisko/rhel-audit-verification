---
type: documentation
status: release-candidate
last_verified: 2026-09-22
---

# Installation and first verification

This guide describes the tested 1.4.8 release candidate. Review VALIDATION.md
before operational reliance. The `.spl` installs on the search head,
not on the Universal Forwarder. Distributed deployments need separate testing.

## 1. Establish the collection prerequisites

Identify approved RHEL hosts, applications, required events and owners. Ensure
the source generates each event with the required content and the existing
Universal Forwarder can read and forward it to an approved Splunk index.
Verify indexed original host identity, timestamps, sourcetype and access rights.
Avoid collecting the same audit trail through both a direct monitor and relay.

Read the shipped `RHEL-SOURCE-ONBOARDING.txt`, `UF-INPUTS.conf.example` and
`USB-COLLECTION.txt` before changing collection. Reference inputs are disabled;
they are not a safe universal configuration. Source rules, destination/TLS,
capacity, retention and backups require separate site-specific decisions.

Check kernel audit loss/backlog, dispatcher queues and any relay rate limiting.
A connected forwarder or a fresh event does not prove lossless delivery.
Do not run a full controlled test suite while the source pipeline is dropping
records. Immutable audit policy changes can require an approved reboot.

Verify collection across rotation and a controlled forwarder outage. The
reference test found that an exact audit.log monitor missed shutdown/boot
records renamed into audit.log.1 while the forwarder was offline. Evaluate
an approved directory monitor restricted to numbered audit rotations, replacing
overlapping inputs rather than adding duplicates. Preserve CRC identity and
checkpoints; do not reset them to make a test pass. The approved reference
repair recovered both exact native transition records. A bounded2-minute
sample had9,221rows/9,221unique hashes; this does not prove all-time lossless
or duplicate-free delivery. The disabled example now includes numbered
rotations. Test your deployment independently before enabling it.

## 2. Install the release

Use `dist/TA_au2_linux-1.4.8.spl` and `dist/SHA256SUMS` from this bundle.
Verify the archive's SHA-256 against that manifest. Back up any existing app,
`local/` configuration and operational lookups before an upgrade.

In Splunk Web, use Manage Apps → Install app from file and select the `.spl`.
Follow the installation result and your site's deployment/restart procedure.
The internal app ID remains `TA_au2_linux`; the displayed name is
**RHEL Audit Verification**.

## 3. Set the approved search scope

Create or update `$SPLUNK_HOME/etc/apps/TA_au2_linux/local/macros.conf` using
your normal Splunk configuration-management process. Replace illustrative
values with your approved index and sourcetypes:

```ini
[aulx_source]
definition = search index=rhel_audit (sourcetype="linux:audit" OR sourcetype="linux:secure" OR sourcetype="linux_app_audit")
iseval = 0
```

Include `linux:kernel:usb` only if that collector contract has been deployed and
validated. Restrict mixed indexes to the approved RHEL host inventory. The
legacy overview has a separate `au2_linux_source` macro. Do not edit packaged
`default/` files to store site overrides. Verify effective configuration after
the normal reload/deployment procedure.

Test scope as the intended analyst, not only the administrator who created the
macro. User-owned knowledge objects can shadow app-shared scope. Check sharing,
ownership and index permissions; reference other-role verification is pending.

## 4. Configure expected feeds

Create `lookups/site_expected_sources.csv` with the shipped schema:

```csv
event_host,index,sourcetype,owner,max_silence_seconds,enabled
example-rhel.example.invalid,rhel_audit,linux:audit,Example owner,3600,1
```

The row is illustrative, not a recommended universal silence threshold.
Use exact indexed values and an owner-approved threshold for each feed.
Set the lookup binding in `local/transforms.conf`:

```ini
[aulx_expected_sources]
filename = site_expected_sources.csv
case_sensitive_match = true
```

An empty inventory means coverage is unknown. It must not be treated as a pass.
Keep operational inventory and verification receipts in separately named,
access-controlled, backed-up lookups outside the distributed release content.
The detailed shipped README explains the receipt lookup override and schema.

## Optional application instrumentation

The source bundle includes tools/operation_audit.py; the .spl does not install
it on RHEL. It records only calls explicitly integrated with its API, using
existing administrator authority. Follow [OPTIONAL-RECORDER.md](OPTIONAL-RECORDER.md).
Do not grant a generic privileged command runner or deploy a validation
harness as production monitoring. Native audit remains necessary.

## 5. Verify before relying on it

Open **Review readiness**, then **RHEL Audit Verification**. Select a bounded
time window and host. Compare expected feeds with indexed evidence. Inspect
each required action/outcome and its original source records, not just counts.

Run approved, benign controlled source actions and correlate time, host, audit
event IDs, identities, target objects and outcomes through to Splunk. Validate
success and failure separately where required. Physical USB testing must occur
after its reader is active; insertion does not test media import/export.
Document exclusions explicitly. Never fabricate a receipt for an untested case.

Missing users can reflect unset audit login IDs, service activity, insufficient
source enrichment or missing correlated records. Inspect the identity basis and
source record. Do not replace missing actors with target accounts or guessed
names. A zero tile means no matching evidence in the selected window, not proof
that collection is disabled. Search warnings, truncation and source loss must
be resolved before claiming completeness.

## Upgrade and rollback

Preserve local overrides, separately named inventory and receipt lookups, and
the previous verified app artifact. After upgrade, repeat package/version,
scope, feed-health and representative event checks. Roll back using the prior
app and saved configuration under your deployment procedure. This app does not
delete or rewrite indexed source records.
