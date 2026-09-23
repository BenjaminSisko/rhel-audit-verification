---
type: documentation
status: release-candidate
last_verified: 2026-09-23
---

# First-run setup wizard

Install the app on a standalone Splunk Enterprise search head, then open
**Set up RHEL Audit Verification** from its navigation. An unconfigured app
declares this as its first-run setup view. Use your existing Splunk login;
there are no endpoint passwords, extra services or external telemetry.
If Splunk displays its standard unconfigured-app prompt, click **Continue to app
setup page**. This is the normal first-run path, not an installation failure.

## 1. Find logs

Choose one to five approved indexes from the list, or type their exact names
if your account cannot list indexes. Click **Find my logs**. No indexed discovery
search runs automatically when you open setup.

Discovery examines at most10,001 records from the last24hours, with a25-second
server search bound. It suggests auditd/authentication formats and known
application/USB sourcetype contracts. Other formats stay explicitly unrecognized.
The sample limit is visible. A recent sample is not complete host discovery,
RHEL identification, lossless delivery or permission certification.

## 2. Confirm expected feeds

Check observed feeds, enter their owner and approved silence threshold, then
click **Add checked feeds**. Edit the CSV draft or import your inventory to
include silent hosts. CSV import replaces only the draft. Existing saved
inventory is loaded at startup and is not silently discarded.

The exact six-column schema is:

```csv
event_host,index,sourcetype,owner,max_silence_seconds,enabled
rhel01.example.invalid,rhel_audit,linux:audit,Linux operations,3600,1
```

The3,600-second example is a suggestion, not a control requirement. Supported
thresholds are60–2,592,000seconds. Enabled is0 or1. Maximum200 feeds/150KB input;
each host/index/sourcetype tuple must be unique. Names must be exact, with no
wildcards, spaces, quotes or SPL fragments. Use the manual deployment guide for
unsupported names, non-CSV lookups, larger fleets or managed/clustered installs.

Confirm the selected systems are Red Hat systems within your audit scope.
Imported rows with enabled=0 remain in inventory but not in the generated scope.

## 3. Preview and save

Click **Preview configuration** and inspect the before/after source scope.
The scope uses exact host/index/sourcetype tuples, not a broad cross-product.
Explicitly approve the preview and click **Save configuration**. Any edit
invalidates the preview. An administrator with write access to the app's
configuration objects must save. The app does not grant permissions.

The wizard uses existing same-origin Splunk REST APIs to:

1. Check that configuration still matches the preview.
2. Save an app-scoped backup in `local/aulx_setup.conf`.
3. Create a uniquely named `aulx_setup_<id>.csv`, then compare its read-back.
4. Update only `aulx_source`, the `aulx_expected_sources` CSV filename binding,
   and the app's `is_configured` flag, verifying each change.
5. Record completion and show the backup ID.

Existing inventory files, verification receipts, other macro/lookup settings,
and the legacy overview's separate scope are untouched. The wizard changes no
inputs, audit rules, forwarders, indexes, credentials, roles, retention or
source records. Backup records contain scope/inventory, not passwords.

Use one administrator/window at a time. These are multiple REST operations,
not an atomic database transaction. Drift checks reduce conflicts; they cannot
eliminate the last read/write race. Interrupted saves attempt guarded rollback,
refusing to overwrite unexpected newer settings. An uncertain/failed rollback
is explicitly reported and needs administrator review. Never retry an uncertain
write blindly. The original CSV and newly created backup/files remain retained.

## 4. Check saved setup

Click **Check saved setup**. The wizard checks the current account's effective
macro/lookup against the shared app configuration, compares expected feeds with
a bounded24-hour sample, and runs a bounded15-minute/1,001-raw-record content
sample through the app's parsers. Warnings, early-finalized jobs, timeouts and
result limits are not treated as passes. Job cleanup is best effort; server
timeout and idle auto-cancellation provide additional bounds.

The content sample can split multi-record audit events. Missing context in that
sample is a prompt for investigation, not proof of a source defect. Open
**Review readiness** and the event dashboard for fuller analysis. The wizard
never creates verification receipts or accepts controls. A setup check under an
administrator does not establish another analyst's permissions.

## Restore and upgrade

Expand **Restore a previous wizard configuration**, enter the shown backup ID
and explicitly confirm. Restore verifies the saved scope/inventory/configured
flag have not changed since that operation, then rebinds the old CSV and scope.
It does not delete any records or inventory files. Partial failures are clearly
reported. Back up `local/`, operational lookup files and metadata before upgrades.

If a user-owned macro shadows app scope, reconcile that override with your
administrator; the wizard will not delete it. Existing custom scope is loaded
but is not automatically rewritten until you approve a generated replacement.
If the page fails to load after an upgrade, reload the browser and verify the
installed app/static assets and your site's cache/deployment procedure.

This first wizard targets standalone Splunk Enterprise. Splunk Cloud, search-head
clusters, deployment-server automation, all non-admin role combinations and
full-scale inventories require separate testing. Source collection and USB
physical-user attribution limitations remain unchanged.
