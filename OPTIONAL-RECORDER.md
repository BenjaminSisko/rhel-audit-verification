---
type: documentation
status: optional-reference-integration
last_verified: 2026-09-22
---

# Optional application-operation recorder

`tools/operation_audit.py` is a root-run Python library for explicitly recording
an approved command's observed result. It is not a daemon, automatic system-wide
collector, CLI command runner, or replacement for native auditd. Running the
file directly installs nothing and performs no operation.

Use it only when an application does not provide an adequate native audit
record and the system owner approves application-specific instrumentation.
It does not intercept commands that bypass the caller. An arbitrary action
label supplied by a caller is not validated by the library and is not proof
that the command implements the catalog event.

## Prerequisites and security boundary

- Existing root administration authority; no new sudoers grant or setuid bit.
- Python3.9 or later. Reference runtime: RHEL10.2. Do not assume RHEL8's older
  system interpreter supports the subprocess identity API.
- A real SSH terminal with kernel login UID/session ID and preserved
  SSH_CONNECTION. Unset login identity or missing terminal/context fails closed.
  This profile does not support cron, local console or system services.
- Existing approved UF route/index/TLS, protected audit storage, and sufficient
  free space. Source values are observations, not cryptographic identity proof.
- A reviewed fixed caller: absolute executable, restricted parameters, intended
  execution UID, truthful event action, exact target and operation-specific
  before/after checks. Do not expose arbitrary caller code through privilege.

The library does not put command arguments or raw stdout/stderr into its event
record. It does preserve target paths and metadata returned by your callbacks;
review those fields for secrets and personal information before forwarding.
Output is buffered in memory, so use only short, bounded-output commands.
Timeout kills the child process group and records unknown, not a fabricated
denial. Commands whose process exits before asynchronous work finishes need a
separate completion observer; do not call request acceptance completion.

## Install on an approved source — not the Splunk search head

Back up existing source configuration first. The following initial-install
example refuses existing helper/log directories; use a separately reviewed
upgrade/rotation process when they already exist. Replace the UF group with
the actual installed forwarder group. Do not run this example blindly.

```sh
set -eu
uf_log_group=splunkfwd
getent group "$uf_log_group"
sudo test ! -e /opt/aulx-operation-audit
sudo test ! -e /var/log/aulx-operations
sudo install -d -o root -g root -m 0755 /opt/aulx-operation-audit
sudo install -o root -g root -m 0644 tools/operation_audit.py /opt/aulx-operation-audit/operation_audit.py
sudo install -d -o root -g "$uf_log_group" -m 0750 /var/log/aulx-operations
sudo install -o root -g "$uf_log_group" -m 0640 /dev/null /var/log/aulx-operations/events.jsonl
sudo install -o root -g root -m 0600 /dev/null /var/log/aulx-operations/intents.jsonl
```

No profile file is required: default command timeout is20 seconds. An optional
root-owned, non-group/other-writable profile.json next to the module may contain
only `{"command_timeout_seconds": 20}`, with an integer from1 through20.
Keep SELinux enforcing. Validate actual UF readability and diagnose labels or
permissions under approved policy; do not disable security to pass a test.

## Integrate a reviewed caller

The callable contract is:

```python
record = operation_audit.execute(
    action=reviewed_catalog_action,
    command=reviewed_absolute_command_and_arguments,
    target=actual_target_resource,
    uid=approved_execution_uid,
    verify=operation_specific_before_after_observer,
    metadata=nonsecret_reference_metadata,
    timeout=20,
)
```

This is API documentation, not a complete executable script. Supply a
root-controlled application-specific caller and review its meaning first.
`verify(None)` runs before the operation and `verify(return_code)` afterward.
Observers must report measured state, not the desired outcome. For example,
a copy operation should compare source/destination bytes and direction, not
only report that cp launched. Never emit arbitrary expected fixtures into the
operational index to make tiles pass.

Exit0 records command success; positive exit records command failure. Signal,
timeout and most launch infrastructure errors remain unknown. A successful
command alone is not semantic acceptance. Optional result_observer callbacks
can examine output and provide a completion identity only with observed basis;
review them carefully. The default process identity is the invocation identity.

The private intents.jsonl is written before command execution. A failed intent
write prevents execution. A failed final write can happen after the operation;
report that gap and never rerun the command automatically. Keep intents private;
do not forward them as completed events. Root can alter local files, so protect
and retain original evidence separately under your site's policy.

## Collect and parse completion records

Merge the following disabled example into the approved source configuration;
do not overwrite existing inputs or collect the same file twice:

```ini
[monitor:///var/log/aulx-operations/events.jsonl]
disabled = 1
index = replace_with_approved_index
sourcetype = linux_app_audit
```

Enable only after review. Include the exact source/host/sourcetype in the app's
approved aulx_source scope. On the actual parsing tier (usually indexer or heavy
forwarder, not a separate search head), apply and verify this source-specific
props contract through normal deployment:

```ini
[source::/var/log/aulx-operations/events.jsonl]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%:z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 16384
```

Keep each JSON record below the parser bound; unbounded metadata is unsupported.
Do not blindly copy source-based CRC salt onto rotating logs: renaming may
cause re-ingestion. Design and test rotation/outage recovery for both JSONL and
native audit logs while preserving checkpoints. No production rotation or
retention policy is provided by this library. Fresh-record receipt alone is
not proof of continuity. The reference native-audit rotation gap was repaired
and exact transition records recovered; this does not establish production
rotation or outage resilience for every source.

## Verify and remove

Run offline contract tests without root:

```sh
python3 tools/test_operation_audit.py
```

Then perform an approved benign operation with a unique reference, preserve
its actual source JSON and independently observed result, and compare exact
raw content/hash, timestamp, event.id, actor/initiator, completing identity,
target, application and outcome in Splunk. Test success and failure separately.
Review missing fields and original source records before creating any receipt.
No receipt is created by this library or its tests.

Rollback: stop invoking the caller and disable only its dedicated input under
change control. Preserve both ledgers and indexed evidence. Do not delete logs,
reset fishbucket/checkpoints or undo an already completed business operation.
