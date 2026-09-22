"""Export gate: all derived session evidence must be preserved.

This proves reference closure only, not source authenticity, boot continuity,
semantic acceptance, or that an action itself used a network connection.
"""
import hashlib
import re
from collections import defaultdict


def values(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def digest(refs):
    return hashlib.sha256("|".join(sorted(set(refs))).encode()).hexdigest()


def checked_refs(value, label):
    refs = values(value)
    if not refs or any(not isinstance(r, str) or not re.fullmatch(r"[0-9a-f]{64}", r) for r in refs):
        raise ValueError("Missing or malformed " + label)
    if len(refs) != len(set(refs)):
        raise ValueError("Duplicate " + label)
    return set(refs)


def verify_session_provenance(raw, events):
    evidence_fields = ("session_remote_access", "session_source_ip", "session_context_basis",
                       "session_context_fingerprints", "session_context_record_fingerprints")
    derived = [event for event in events if any(event.get(name) for name in evidence_fields)]
    if not derived:
        return {"derived_category_rows_checked": 0, "status": "NO_DERIVED_CONTEXT",
                "semantic_acceptance": False, "boot_continuity_verified": False}
    groups = defaultdict(set)
    for record in raw:
        key, ref = record.get("event_key"), record.get("record_fingerprint")
        if not isinstance(key, str) or not key:
            raise ValueError("Source record missing event key")
        groups[key].update(checked_refs(ref, "source record fingerprint"))
    by_fingerprint = defaultdict(list)
    for key, refs in groups.items():
        by_fingerprint[digest(refs)].append((key, refs))
    checked = 0
    for event in derived:
        if any(not event.get(name) for name in evidence_fields):
            raise ValueError("Incomplete session provenance fields")
        host = event.get("event_host")
        if not isinstance(host, str) or not host:
            raise ValueError("Ambiguous event host")
        key = event.get("event_key")
        prefix = host + "|audit|"
        if not isinstance(key, str) or not key.startswith(prefix):
            raise ValueError("Target is not an audit event for this host")
        target_refs = checked_refs(event.get("record_fingerprint"), "target record references")
        if groups.get(key) != target_refs or event.get("event_fingerprint") != digest(target_refs):
            raise ValueError("Target evidence missing or fingerprint mismatch")
        support = checked_refs(event.get("session_context_fingerprints"), "support event references")
        if len(support) != 3:
            raise ValueError("Expected three distinct supporting events")
        expected = set()
        for fingerprint in support:
            matches = by_fingerprint.get(fingerprint, [])
            if len(matches) != 1:
                raise ValueError("Supporting event missing or ambiguous")
            support_key, refs = matches[0]
            if not support_key.startswith(prefix):
                raise ValueError("Supporting event belongs to another host")
            expected.update(refs)
        declared = checked_refs(event.get("session_context_record_fingerprints"), "support record references")
        if declared != expected:
            raise ValueError("Supporting record set does not match complete supporting events")
        checked += 1
    return {"derived_category_rows_checked": checked, "status": "REFERENCE_CLOSURE_PASS",
            "semantic_acceptance": False, "boot_continuity_verified": False}
