"""Export gate: all derived session evidence must be preserved.

This proves reference closure only, not source authenticity, boot continuity,
semantic acceptance, or that an action itself used a network connection.
"""
import hashlib
import json
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


def verify_usb_session_provenance(raw, events):
    """Reference closure for contextual sessions, never physical attribution."""
    groups = defaultdict(set)
    for record in raw:
        key = record.get('event_key')
        if key:
            groups[key].update(checked_refs(record.get('record_fingerprint'), 'source fingerprint'))
    by_fingerprint = defaultdict(list)
    for key, refs in groups.items():
        by_fingerprint[digest(refs)].append((key, refs))
    checked = 0
    for event in events:
        evidence = values(event.get('usb_session_evidence'))
        if not evidence:
            if int(event.get('usb_session_count') or 0) != 0:
                raise ValueError('USB session count without evidence')
            continue
        if event.get('native_kind') != 'kernel-usb':
            raise ValueError('USB context on a non-USB event')
        if len(evidence) != int(event.get('usb_session_count', -1)):
            raise ValueError('USB session count mismatch')
        host = event.get('event_host')
        if not isinstance(host, str) or not host:
            raise ValueError('USB host missing or ambiguous')
        refs = checked_refs(event.get('record_fingerprint'), 'USB target references')
        if groups.get(event.get('event_key')) != refs or event.get('event_fingerprint') != digest(refs):
            raise ValueError('USB target evidence missing')
        for encoded in evidence:
            context = json.loads(encoded)
            if not float(context['start']) <= float(event['event_time']) < float(context['end']):
                raise ValueError('USB timestamp outside declared session interval')
            support = checked_refs(context['event_proofs'].split(','), 'USB session event references')
            if len(support) != 3:
                raise ValueError('Expected three USB session anchors')
            expected = set()
            for fingerprint in support:
                matches = by_fingerprint.get(fingerprint, [])
                if len(matches) != 1 or not matches[0][0].startswith(host+'|audit|'):
                    raise ValueError('USB session support missing, ambiguous or another host')
                expected.update(matches[0][1])
            if checked_refs(context['record_proofs'].split(','), 'USB session records') != expected:
                raise ValueError('USB session record closure mismatch')
            checked += 1
    return {'contextual_sessions_checked': checked, 'status': 'REFERENCE_CLOSURE_PASS',
            'physical_actor_verified': False, 'semantic_acceptance': False,
            'boot_continuity_verified': False}
