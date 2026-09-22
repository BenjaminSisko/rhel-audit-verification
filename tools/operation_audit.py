#!/usr/bin/env python3
"""Optional command-completion recorder. Root-run library, NOT a privileged API.

Only commands explicitly called through this library are covered. Native audit
remains necessary. No arbitrary application's outcome is inferred from execve.
No command arguments, stdout, stderr, passwords, or tokens enter the event log.
"""
import datetime
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time
import uuid

LOG = Path('/var/log/aulx-operations/events.jsonl')
PROFILE = Path(__file__).with_name('profile.json')


def load_profile(path=PROFILE):
    """Optional root-controlled timeout bound, read for each operation."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {'command_timeout_seconds': 20, 'source': 'built-in default', 'sha256': None}
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
            raise PermissionError('Profile must be a small root-owned nonwritable regular file')
        payload = stream.read(4097)
    data = json.loads(payload)
    if set(data) != {'command_timeout_seconds'} or type(data['command_timeout_seconds']) is not int:
        raise ValueError('Invalid timeout profile schema')
    if not 1 <= data['command_timeout_seconds'] <= 20:
        raise ValueError('Timeout profile cannot exceed approved 20-second bound')
    return dict(data, source=str(path), sha256=digest(payload))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')


def append(record, log=LOG):
    # Fail closed on links, nonregular or non-root-controlled audit storage.
    parent = log.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise PermissionError('Audit directory must be root-owned and not writable by group/other')
    fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Audit file must be root-owned and not writable by group/other')
        data = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
        fcntl.flock(fd, fcntl.LOCK_EX)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def context():
    if os.geteuid() != 0:
        raise PermissionError('Recorder requires existing administrator authority; no setuid/sudo grant')
    loginuid = int(Path('/proc/self/loginuid').read_text().strip())
    if loginuid in (-1, 4294967295):
        raise RuntimeError('No source login identity; do not manufacture an initiator')
    terminal = os.ttyname(0)  # A real controlling SSH terminal is required in this profile.
    peer = os.environ.get('SSH_CONNECTION', '').split()
    if len(peer) != 4:
        raise RuntimeError('Missing SSH session context; no remote/local default')
    ipaddress.ip_address(peer[0])
    ipaddress.ip_address(peer[2])
    return {'actor': pwd.getpwuid(loginuid).pw_name, 'login_uid': loginuid,
            'terminal': terminal, 'source_ip': peer[0],
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'session': Path('/proc/self/sessionid').read_text().strip(),
            'context_basis': 'kernel loginuid/sessionid and SSH_CONNECTION preserved from operator shell'}


def execute(action, command, target, uid, verify=None, metadata=None, timeout=20, log=LOG, result_observer=None):
    """Observe a real child command; return record without assigning a test verdict.

    verify returns source-observed postcondition metadata; it must not supply a
    desired result. A zero command return without verified state is only a
    command result. Timeout/infrastructure launch errors remain unknown.
    Explicit exec permission denial proves a failed Start application attempt.
    Caller owns application-specific semantics and reviewed command allowlist.
    """
    ctx = context()
    profile = load_profile()
    effective_timeout = min(timeout, profile['command_timeout_seconds'])
    if not command or not os.path.isabs(command[0]):
        raise ValueError('An absolute executable is required')
    user = pwd.getpwuid(uid)
    event_id = str(uuid.uuid4())
    begin = timestamp()
    intent = {'timestamp': begin, 'operation_intent': event_id, 'action_requested': action,
              'actor': ctx['actor'], 'target': target, 'executable': command[0]}
    append(intent, log.with_name('intents.jsonl'))  # Private intent ledger, not forwarded as completion.
    started = time.monotonic()
    process_id = None
    result = 'unknown'
    code = None
    error_kind = None
    observed = {}
    stdout = b''
    stderr = b''
    before = verify(None) if verify is not None else {}
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, user=uid, group=user.pw_gid,
                                extra_groups=os.getgrouplist(user.pw_name, user.pw_gid),
                                env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C'}, start_new_session=True)
        process_id = proc.pid
        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
            code = proc.returncode
            result = 'success' if code == 0 else ('failure' if code > 0 else 'unknown')
            if code < 0:
                error_kind = 'signal'
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
            error_kind = 'timeout'
        if verify is not None:
            observed = verify(code)
    except OSError as error:
        error_kind = type(error).__name__
        code = error.errno
        result = 'unknown'
        if process_id is None and action == 'Start application' and error.errno in (errno.EACCES, errno.EPERM):
            result = 'failure'
        if verify is not None:
            observed = verify(code)
    completion = result_observer(code, stdout, stderr) if result_observer is not None else {}
    # Only a reviewed application-specific observer can report an execution
    # identity transition. Retain original invocation identity and exact basis.
    completing_uid = uid
    if result == 'success' and 'completed_uid' in completion:
        if type(completion['completed_uid']) is not int or not completion.get('identity_basis'):
            raise ValueError('Observed completion identity requires integer UID and evidence basis')
        completing_uid = completion['completed_uid']
    completing_user = pwd.getpwuid(completing_uid).pw_name
    record = {
        'timestamp': timestamp(),
        'event': {'id': event_id, 'action': action, 'outcome': result,
                  'initiator': ctx['actor'], 'completer': completing_user,
                  'remote': True, 'code': str(code) if code is not None else error_kind,
                  'reason': error_kind or 'command exit status '+str(code)},
        'user': {'name': ctx['actor'], 'id': ctx['login_uid'], 'effective': {'id': str(completing_uid)}},
        'service': {'name': command[0]}, 'object': {'name': target},
        'terminal': {'id': ctx['terminal']}, 'source': {'ip': ctx['source_ip']},
        'process': {'pid': process_id, 'user': user.pw_name},
        'operation_audit': {'schema': 1, 'source_kind': 'command-completion-wrapper',
                            'started': begin, 'duration_seconds': round(time.monotonic()-started, 6),
                            'boot_id': ctx['boot_id'], 'session_id': ctx['session'],
                            'context_basis': ctx['context_basis'],
                            'profile': profile, 'effective_timeout_seconds': effective_timeout,
                            'invocation_uid': uid, 'completion_observation': completion,
                            'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr),
                            'helper_sha256': digest(Path(__file__).read_bytes()),
                            'precondition': before, 'postcondition': observed, 'metadata': metadata or {},
                            'coverage': 'only this wrapped command; not arbitrary host/application coverage'}
    }
    append(record, log)
    return record
