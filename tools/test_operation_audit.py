#!/usr/bin/env python3
"""Offline contract checks only; not live event acceptance."""
import os
import errno
import subprocess
import unittest
from unittest.mock import Mock, patch
import operation_audit as oa


class RecorderTests(unittest.TestCase):
    def exercise(self, code=0, effect=None, launch_error=None, action='Read/access', observer=None):
        records = []
        process = Mock(pid=123, returncode=code)
        process.communicate.side_effect = effect or [(b'private-output', b'private-error')]
        user = Mock(pw_gid=42, pw_name='test-user')
        ctx = {'actor': 'initiator', 'login_uid': 41, 'terminal': '/dev/pts/1',
               'source_ip': '192.0.2.3', 'boot_id': 'test', 'session': '8', 'context_basis': 'fixture'}
        with patch.object(oa, 'context', return_value=ctx), patch.object(oa, 'append', side_effect=records.append), \
             patch.object(oa.pwd, 'getpwuid', return_value=user), patch.object(oa.os, 'getgrouplist', return_value=[42]), \
             patch.object(oa.subprocess, 'Popen', return_value=process, side_effect=launch_error), patch.object(oa.os, 'killpg'), \
             patch.object(oa, 'load_profile', return_value={'command_timeout_seconds': 15, 'source': 'fixture', 'sha256': 'fixture'}):
            # append receives optional log argument as well.
            with patch.object(oa, 'append', side_effect=lambda record, log: records.append(record)):
                result = oa.execute(action, ['/usr/bin/head', '-c', '1', '/test'], '/test', 42,
                                    lambda rc: {'observed_rc': rc}, result_observer=observer)
        return result, records

    def test_success_from_command(self):
        result, records = self.exercise(0)
        self.assertEqual(result['event']['outcome'], 'success')
        self.assertNotIn('event', records[0])
        self.assertEqual(result['object']['name'], '/test')
        self.assertNotIn('private-output', str(records))
        self.assertNotIn('private-error', str(records))
        self.assertEqual(result['event']['initiator'], 'initiator')
        self.assertEqual(result['event']['completer'], 'test-user')

    def test_nonzero_is_failure(self):
        result, _ = self.exercise(13)
        self.assertEqual(result['event']['outcome'], 'failure')
        self.assertEqual(result['event']['code'], '13')

    def test_signal_not_denial(self):
        result, _ = self.exercise(-9)
        self.assertEqual(result['event']['outcome'], 'unknown')

    def test_timeout_not_denial(self):
        result, _ = self.exercise(-9, [subprocess.TimeoutExpired('cmd', 20), (b'', b'')])
        self.assertEqual(result['event']['outcome'], 'unknown')
        self.assertEqual(result['event']['reason'], 'timeout')

    def test_exec_permission_denial_is_failed_start(self):
        result, _ = self.exercise(launch_error=PermissionError(errno.EACCES, 'denied'), action='Start application')
        self.assertEqual(result['event']['outcome'], 'failure')
        self.assertEqual(result['event']['code'], '13')
        self.assertIsNone(result['process']['pid'])

    def test_launch_resource_error_is_unknown(self):
        result, _ = self.exercise(launch_error=OSError(errno.ENOMEM, 'resource error'), action='Start application')
        self.assertEqual(result['event']['outcome'], 'unknown')

    def test_profile_consumed(self):
        result, _ = self.exercise()
        self.assertEqual(result['operation_audit']['effective_timeout_seconds'], 15)

    def test_observed_completion_identity(self):
        result, _ = self.exercise(observer=lambda *args: {'completed_uid': 0, 'identity_basis': 'observed result'})
        self.assertEqual(result['user']['effective']['id'], '0')
        self.assertEqual(result['operation_audit']['invocation_uid'], 42)

    def test_failed_command_cannot_claim_root(self):
        result, _ = self.exercise(1, observer=lambda *args: {'completed_uid': 0, 'identity_basis': 'requested only'})
        self.assertEqual(result['user']['effective']['id'], '42')

    def test_identity_without_basis_rejected(self):
        with self.assertRaises(ValueError):
            self.exercise(observer=lambda *args: {'completed_uid': 0})

    def test_log_failure_prevents_command(self):
        with patch.object(oa, 'context', return_value={'actor': 'a'}), \
             patch.object(oa, 'append', side_effect=PermissionError), \
             patch.object(oa.subprocess, 'Popen') as command:
            with self.assertRaises(PermissionError):
                oa.execute('Read/access', ['/usr/bin/true'], '/test', os.getuid())
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
