#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'package/TA_au2_linux/bin'))
from aulx_provenance import digest, verify_usb_session_provenance

class USBProofTests(unittest.TestCase):
    def setUp(self):
        self.raw=[{'event_key':'example.invalid|audit|'+str(i),'record_fingerprint':str(i)*64} for i in range(1,4)]
        self.raw.append({'event_key':'usb-target','record_fingerprint':'4'*64})
        self.context={'start':10,'end':20,'event_proofs':','.join(digest([str(i)*64]) for i in range(1,4)),
                      'record_proofs':','.join(str(i)*64 for i in range(1,4))}
        self.event={'event_key':'usb-target','event_host':'example.invalid','native_kind':'kernel-usb',
                    'event_time':15,'record_fingerprint':'4'*64,'event_fingerprint':digest(['4'*64]),
                    'usb_session_count':1,'usb_session_evidence':json.dumps(self.context)}
    def test_valid(self):
        r=verify_usb_session_provenance(self.raw,[self.event]);self.assertEqual(r['contextual_sessions_checked'],1)
        self.assertFalse(r['physical_actor_verified'])
    def test_missing_anchor(self):
        with self.assertRaises(ValueError):verify_usb_session_provenance(self.raw[1:],[self.event])
    def test_wrong_host(self):
        self.event['event_host']='other.invalid'
        with self.assertRaises(ValueError):verify_usb_session_provenance(self.raw,[self.event])
    def test_wrong_time(self):
        self.event['event_time']=20
        with self.assertRaises(ValueError):verify_usb_session_provenance(self.raw,[self.event])
    def test_target_missing(self):
        with self.assertRaises(ValueError):verify_usb_session_provenance(self.raw[:-1],[self.event])
    def test_count_mismatch(self):
        self.event['usb_session_count']=2
        with self.assertRaises(ValueError):verify_usb_session_provenance(self.raw,[self.event])
    def test_no_context(self):
        self.assertEqual(verify_usb_session_provenance(self.raw,[])['contextual_sessions_checked'],0)

if __name__=='__main__':unittest.main()
