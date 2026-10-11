"""Benign local suffix, retry and accepted-state preservation regressions."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, manifest, verify
from durable_witness import (_validate_case_state, snapshot_wire, witness_payload)
from durable_witness_network import DurableWitnessProcessNetwork
from fixtures import grant
from model import Authority
from witness_delta import Witness
from witness_network import WitnessTCPNetwork
from witness_sync import BATCH, HistorySession, agrees, prefix


def authority(publications=1):
    value = Authority('n1')
    value.append('grant', grant('n1'), 0)
    for index in range(publications):
        value.append('publish', manifest('n1', f'item-{index}', []), 0)
    return value


def checkpoint(value, now=1):
    return {'op': 'checkpoint', **prefix(value.log, value.ns), 'issued': now}


class WitnessSyncTests(unittest.TestCase):
    def test_prefix_agreement_requires_namespace_count_and_tip(self):
        value = authority()
        valid = {'ok': True, **prefix(value.log, value.ns)}
        self.assertTrue(agrees(valid, value.ns, value.log))
        for field, wrong in (('ns', 'n2'), ('count', True),
                             ('count', len(value.log) + 1), ('tip', 'stale')):
            with self.subTest(field=field, wrong=wrong):
                reply = {**valid, field: wrong}
                self.assertFalse(agrees(reply, value.ns, value.log))

    def test_batch_boundary_and_warm_retry_transfer_only_suffix(self):
        async def scenario():
            value = authority(BATCH + 1)
            async with WitnessTCPNetwork() as network:
                network.configure('batch', value.ns)
                network.advance('batch', 1)
                first = await network.signatures('batch', checkpoint(value), value.log)
                count = network.counters.history_events
                retry = await network.signatures('batch', checkpoint(value), value.log)
                self.assertEqual(network.counters.history_events, count)
                value.append('publish', manifest('n1', 'added', []), 2)
                network.advance('batch', 2)
                later = await network.signatures('batch', checkpoint(value, 2), value.log)
                self.assertEqual(network.counters.history_events - count, 4)
                self.assertEqual(count, 4 * (BATCH + 2))
                self.assertEqual(first, retry)
                for item in later:
                    self.assertTrue(verify('witness:n1:' + item['id'],
                                           checkpoint(value, 2), item['signature']))
                self.assertEqual(len(later), 4)
                counters = network.counters
                self.assertEqual(counters.wire_bytes, counters.prefix_wire_bytes
                                 + counters.sync_wire_bytes + counters.reset_wire_bytes
                                 + counters.certify_wire_bytes)
        asyncio.run(scenario())

    def test_reset_discards_staging_not_accepted_state(self):
        value = authority()
        owner = Witness('n1', 'w1', clock=1)
        session = HistorySession(owner)
        session.sync('n1', 0, '', value.log)
        self.assertEqual(owner.log, [])
        self.assertIsNotNone(session.certify(checkpoint(value)))
        before = witness_payload(owner)
        value.append('publish', manifest('n1', 'added', []), 2)
        session.sync('n1', 2, commitment(owner.log[-1]), value.log[2:])
        self.assertEqual(session.frontier()['count'], 3)
        self.assertEqual(session.reset('n1')['count'], 2)
        self.assertEqual(witness_payload(owner), before)

    def test_wrong_base_gap_namespace_and_bad_final_receipt_are_atomic(self):
        value = authority()
        session = HistorySession(Witness('n1', 'w1'))
        before = deepcopy(session.candidate)
        for ns, start, tip, events in (
                ('n2', 0, '', value.log), ('n1', 1, '', value.log),
                ('n1', 0, 'wrong', value.log), ('n1', 0, '', value.log[1:])):
            with self.subTest(ns=ns, start=start, tip=tip):
                with self.assertRaises(ValueError):
                    session.sync(ns, start, tip, events)
                self.assertEqual(session.candidate, before)
        damaged = deepcopy(value.log)
        damaged[-1]['signature'] = 'invalid'
        with self.assertRaises(ValueError):
            session.sync('n1', 0, '', damaged)
        self.assertEqual(session.candidate, before)

    def test_incomplete_body_cannot_commit_staged_history(self):
        value = authority()
        owner = Witness('n1', 'w1', clock=1)
        session = HistorySession(owner)
        session.sync('n1', 0, '', value.log)
        bad = checkpoint(value)
        bad['count'] -= 1
        self.assertIsNone(session.certify(bad))
        self.assertEqual(owner.log, [])
        self.assertEqual(owner.signed_slots, {})
        self.assertIsNotNone(session.certify(checkpoint(value)))

    def test_lost_sync_reply_retry_discovers_staged_prefix(self):
        async def scenario():
            value = authority()
            async with WitnessTCPNetwork() as network:
                network.configure('lost', value.ns)
                network.advance('lost', 1)
                # Deliver suffix, then discard the response as a lost reply.
                await network.exchange('w1', {
                    'op': 'sync', 'case': 'lost', 'ns': value.ns,
                    'start': 0, 'previous': '', 'events': value.log})
                before = network.counters.history_events
                reply = await network.rpc('w1', 'lost', checkpoint(value), value.log)
                self.assertIn('signature', reply)
                self.assertEqual(network.counters.history_events, before)
        asyncio.run(scenario())

    def test_new_session_from_snapshot_preserves_prefix_and_slots(self):
        value = authority()
        owner = Witness('n1', 'w1', clock=1)
        self.assertIsNotNone(owner.certify(checkpoint(value), value.log))
        envelope = json.loads(snapshot_wire(witness_payload(owner)))
        self.assertEqual(commitment(envelope['state']), envelope['commitment'])
        recovered = _validate_case_state(envelope['state'], 'n1', 'w1', False)
        session = HistorySession(recovered)
        self.assertEqual(session.frontier(), {'ok': True, **prefix(value.log, 'n1')})
        slots = deepcopy(recovered.signed_slots)
        self.assertIsNotNone(session.certify(checkpoint(value)))
        self.assertEqual(recovered.signed_slots, slots)
        self.assertEqual(snapshot_wire(witness_payload(recovered)),
                         snapshot_wire(witness_payload(owner)))

    def test_stale_staging_recovers_via_reset_to_empty_accepted_prefix(self):
        async def scenario():
            value = authority()
            async with WitnessTCPNetwork() as network:
                network.configure('reset', value.ns)
                network.advance('reset', 1)
                session = network.sessions['w1']['reset']
                session.sync('n1', 0, '', value.log)
                # A request for an earlier *unaccepted* frontier discards the
                # extra staging. This is not an accepted-branch rollback.
                shorter = deepcopy(value)
                shorter.log = shorter.log[:1]
                reply = await network.rpc('w1', 'reset', checkpoint(shorter), shorter.log)
                self.assertIn('signature', reply)
                self.assertGreater(network.counters.reset_wire_bytes, 0)
                self.assertEqual(network.states['w1']['reset'].log, shorter.log)
        asyncio.run(scenario())

    def test_reset_never_rolls_back_an_accepted_frontier(self):
        async def scenario():
            value = authority()
            async with WitnessTCPNetwork() as network:
                network.configure('retained', value.ns)
                network.advance('retained', 1)
                await network.signatures('retained', checkpoint(value), value.log)
                before = witness_payload(network.states['w1']['retained'])
                shorter = deepcopy(value)
                shorter.log = shorter.log[:1]
                reply = await network.rpc('w1', 'retained', checkpoint(shorter), shorter.log)
                self.assertTrue(reply['reject'])
                self.assertEqual(witness_payload(network.states['w1']['retained']), before)
        asyncio.run(scenario())

    def test_full_reference_and_incremental_certify_identical_bodies(self):
        async def scenario():
            value = authority(3)
            results = []
            for mode in (False, True):
                async with WitnessTCPNetwork(incremental=mode) as network:
                    network.configure('parity', value.ns)
                    network.advance('parity', 1)
                    signatures = await network.signatures('parity', checkpoint(value), value.log)
                    results.append((signatures,
                                    [witness_payload(network.states[wid]['parity'])
                                     for wid in network.states]))
            self.assertEqual(results[0], results[1])
        asyncio.run(scenario())

    @unittest.skipIf(os.name == 'nt', 'POSIX directory-fsync recovery requires a supported host')
    def test_process_restart_uses_retained_prefix_without_retransmission(self):
        async def scenario(root):
            value = authority()
            async with DurableWitnessProcessNetwork(root) as network:
                await network.configure('resume', value.ns)
                await network.advance('resume', 1)
                first = await network.signatures('resume', checkpoint(value), value.log)
                await network.restart_all()
                before = network.counters.history_events
                retry = await network.signatures('resume', checkpoint(value), value.log)
                self.assertEqual(network.counters.history_events, before)
                self.assertEqual(first, retry)
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(Path(directory)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
