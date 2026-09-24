"""Crash-order and state-integrity checks for durable witnesses."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, encode, manifest
from durable_witness import (
    DurableCommitUncertain,
    DurableStateError,
    DurableWitness,
    InjectedCrash,
)
from fixtures import grant
from model import Authority
from witness_delta import _scope_id


def base_authority() -> Authority:
    authority = Authority('n1')
    authority.append('grant', grant('n1'), 0)
    authority.append('publish', manifest('n1', 'leaf', []), 0)
    return authority


def checkpoint(authority: Authority, issued: int) -> dict:
    return {
        'op': 'checkpoint', 'ns': authority.ns,
        'count': len(authority.log),
        'tip': commitment(authority.log[-1]) if authority.log else '',
        'issued': issued,
    }




def rewrite_snapshot(path: Path, mutate) -> None:
    envelope = json.loads(path.read_text())
    mutate(envelope['state'])
    envelope['commitment'] = commitment(envelope['state'])
    path.write_bytes(encode(envelope) + b'\n')


class DurableWitnessTests(unittest.TestCase):
    def test_rejects_cross_namespace_scope_even_with_matching_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            DurableWitness(path, 'n1', 'w1')
            keys = ['n2/object']
            scope = _scope_id('n1', tuple(keys))
            rewrite_snapshot(path, lambda state: state['scopes'].append(
                {'scope': scope, 'keys': keys}))
            with self.assertRaises(DurableStateError):
                DurableWitness(path, 'n1', 'w1')

    def test_rejects_signed_slot_beyond_persisted_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            self.assertIsNotNone(
                witness.certify(checkpoint(authority, 1), authority.log))
            def corrupt(state):
                state['signed_slots'][0]['slot'][1] = len(state['log']) + 1
            rewrite_snapshot(path, corrupt)
            with self.assertRaises(DurableStateError):
                DurableWitness(path, 'n1', 'w1')

    def test_rejects_signed_slot_table_over_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            self.assertIsNotNone(
                witness.certify(checkpoint(authority, 1), authority.log))
            with patch('durable_witness.MAX_SIGNED_SLOTS', 0):
                with self.assertRaises(DurableStateError):
                    DurableWitness(path, 'n1', 'w1')

    def test_reopen_retains_signed_branch_and_rejects_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            base = base_authority()
            left = deepcopy(base); right = deepcopy(base)
            left.append('revoke', {'target': 'n1/leaf'}, 2)
            right.append('publish', manifest('n1', 'leaf', [], blob='fork'), 2)
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(2)
            self.assertIsNotNone(witness.certify(checkpoint(left, 2), left.log))
            reopened = DurableWitness(path, 'n1', 'w1')
            self.assertEqual(reopened.summary().count, len(left.log))
            self.assertIsNone(reopened.certify(checkpoint(right, 2), right.log))

    def test_crash_after_temp_fsync_recovers_old_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            base = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            self.assertIsNotNone(witness.certify(checkpoint(base, 1), base.log))
            extended = deepcopy(base)
            extended.append('revoke', {'target': 'n1/leaf'}, 2)
            witness.advance(2)
            with self.assertRaises(InjectedCrash):
                witness.certify(
                    checkpoint(extended, 2), extended.log,
                    crash='after-temp-fsync')
            with self.assertRaises(DurableStateError):
                witness.summary()
            reopened = DurableWitness(path, 'n1', 'w1')
            self.assertEqual(reopened.summary().count, len(base.log))
            self.assertFalse(list(path.parent.glob(f'.{path.name}.tmp-*')))
            reopened.advance(2)
            self.assertIsNotNone(
                reopened.certify(checkpoint(extended, 2), extended.log))

    def test_crash_after_replace_recovers_new_state_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            body = checkpoint(authority, 1)
            with self.assertRaises(InjectedCrash):
                witness.certify(body, authority.log, crash='after-replace')
            with self.assertRaises(DurableStateError):
                witness.certify(body, authority.log)
            reopened = DurableWitness(path, 'n1', 'w1')
            self.assertEqual(reopened.summary().count, len(authority.log))
            self.assertIsNotNone(reopened.certify(body, authority.log))

    def test_clock_is_durable_and_cannot_move_backwards_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            witness = DurableWitness(path, 'n1', 'w2')
            witness.advance(5)
            reopened = DurableWitness(path, 'n1', 'w2')
            self.assertEqual(reopened.summary().clock, 5)
            with self.assertRaises(ValueError):
                reopened.advance(4)

    def test_corrupt_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            DurableWitness(path, 'n1', 'w3')
            path.write_text('{"state":{},"commitment":"wrong"}\n')
            with self.assertRaises(DurableStateError):
                DurableWitness(path, 'n1', 'w3')

    def test_identity_or_fault_mode_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            DurableWitness(path, 'n1', 'w1', faulty=False)
            with self.assertRaises(DurableStateError):
                DurableWitness(path, 'n1', 'w1', faulty=True)
            with self.assertRaises(DurableStateError):
                DurableWitness(path, 'n1', 'w2', faulty=False)

    def test_before_commit_crash_requires_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            body = checkpoint(authority, 1)
            with self.assertRaises(InjectedCrash):
                witness.certify(body, authority.log, crash='before-commit')
            with self.assertRaises(DurableStateError):
                witness.certify(body, authority.log)
            reopened = DurableWitness(path, 'n1', 'w1')
            self.assertIsNotNone(reopened.certify(body, authority.log))

    def test_temp_fsync_failure_rolls_back_and_remains_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            body = checkpoint(authority, 1)
            with patch('durable_witness.os.fsync', side_effect=OSError('disk')):
                with self.assertRaises(DurableStateError):
                    witness.certify(body, authority.log)
            self.assertEqual(witness.summary().count, 0)
            self.assertIsNotNone(witness.certify(body, authority.log))

    def test_replace_failure_rolls_back_and_remains_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            body = checkpoint(authority, 1)
            with patch('durable_witness.os.replace', side_effect=OSError('rename')):
                with self.assertRaises(DurableStateError):
                    witness.certify(body, authority.log)
            self.assertEqual(witness.summary().count, 0)
            self.assertIsNotNone(witness.certify(body, authority.log))

    def test_directory_fsync_failure_poisoned_until_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            authority = base_authority()
            witness = DurableWitness(path, 'n1', 'w1')
            witness.advance(1)
            body = checkpoint(authority, 1)
            with patch('durable_witness.os.fsync', side_effect=[None, OSError('dir')]):
                with self.assertRaises(DurableCommitUncertain):
                    witness.certify(body, authority.log)
            with self.assertRaises(DurableStateError):
                witness.summary()
            with self.assertRaises(DurableStateError):
                witness.certify(body, authority.log)
            reopened = DurableWitness(path, 'n1', 'w1')
            self.assertEqual(reopened.summary().count, len(authority.log))
            self.assertIsNotNone(reopened.certify(body, authority.log))


if __name__ == '__main__':
    unittest.main(verbosity=2)
