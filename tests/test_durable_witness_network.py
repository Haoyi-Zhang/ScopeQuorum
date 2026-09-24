"""Separate-process crash/recovery checks for durable witness endpoints."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from pathlib import Path
import tempfile
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, manifest
from durable_witness_network import DurableWitnessProcessNetwork
from fixtures import grant
from model import Authority
from witness_delta import QUORUM


def authority() -> Authority:
    value = Authority('n1')
    value.append('grant', grant('n1'), 0)
    value.append('publish', manifest('n1', 'leaf', []), 0)
    return value


def checkpoint(value: Authority, issued: int) -> dict:
    return {
        'op': 'checkpoint', 'ns': value.ns,
        'count': len(value.log),
        'tip': commitment(value.log[-1]), 'issued': issued,
    }


class DurableWitnessNetworkTests(unittest.TestCase):
    def test_four_distinct_processes_certify(self):
        async def scenario(root: Path):
            value = authority()
            async with DurableWitnessProcessNetwork(root) as network:
                await network.configure('valid', 'n1')
                await network.advance('valid', 1)
                signatures = await network.signatures(
                    'valid', checkpoint(value, 1), value.log)
                return signatures, dict(network.pids)
        with tempfile.TemporaryDirectory() as directory:
            signatures, pids = asyncio.run(scenario(Path(directory)))
        self.assertEqual(len(signatures), 4)
        self.assertEqual(len(set(pids.values())), 4)

    def test_crash_after_durable_replace_recovers_and_retries(self):
        async def scenario(root: Path):
            value = authority()
            async with DurableWitnessProcessNetwork(root) as network:
                await network.configure('recover', 'n1', faulty=('w0',))
                await network.advance('recover', 1)
                network.blocked = {'w0'}
                body = checkpoint(value, 1)
                first = await network.signatures(
                    'recover', body, value.log,
                    crash={'w1': 'after-replace'})
                recovered = await network.restart('w1')
                second = await network.signatures('recover', body, value.log)
                return first, second, recovered, network.counters
        with tempfile.TemporaryDirectory() as directory:
            first, second, recovered, counters = asyncio.run(
                scenario(Path(directory)))
        self.assertEqual(len(first), 2)
        self.assertTrue(recovered)
        self.assertEqual(len(second), QUORUM)
        self.assertEqual(counters.injected_crashes, 1)
        self.assertEqual(counters.restarts, 1)

    def test_full_committee_restart_preserves_fork_exclusion(self):
        async def scenario(root: Path):
            base = authority()
            left = deepcopy(base); right = deepcopy(base)
            left.append('revoke', {'target': 'n1/leaf'}, 2)
            right.append('publish', manifest('n1', 'leaf', [], blob='fork'), 2)
            async with DurableWitnessProcessNetwork(root) as network:
                await network.configure('fork', 'n1', faulty=('w0',))
                await network.advance('fork', 2)
                network.blocked = {'w3'}
                first = await network.signatures(
                    'fork', checkpoint(left, 2), left.log)
                network.blocked = set()
                await network.restart_all()
                await network.advance('fork', 3)
                network.blocked = {'w1'}
                second = await network.signatures(
                    'fork', checkpoint(right, 3), right.log)
                return first, second
        with tempfile.TemporaryDirectory() as directory:
            first, second = asyncio.run(scenario(Path(directory)))
        self.assertEqual(len(first), QUORUM)
        self.assertLess(len(second), QUORUM)

    def test_corrupt_one_disk_is_not_silently_reset(self):
        async def scenario(root: Path):
            value = authority()
            async with DurableWitnessProcessNetwork(root) as network:
                await network.configure('corrupt', 'n1')
                await network.advance('corrupt', 1)
                body = checkpoint(value, 1)
                initial = await network.signatures('corrupt', body, value.log)
                network.stop('w1')
                network.state_path('w1', 'corrupt').write_text(
                    '{"state":{},"commitment":"bad"}\n')
                recovered = await network.restart('w1', strict=False)
                signatures = await network.signatures('corrupt', body, value.log)
                return initial, recovered, signatures
        with tempfile.TemporaryDirectory() as directory:
            initial, recovered, signatures = asyncio.run(
                scenario(Path(directory)))
        self.assertEqual(len(initial), 4)
        self.assertFalse(recovered)
        self.assertEqual(len(signatures), QUORUM)


if __name__ == '__main__':
    unittest.main(verbosity=2)
