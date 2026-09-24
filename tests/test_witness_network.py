"""Loopback transport checks for independent witness endpoints."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, manifest
from fixtures import grant
from model import Authority
from witness_delta import QUORUM
from witness_network import WitnessTCPNetwork


def authority():
    a = Authority('n1')
    a.append('grant', grant('n1'), 0)
    a.append('publish', manifest('n1', 'leaf', []), 0)
    return a


class WitnessNetworkTests(unittest.TestCase):
    def test_distinct_endpoints_certify_valid_checkpoint(self):
        async def scenario():
            a = authority()
            body = {'op':'checkpoint','ns':'n1','count':len(a.log),
                    'tip':commitment(a.log[-1]),'issued':1}
            async with WitnessTCPNetwork() as network:
                network.configure('valid', 'n1')
                network.advance('valid', 1)
                signatures = await network.signatures('valid', body, a.log)
                return signatures, network.counters
        signatures, counters = asyncio.run(scenario())
        self.assertEqual(len(signatures), 4)
        self.assertEqual({item['id'] for item in signatures}, {'w0','w1','w2','w3'})
        self.assertEqual(counters.messages, 8)
        self.assertGreater(counters.wire_bytes, 0)

    def test_partition_below_quorum_blocks(self):
        async def scenario():
            a = authority()
            body = {'op':'checkpoint','ns':'n1','count':len(a.log),
                    'tip':commitment(a.log[-1]),'issued':1}
            async with WitnessTCPNetwork() as network:
                network.configure('partition', 'n1')
                network.advance('partition', 1)
                network.blocked = {'w2','w3'}
                signatures = await network.signatures('partition', body, a.log)
                return signatures, network.counters
        signatures, counters = asyncio.run(scenario())
        self.assertLess(len(signatures), QUORUM)
        self.assertEqual(counters.drops, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
