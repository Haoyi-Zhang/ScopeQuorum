"""Loopback transport checks for independent witness endpoints."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, manifest
from fixtures import grant
from model import Authority
from witness_delta import QUORUM
from witness_network import WitnessTCPNetwork
from witness_network_study import UPDATES, valid_update_case


def authority():
    a = Authority('n1')
    a.append('grant', grant('n1'), 0)
    a.append('publish', manifest('n1', 'leaf', []), 0)
    return a


class WitnessNetworkTests(unittest.TestCase):
    def test_network_updates_check_actual_cached_scope(self):
        async def scenario():
            async with WitnessTCPNetwork() as network:
                return [await valid_update_case(network, 'state-' + update,
                                                'public-lock', 1, update)
                        for update in UPDATES]
        for row in asyncio.run(scenario()):
            with self.subTest(update=row['update']):
                self.assertTrue(row['accepted'])
                self.assertTrue(row['client_state_matches_reference'])
                self.assertEqual(row['actual_scope_valid_after_update'],
                                 row['expected_serve_after_update'])

    def test_network_study_detects_dropped_client_renewal(self):
        async def scenario():
            async with WitnessTCPNetwork() as network:
                with patch('witness_network_study.WitnessScopeCache.apply_renew',
                           return_value=None):
                    return await valid_update_case(network, 'dropped-renewal',
                                                   'public-lock', 1,
                                                   'artifact-revocation')
        row = asyncio.run(scenario())
        self.assertTrue(row['accepted'])  # Signer counts alone would pass.
        self.assertTrue(row['actual_scope_valid_after_update'])
        self.assertFalse(row['expected_serve_after_update'])
        self.assertFalse(row['client_state_matches_reference'])

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
