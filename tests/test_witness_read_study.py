"""Owned finite baseline/adaptor parity and transport-accounting regressions."""
from copy import deepcopy
import asyncio
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import encode, manifest
from fixtures import grant
from model import Authority
from witness_delta import (WitnessCommittee, WitnessedScopeService, WitnessScopeCache,
                           _tip, check_witness_scopes)
from witness_network import WitnessTCPNetwork
from witness_read_study import PrefixCache, ReadEndpoint, compare, run_mode, state_cost


def authority():
    a = Authority('n1')
    a.append('grant', grant('n1'), 0)
    a.append('publish', manifest('n1', 'leaf', []), 0)
    a.append('publish', manifest('n1', 'parent', ['n1/leaf']), 0)
    return a


def prefix_reply(a, now=1, start=0):
    service = WitnessedScopeService(a, WitnessCommittee(a.ns))
    return {'start': start, 'previous': _tip(a.log, start),
            'events': deepcopy(a.log[start:]), 'certificate': service.checkpoint(now)}


class PrefixContractTests(unittest.TestCase):
    def test_complete_prefix_then_suffix_preserves_same_contract(self):
        a = authority()
        cache = PrefixCache(a.ns)
        cache.apply(prefix_reply(a), 1)
        self.assertTrue(check_witness_scopes({a.ns: cache.view}, 'n1/parent', 1)['serve'])
        a.append('revoke', {'target': 'n1/leaf'}, 2)
        cache.apply(prefix_reply(a, 2, 3), 2, floor=3)
        verdict = check_witness_scopes({a.ns: cache.view}, 'n1/parent', 2)
        self.assertFalse(verdict['serve'])
        self.assertEqual(cache.view.count, 4)

    def test_wrong_base_count_tip_or_signature_is_atomic(self):
        a = authority()
        correct = prefix_reply(a)
        for change in ('base', 'count', 'tip', 'signature', 'receipt'):
            cache = PrefixCache(a.ns)
            bad = deepcopy(correct)
            if change == 'base':
                bad['start'] = True
            elif change == 'count':
                bad['events'].pop()
            elif change == 'tip':
                bad['previous'] = 'wrong'
            elif change == 'signature':
                bad['certificate']['witnesses'][0]['signature'] = 'invalid'
            else:
                bad['events'][1]['signature'] = 'invalid'
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    cache.apply(bad, 1)
                self.assertEqual(cache.log, [])
                self.assertIsNone(cache.view.scope)

    def test_three_epsilon_boundary_and_remembered_floor(self):
        a = authority()
        reply = prefix_reply(a)
        cache = PrefixCache(a.ns)
        cache.apply(reply, 7, epsilon=1)  # 7-1+3 = 9 < 10
        self.assertTrue(check_witness_scopes({a.ns: cache.view}, 'n1/parent', 7, epsilon=1)['serve'])
        self.assertFalse(check_witness_scopes({a.ns: cache.view}, 'n1/parent', 8, epsilon=1)['serve'])
        with self.assertRaises(ValueError):
            PrefixCache(a.ns).apply(reply, 8, epsilon=1)
        with self.assertRaises(ValueError):
            PrefixCache(a.ns).apply(reply, 1, floor=4)

    def test_exact_checkpoint_body_and_distinct_quorum_required(self):
        a = authority()
        reply = prefix_reply(a)
        reply['certificate']['witnesses'][1] = deepcopy(reply['certificate']['witnesses'][0])
        with self.assertRaises(ValueError):
            PrefixCache(a.ns).apply(reply, 1)


class ReadTransportTests(unittest.TestCase):
    def test_tcp_scope_adapter_matches_existing_signed_bodies(self):
        async def scenario():
            a = authority()
            original = WitnessedScopeService(a, WitnessCommittee(a.ns))
            async with WitnessTCPNetwork() as network:
                network.configure(a.ns, a.ns)
                async with ReadEndpoint({a.ns: a}, network) as endpoint:
                    network.advance(a.ns, 1)
                    request = {'op': 'register', 'ns': a.ns, 'keys': ['n1/leaf'], 'now': 1}
                    actual = await endpoint.exchange(request)
                    expected = original.register(['n1/leaf'], 1)
                    self.assertEqual(actual, expected)
                    self.assertEqual(endpoint.client_bytes, len(encode(request)) + len(encode(actual)) + 2)
                    self.assertEqual(endpoint.snapshot_serializations, 4)
                    cache = WitnessScopeCache(a.ns)
                    cache.apply_register(actual, 1)
                    for now, kind in ((2, 'extend'), (3, 'head'), (4, 'renew')):
                        network.advance(a.ns, now)
                        if kind == 'extend':
                            request = {'op': 'extend', 'ns': a.ns, 'scope': cache.scope,
                                       'from': cache.count, 'add': ['n1/parent'], 'now': now}
                            expected = original.extend(cache.scope, cache.count, ['n1/parent'], now)
                        else:
                            if kind == 'renew':
                                a.append('revoke', {'target': 'n1/leaf'}, now)
                            request = {'op': 'refresh', 'ns': a.ns, 'scope': cache.scope,
                                       'from': cache.count, 'now': now}
                            expected = (original.head(cache.scope, now) if kind == 'head'
                                        else original.renew(cache.scope, cache.count, now))
                        actual = await endpoint.exchange(request)
                        self.assertEqual(actual, expected)
                        getattr(cache, 'apply_' + kind)(actual, now)
                    self.assertFalse(check_witness_scopes({a.ns: cache}, 'n1/parent', 4)['serve'])
                    counters = network.counters
                    self.assertEqual(counters.wire_bytes, counters.prefix_wire_bytes + counters.sync_wire_bytes
                                     + counters.reset_wire_bytes + counters.certify_wire_bytes)
                    costs = state_cost(endpoint, network, {a.ns: cache})
                    self.assertEqual(costs['aggregate_serialized_bytes'],
                                     sum(costs[k] for k in ('sequencer_bytes', 'client_bytes',
                                                           'accepted_witness_bytes', 'staging_bytes')))
        asyncio.run(scenario())

    def test_quorum_loss_does_not_return_uncertified_client_state(self):
        async def scenario():
            a = authority()
            async with WitnessTCPNetwork() as network:
                network.configure(a.ns, a.ns)
                network.advance(a.ns, 1)
                network.blocked = {'w2', 'w3'}
                async with ReadEndpoint({a.ns: a}, network) as endpoint:
                    request = {'op': 'register', 'ns': a.ns, 'keys': ['n1/leaf'], 'now': 1}
                    self.assertEqual(await endpoint.exchange(request), {'unavailable': True})
                    self.assertEqual(endpoint.scopes[a.ns], {})
                    self.assertEqual(endpoint.snapshot_serializations, 2)
                    # Preserve the partial witnesses' signed state, then retry.
                    slots = deepcopy(network.states['w0'][a.ns].signed_slots)
                    network.blocked.clear()
                    cert = await endpoint.exchange(request)
                    cache = WitnessScopeCache(a.ns)
                    cache.apply_register(cert, 1)
                    self.assertEqual(slots, network.states['w0'][a.ns].signed_slots)
                    self.assertEqual(len(endpoint.scopes[a.ns]), 1)
        asyncio.run(scenario())

    def test_real_cross_namespace_reads_revoke_expire_and_recover(self):
        async def scenario():
            results = [await run_mode('public-lock', 3, 1, 'capability-revoke', mode)
                       for mode in ('prefix', 'scope')]
            row = compare(*results)
            self.assertEqual(row['read_pairs'], 10)
            for result in results:
                self.assertEqual(sum(r['verdict']['serve'] for r in result['rows']), 6)
                self.assertEqual(result['rows'][4]['verdict']['reason'], 'EXPIRED')
                self.assertTrue(result['rows'][5]['verdict']['serve'])
                self.assertFalse(result['rows'][6]['verdict']['serve'])
                self.assertGreater(result['witness_counters']['prefix_wire_bytes'], 0)
                self.assertGreater(result['peak_state']['staging_bytes'], 0)
            self.assertGreater(results[1]['operations'].get('extend', 0), 0)
        asyncio.run(scenario())


if __name__ == '__main__':
    unittest.main(verbosity=2)
