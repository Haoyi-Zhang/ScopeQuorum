"""Owned benign transcript round trips and fail-closed client recovery."""
from copy import deepcopy
from dataclasses import asdict
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import encode, manifest
from fixtures import grant
from model import Authority
import witness_client
from witness_client import WitnessClient
from witness_delta import WitnessCommittee, WitnessedScopeService


def fixture():
    authorities, services = {}, {}
    for ns in ('n0', 'n1'):
        authority = Authority(ns)
        authority.append('grant', grant(ns), 0)
        authorities[ns] = authority
        services[ns] = WitnessedScopeService(authority, WitnessCommittee(ns))
    authorities['n0'].append('publish', manifest('n0', 'root', ['n1/leaf']), 0)
    for name in ('leaf', 'extra'):
        authorities['n1'].append('publish', manifest('n1', name, []), 0)
    client = WitnessClient(['n0', 'n1'])
    for ns, key in [('n0', 'n0/root'), ('n1', 'n1/leaf')]:
        client.apply(services[ns].register([key], 1), 1)
    return authorities, services, client


def restore(client, payload=None, **overrides):
    policy = dict(namespaces=['n0', 'n1'], delta=10, epsilon=0,
                  minimum_floors=client.floors)
    policy.update(overrides)
    return WitnessClient.restore(client.snapshot() if payload is None else payload, **policy)


class WitnessClientTests(unittest.TestCase):
    def test_roundtrip_preserves_multinamespace_state_and_all_four_operations(self):
        authorities, services, client = fixture()
        cache = client.views['n1']
        client.apply(services['n1'].extend(cache.scope, cache.count, ['n1/extra'], 2), 2)
        authorities['n1'].append('revoke', {'target': 'n1/extra'}, 3)
        cache = client.views['n1']
        client.apply(services['n1'].renew(cache.scope, cache.count, 3), 3)
        client.apply(services['n1'].head(client.views['n1'].scope, 4), 4)
        reopened = restore(client)
        self.assertEqual(reopened.snapshot(), client.snapshot())
        self.assertEqual(reopened.floors, client.floors)
        self.assertEqual({ns: asdict(c) for ns, c in reopened.views.items()},
                         {ns: asdict(c) for ns, c in client.views.items()})
        for root in ('n0/root', 'n1/extra'):
            self.assertEqual(reopened.check(root, 5), client.check(root, 5))
        self.assertTrue(reopened.check('n0/root', 5)['serve'])
        self.assertEqual(reopened.check('n1/extra', 5)['reason'], 'INVALID_OR_MISSING_STATUS')

    def test_historical_replay_never_refreshes_expired_evidence(self):
        _, services, client = fixture()
        cache = client.views['n1']
        client.apply(services['n1'].head(cache.scope, 15), 15)
        reopened = restore(client)
        self.assertEqual(reopened.views['n0'].issued, 1)
        self.assertEqual(reopened.views['n1'].issued, 15)
        self.assertEqual(reopened.check('n0/root', 15)['reason'], 'EXPIRED')
        self.assertTrue(reopened.check('n1/leaf', 24)['serve'])
        self.assertEqual(reopened.check('n1/leaf', 25)['reason'], 'EXPIRED')

    def test_nonzero_clock_margin_survives_reconstruction(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 10)
        authority.append('publish', manifest('n1', 'leaf', []), 10)
        service = WitnessedScopeService(authority, WitnessCommittee('n1', clock_epsilon=2))
        client = WitnessClient(['n1'], delta=10, epsilon=2)
        client.apply(service.register(['n1/leaf'], 14, witness_now=12), 10)
        reopened = WitnessClient.restore(client.snapshot(), namespaces=['n1'],
                                          delta=10, epsilon=2, minimum_floors=client.floors)
        self.assertTrue(reopened.check('n1/leaf', 17)['serve'])
        self.assertEqual(reopened.check('n1/leaf', 18)['reason'], 'EXPIRED')

    def test_stale_live_admission_is_atomic(self):
        _, services, client = fixture()
        before = client.snapshot()
        cert = services['n1'].head(client.views['n1'].scope, 2)
        with self.assertRaises(ValueError):
            client.apply(cert, 12)
        self.assertEqual(client.snapshot(), before)

    def test_owned_corruptions_fail_closed_without_touching_live_client(self):
        _, _, client = fixture()
        before = client.snapshot()
        def signature(v): v['certificates']['n1'][0]['witnesses'][0]['signature'] = 'A' * 88
        def duplicate_signer(v): v['certificates']['n1'][0]['witnesses'][1] = deepcopy(v['certificates']['n1'][0]['witnesses'][0])
        def count(v): v['certificates']['n1'][0]['body']['count'] += 1
        def scope(v): v['certificates']['n1'][0]['body']['scope'] = 'A' * 44
        def namespace(v): v['certificates']['n1'][0]['body']['ns'] = 'n0'
        def missing_floor(v): del v['floors']['n1']
        def lowered_floor(v): v['floors']['n1'] -= 1
        def bool_floor(v): v['floors']['n1'] = True
        def missing_namespace(v): del v['certificates']['n1']
        def false_policy(v): v['epsilon'] = False
        def changed_policy(v): v['delta'] = 11
        def unknown(v): v['cache'] = {}
        for change in (signature, duplicate_signer, count, scope, namespace, missing_floor,
                       lowered_floor, bool_floor, missing_namespace, false_policy, changed_policy, unknown):
            damaged = json.loads(before)
            change(damaged)
            with self.subTest(change=change.__name__), self.assertRaises(ValueError):
                restore(client, encode(damaged))
            self.assertEqual(client.snapshot(), before)

    def test_incomplete_reordered_transition_sequence_is_rejected(self):
        authorities, services, client = fixture()
        authorities['n1'].append('publish', manifest('n1', 'unrelated', []), 2)
        cache = client.views['n1']
        client.apply(services['n1'].renew(cache.scope, cache.count, 2), 2)
        saved = json.loads(client.snapshot())
        for rows in ([saved['certificates']['n1'][1]], list(reversed(saved['certificates']['n1']))):
            damaged = deepcopy(saved)
            damaged['certificates']['n1'] = rows
            with self.assertRaises(ValueError):
                restore(client, encode(damaged))

    def test_independent_floor_detects_whole_snapshot_rollback(self):
        authorities, services, client = fixture()
        old = client.snapshot()
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        cache = client.views['n1']
        client.apply(services['n1'].renew(cache.scope, cache.count, 2), 2)
        with self.assertRaises(ValueError):
            restore(client, old)
        # A lost independent anchor is a different premise, not detectable from
        # an internally consistent old transcript alone.
        old_floors = json.loads(old)['floors']
        reopened = restore(client, old, minimum_floors=old_floors)
        self.assertTrue(reopened.check('n0/root', 2)['serve'])
        self.assertFalse(client.check('n0/root', 2)['serve'])

    def test_independent_floor_and_trust_configuration_types_are_exact(self):
        _, _, client = fixture()
        for floors in ({'n0': True, 'n1': 0}, {'n0': 0}, {'n0': 0, 'n1': -1}):
            with self.subTest(floors=floors), self.assertRaises(ValueError):
                restore(client, minimum_floors=floors)
        for config in (['n0'], ['n0', 'n1', 'n2']):
            with self.assertRaises(ValueError):
                restore(client, namespaces=config)
        for config in ([], ['n0', 'n0'], ['n99'], ['n0', False]):
            with self.assertRaises(ValueError):
                WitnessClient(config)
        for policy in ({'delta': True}, {'epsilon': False}, {'delta': 6, 'epsilon': 2}):
            with self.assertRaises(ValueError):
                WitnessClient(['n0'], **policy)

    def test_malformed_json_and_size_bounds_are_rejected(self):
        _, _, client = fixture()
        for payload in (b'', b'{', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff',
                        b'{"x":{"a":1,"a":2}}', client.snapshot()[:-1], 'not bytes'):
            with self.subTest(payload=repr(payload)[:40]), self.assertRaises(ValueError):
                restore(client, payload)
        with patch.object(witness_client, 'MAX_FRAME', len(client.snapshot()) - 1):
            with self.assertRaises(ValueError):
                restore(client)

    def test_capacity_errors_preserve_client_state(self):
        _, services, client = fixture()
        cert = services['n1'].head(client.views['n1'].scope, 2)
        before = client.snapshot()
        with patch.object(witness_client, 'MAX_CERTIFICATES', 2):
            with self.assertRaises(ValueError):
                client.apply(cert, 2)
            with self.assertRaises(ValueError):
                restore(client, encode({**json.loads(before), 'certificates': {
                    'n0': json.loads(before)['certificates']['n0'],
                    'n1': json.loads(before)['certificates']['n1'] + [cert]}}))
        with patch.object(witness_client, 'MAX_FRAME', len(before)):
            with self.assertRaises(ValueError):
                client.apply(cert, 2)
        self.assertEqual(client.snapshot(), before)

    def test_external_mutation_does_not_change_transcript_or_cached_state(self):
        _, services, client = fixture()
        cert = services['n1'].head(client.views['n1'].scope, 2)
        client.apply(cert, 2)
        before = client.snapshot()
        cert['body']['issued'] = 999
        views = client.views
        views['n1'].objects['n1/leaf']['valid'] = False
        floors = client.floors
        floors['n1'] = 999
        self.assertEqual(client.snapshot(), before)
        self.assertTrue(client.check('n0/root', 2)['serve'])

    def test_empty_configured_namespace_is_preserved(self):
        client = WitnessClient(['n0', 'n1'])
        reopened = restore(client)
        self.assertEqual(reopened.floors, {'n0': 0, 'n1': 0})
        self.assertEqual(reopened.snapshot(), client.snapshot())
        self.assertEqual(reopened.check('n0/root', 1)['reason'], 'MISSING_STATUS')

    def test_real_tcp_client_restores_then_accepts_new_signed_revocation(self):
        from witness_network import WitnessTCPNetwork
        from witness_read_study import ReadEndpoint

        async def scenario():
            authorities, _, _ = fixture()
            client = WitnessClient(['n0', 'n1'])
            async with WitnessTCPNetwork() as network:
                for ns in authorities:
                    network.configure(ns, ns)
                    network.advance(ns, 1)
                async with ReadEndpoint(authorities, network) as endpoint:
                    for ns, key in [('n0', 'n0/root'), ('n1', 'n1/leaf')]:
                        cert = await endpoint.exchange(
                            {'op': 'register', 'ns': ns, 'keys': [key], 'now': 1})
                        client.apply(cert, 1)
                    reopened = restore(client)
                    self.assertEqual(reopened.check('n0/root', 2), client.check('n0/root', 2))
                    self.assertTrue(reopened.check('n0/root', 2)['serve'])
                    authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
                    network.advance('n1', 2)
                    cache = reopened.views['n1']
                    cert = await endpoint.exchange({'op': 'refresh', 'ns': 'n1',
                        'scope': cache.scope, 'from': cache.count, 'now': 2})
                    reopened.apply(cert, 2)
                    self.assertEqual(reopened.check('n0/root', 2)['reason'],
                                     'INVALID_OR_MISSING_STATUS')
                    with self.assertRaises(ValueError):
                        restore(reopened, client.snapshot())
                    self.assertEqual(endpoint.client_messages, 6)
                    self.assertGreater(network.counters.wire_bytes, 0)
        asyncio.run(scenario())

    def test_structured_malformed_rows_reject_without_live_mutation(self):
        _, _, client = fixture()
        before = client.snapshot()
        original = json.loads(before)['certificates']['n1'][0]
        malformed = [None, [], 7]
        for body in (None, [], 'body'):
            malformed.append({**deepcopy(original), 'body': body})
        for field in ('ns', 'op'):
            for value in ([], {}, None, True):
                row = deepcopy(original)
                row['body'][field] = value
                malformed.append(row)
        row = deepcopy(original)
        row['witnesses'][0] = []
        malformed.append(row)
        for row in malformed:
            with self.subTest(row=repr(row)[:80]):
                saved = json.loads(before)
                saved['certificates']['n1'][0] = row
                with self.assertRaises(ValueError):
                    restore(client, encode(saved))
                with self.assertRaises(ValueError):
                    client.apply(row, 2)
                self.assertEqual(client.snapshot(), before)

    def test_restored_future_time_margin_and_nondefault_policy_continuation(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 10)
        authority.append('publish', manifest('n1', 'leaf', []), 10)
        service = WitnessedScopeService(authority, WitnessCommittee('n1', clock_epsilon=2))
        client = WitnessClient(['n1'], delta=10, epsilon=2)
        client.apply(service.register(['n1/leaf'], 14, witness_now=12), 10)
        def reopen(value):
            return WitnessClient.restore(value.snapshot(), namespaces=['n1'],
                delta=10, epsilon=2, minimum_floors=value.floors)
        reopened = reopen(client)
        self.assertTrue(reopened.check('n1/leaf', 8)['serve'])
        self.assertEqual(reopened.check('n1/leaf', 7)['reason'], 'EXPIRED')
        for now in (True, 1.5, -1):
            self.assertEqual(reopened.check('n1/leaf', now)['reason'], 'BAD_POLICY')
        authority.append('publish', manifest('n1', 'extra', []), 11)
        cache = reopened.views['n1']
        reopened.apply(service.extend(cache.scope, cache.count, ['n1/extra'],
                                      15, witness_now=13), 11)
        reopened.apply(service.head(reopened.views['n1'].scope, 16, witness_now=14), 12)
        again = reopen(reopened)
        self.assertEqual(again.snapshot(), reopened.snapshot())
        self.assertTrue(again.check('n1/extra', 19)['serve'])
        self.assertEqual(again.check('n1/extra', 20)['reason'], 'EXPIRED')

    def test_exact_transcript_and_byte_capacity_accepts_last_transition(self):
        _, services, client = fixture()
        cert = services['n1'].head(client.views['n1'].scope, 2)
        reference = restore(client)
        reference.apply(cert, 2)
        exact_bytes = len(reference.snapshot())
        with patch.object(witness_client, 'MAX_CERTIFICATES', 3), \
                patch.object(witness_client, 'MAX_FRAME', exact_bytes):
            client.apply(cert, 2)
            self.assertEqual(len(client.snapshot()), exact_bytes)
            self.assertEqual(restore(client).snapshot(), client.snapshot())
            before = client.snapshot()
            with self.assertRaises(ValueError):
                client.apply(services['n1'].head(client.views['n1'].scope, 3), 3)
            self.assertEqual(client.snapshot(), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
