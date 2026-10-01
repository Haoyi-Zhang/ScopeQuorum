"""Directed checks for the honest-issuer scoped status-delta counter-design."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import manifest
from codec import sign
from fixtures import grant
from model import Authority
from scope_delta import ScopeCache, ScopeService, check_scopes


def world():
    a0, a1 = Authority('n0'), Authority('n1')
    a0.append('grant', grant('n0'), 0)
    a1.append('grant', grant('n1'), 0)
    a1.append('publish', manifest('n1', 'leaf', []), 0)
    a1.append('publish', manifest('n1', 'leaf2', []), 0)
    a0.append('publish', manifest('n0', 'root', ['n1/leaf']), 0)
    a0.append('publish', manifest('n0', 'root2', ['n1/leaf', 'n1/leaf2']), 0)
    return {'n0': a0, 'n1': a1}


def registered(authorities, root2=False, now=1):
    s0, s1 = ScopeService(authorities['n0']), ScopeService(authorities['n1'])
    c0, c1 = ScopeCache('n0'), ScopeCache('n1')
    c0.apply_register(s0.register(['n0/root2' if root2 else 'n0/root'], now), now)
    keys = ['n1/leaf', 'n1/leaf2'] if root2 else ['n1/leaf']
    c1.apply_register(s1.register(keys, now), now)
    return {'n0': s0, 'n1': s1}, {'n0': c0, 'n1': c1}


class ScopeDeltaTests(unittest.TestCase):
    def test_honest_scope_reads_keep_two_epsilon_policy(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 10)
        authority.append('publish', manifest('n1', 'leaf', []), 10)
        service = ScopeService(authority)
        cache = ScopeCache('n1')
        cache.apply_register(
            service.register(['n1/leaf'], 14), 10, delta=10, epsilon=2)
        # 19 - 14 + 2*2 == 9, still fresh for the honest-issuer path.
        self.assertTrue(check_scopes(
            {'n1': cache}, 'n1/leaf', 19, delta=10, epsilon=2)['serve'])
        self.assertEqual(check_scopes(
            {'n1': cache}, 'n1/leaf', 20, delta=10, epsilon=2)['reason'],
            'EXPIRED')

    def test_scope_service_rejects_issuance_before_latest_event_transactionally(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 2)
        authority.append('publish', manifest('n1', 'leaf', []), 2)
        authority.append('publish', manifest('n1', 'leaf2', []), 2)
        service = ScopeService(authority)
        with self.assertRaises(ValueError):
            service.register(['n1/leaf'], 1)
        self.assertEqual(service.scopes, {})

        registration = service.register(['n1/leaf'], 2)
        scope = registration['body']['scope']
        count = registration['body']['count']
        before = deepcopy(service.scopes)
        authority.append('publish', manifest('n1', 'later', []), 3)
        with self.assertRaises(ValueError):
            service.renew(scope, count, 2)
        self.assertEqual(service.scopes, before)
        with self.assertRaises(ValueError):
            service.extend(scope, count, ['n1/leaf2'], 2)
        self.assertEqual(service.scopes, before)
        self.assertEqual(service.renew(scope, count, 3)['body']['issued'], 3)
        extended = service.extend(scope, count, ['n1/leaf2'], 3)
        self.assertEqual(extended['body']['issued'], 3)

    def test_valid_cross_namespace_closure(self):
        a = world(); _, caches = registered(a)
        self.assertTrue(check_scopes(caches, 'n0/root', 2)['serve'])

    def test_unrelated_update_has_empty_projection(self):
        a = world(); services, caches = registered(a)
        a['n1'].append('publish', manifest('n1', 'unrelated', []), 2)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        body = report['body']
        self.assertEqual(body['conflicts'], [])
        self.assertEqual(body['revoked_keys'], [])
        self.assertEqual(body['revoked_caps'], [])
        caches['n1'].apply_renew(report, 2)
        self.assertTrue(check_scopes(caches, 'n0/root', 2)['serve'])

    def test_identical_duplicate_is_status_neutral(self):
        a = world(); services, caches = registered(a)
        a['n1'].append('publish', deepcopy(a['n1'].log[1]['body']['data']), 2)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(report['body']['conflicts'], [])
        caches['n1'].apply_renew(report, 2)
        self.assertTrue(check_scopes(caches, 'n0/root', 2)['serve'])

    def test_artifact_revocation_is_projected(self):
        a = world(); services, caches = registered(a)
        a['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(report['body']['revoked_keys'], ['n1/leaf'])
        caches['n1'].apply_renew(report, 2)
        self.assertEqual(check_scopes(caches, 'n0/root', 2)['reason'],
                         'INVALID_OR_MISSING_STATUS')

    def test_capability_revocation_is_one_grouped_cause(self):
        a = world(); services, caches = registered(a, root2=True)
        a['n1'].append('revoke_cap', {'target': 'cap:n1:0'}, 2)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(report['body']['revoked_caps'], ['cap:n1:0'])
        caches['n1'].apply_renew(report, 2)
        self.assertFalse(caches['n1'].objects['n1/leaf']['valid'])
        self.assertFalse(caches['n1'].objects['n1/leaf2']['valid'])
        self.assertFalse(check_scopes(caches, 'n0/root2', 2)['serve'])

    def test_conflicting_publication_is_projected(self):
        a = world(); services, caches = registered(a)
        a['n1'].append('publish', manifest('n1', 'leaf', [], blob='other'), 2)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(report['body']['conflicts'], ['n1/leaf'])
        caches['n1'].apply_renew(report, 2)
        self.assertFalse(check_scopes(caches, 'n0/root', 2)['serve'])

    def test_scope_extension_adds_only_new_objects(self):
        a = world(); service = ScopeService(a['n1']); cache = ScopeCache('n1')
        cache.apply_register(service.register(['n1/leaf'], 1), 1)
        old_scope = cache.scope
        report = service.extend(cache.scope, cache.count, ['n1/leaf2'], 2)
        self.assertEqual([x['key'] for x in report['body']['objects']], ['n1/leaf2'])
        cache.apply_extend(report, 2)
        self.assertEqual(set(cache.objects), {'n1/leaf', 'n1/leaf2'})
        self.assertNotEqual(cache.scope, old_scope)

    def test_lost_extension_response_preserves_retryable_old_scope(self):
        a = world(); service = ScopeService(a['n1']); cache = ScopeCache('n1')
        cache.apply_register(service.register(['n1/leaf'], 1), 1)
        old_scope = cache.scope
        first = service.extend(old_scope, cache.count, ['n1/leaf2'], 2)
        # Simulate a lost response: the client keeps its old immutable handle.
        renewal = service.renew(old_scope, cache.count, 2)
        cache.apply_renew(renewal, 2)
        retry = service.extend(old_scope, cache.count, ['n1/leaf2'], 2)
        self.assertEqual(retry['body']['scope'], first['body']['scope'])
        cache.apply_extend(retry, 2)
        self.assertEqual(set(cache.objects), {'n1/leaf', 'n1/leaf2'})

    def test_scope_handle_binds_registered_key_set(self):
        a = world(); service = ScopeService(a['n1']); cache = ScopeCache('n1')
        report = service.register(['n1/leaf'], 1)
        bad = deepcopy(report)
        bad['body']['scope'] = 'A' * 44
        bad['signature'] = sign('authority:n1', bad['body'])
        with self.assertRaises(ValueError): cache.apply_register(bad, 1)
        self.assertIsNone(cache.scope)

    def test_invalid_extension_is_transactional(self):
        a = world(); service = ScopeService(a['n1']); cache = ScopeCache('n1')
        cache.apply_register(service.register(['n1/leaf'], 1), 1)
        report = service.extend(cache.scope, cache.count, ['n1/leaf2'], 2)
        bad = deepcopy(report)
        bad['body']['objects'][0]['manifest']['key'] = 'n1/wrong'
        bad['signature'] = sign('authority:n1', bad['body'])
        before = deepcopy(cache)
        with self.assertRaises(ValueError): cache.apply_extend(bad, 2)
        self.assertEqual(cache, before)

    def test_invalid_or_missing_registration_is_not_cacheable(self):
        a = world(); service = ScopeService(a['n1'])
        with self.assertRaises(ValueError):
            service.register(['n1/missing'], 1)
        a['n1'].append('revoke', {'target': 'n1/leaf'}, 1)
        with self.assertRaises(ValueError):
            service.register(['n1/leaf'], 1)

    def test_tampered_report_and_wrong_frontier_fail(self):
        a = world(); services, caches = registered(a)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        bad = deepcopy(report); bad['body']['count'] += 1
        with self.assertRaises(ValueError): caches['n1'].apply_renew(bad, 2)
        bad = deepcopy(report); bad['body']['from'] -= 1
        # Signature is now wrong as well; either check must fail closed.
        with self.assertRaises(ValueError): caches['n1'].apply_renew(bad, 2)

    def test_fresh_head_renews_unchanged_scope(self):
        a = world(); _, caches = registered(a)
        caches['n0'].apply_head(a['n0'].head(10), 10)
        caches['n1'].apply_head(a['n1'].head(10), 10)
        self.assertTrue(check_scopes(caches, 'n0/root', 10)['serve'])

    def test_failed_registration_does_not_allocate_scope(self):
        a = world(); service = ScopeService(a['n1'])
        with self.assertRaises(ValueError):
            service.register(['n1/missing'], 1)
        self.assertEqual(service.scopes, {})

    def test_expiry_and_floor_are_enforced(self):
        a = world(); services, caches = registered(a)
        report = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        with self.assertRaises(ValueError): caches['n1'].apply_renew(report, 12)
        with self.assertRaises(ValueError): caches['n1'].apply_renew(report, 2, floor=99)


if __name__ == '__main__':
    unittest.main(verbosity=2)
