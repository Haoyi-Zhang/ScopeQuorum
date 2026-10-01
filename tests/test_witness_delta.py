"""Directed checks for quorum-witnessed exact-scope deltas."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import witness_delta
from codec import commitment, manifest, sign, signed_receipt
from fixtures import grant
from model import Authority
from scope_delta import check_scopes as check_scopes_with_legacy_two_epsilon
from witness_delta import (
    QUORUM,
    QuorumUnavailable,
    Witness,
    WitnessCommittee,
    WitnessScopeCache,
    WitnessedScopeService,
    check_witness_scopes,
    quorum_intersection_audit,
)


def world():
    a0, a1 = Authority('n0'), Authority('n1')
    a0.append('grant', grant('n0'), 0)
    a1.append('grant', grant('n1'), 0)
    a1.append('publish', manifest('n1', 'leaf', []), 0)
    a1.append('publish', manifest('n1', 'leaf2', []), 0)
    a0.append('publish', manifest('n0', 'root', ['n1/leaf']), 0)
    a0.append('publish', manifest('n0', 'root2', ['n1/leaf', 'n1/leaf2']), 0)
    return {'n0': a0, 'n1': a1}


def registered(authorities, *, root2=False, now=1, faulty=()):
    committees = {
        ns: WitnessCommittee(ns, faulty=faulty)
        for ns in ('n0', 'n1')
    }
    services = {
        ns: WitnessedScopeService(authorities[ns], committees[ns])
        for ns in ('n0', 'n1')
    }
    caches = {'n0': WitnessScopeCache('n0'), 'n1': WitnessScopeCache('n1')}
    root = 'n0/root2' if root2 else 'n0/root'
    remote = ['n1/leaf', 'n1/leaf2'] if root2 else ['n1/leaf']
    caches['n0'].apply_register(services['n0'].register([root], now), now)
    caches['n1'].apply_register(services['n1'].register(remote, now), now)
    return committees, services, caches


def malicious_renew_body(service, cache, now, *, conflicts=(), revoked_keys=(), revoked_caps=()):
    return {
        'op': 'renew', 'ns': service.ns, 'scope': cache.scope,
        'from': cache.count, **service._frontier(now),
        'conflicts': list(conflicts), 'revoked_keys': list(revoked_keys),
        'revoked_caps': list(revoked_caps),
    }


class WitnessDeltaTests(unittest.TestCase):
    def test_nonzero_error_cached_reads_use_three_epsilon(self):
        """Exercise certificate admission and later serving through public APIs.

        True-time annotations for this bounded trace are: publications at 10;
        witnesses read 12 while the report says 14; the client reads 10 at true
        time 12; a revocation at 11 obtains a quorum at witness reading 13; and
        the isolated client reads 19 at true time 21.  With two epsilon the old
        cache would still serve at 19; witnessed reads must use three epsilon.
        """
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 10)
        authority.append('publish', manifest('n1', 'leaf', []), 10)
        committee = WitnessCommittee('n1', clock_epsilon=2)
        service = WitnessedScopeService(authority, committee)
        cache = WitnessScopeCache('n1')

        certificate = service.register(
            ['n1/leaf'], 14, witness_now=12)
        cache.apply_register(certificate, 10, delta=10, epsilon=2)
        self.assertTrue(check_witness_scopes(
            {'n1': cache}, 'n1/leaf', 17, delta=10, epsilon=2)['serve'])
        # Strict endpoint: 18 - 14 + 3*2 == 10, so it is expired.
        self.assertEqual(check_witness_scopes(
            {'n1': cache}, 'n1/leaf', 18, delta=10, epsilon=2)['reason'],
            'EXPIRED')

        authority.append('revoke', {'target': 'n1/leaf'}, 11)
        acknowledged = service.checkpoint(15, witness_now=13)
        self.assertEqual(len(acknowledged['witnesses']), QUORUM)
        # Reproduce the former adapter wiring: forwarding this witnessed cache
        # through the honest 2*epsilon scope checker still serves at 19.
        self.assertTrue(check_scopes_with_legacy_two_epsilon(
            {'n1': cache}, 'n1/leaf', 19, delta=10, epsilon=2)['serve'])
        # The public witnessed API must instead apply the composed 3*epsilon
        # guard on every read and fail closed.
        self.assertEqual(check_witness_scopes(
            {'n1': cache}, 'n1/leaf', 19, delta=10, epsilon=2)['reason'],
            'EXPIRED')

    def test_noncanonical_dependency_order_is_rejected(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        publication = manifest('n1', 'root', ['n2/z', 'n2/a'])
        # Re-sign an otherwise valid manifest after deliberately destroying
        # the canonical dependency order.  Signatures authenticate bytes; the
        # witness must additionally enforce the protocol's canonical form.
        publication['manifest']['deps'] = ['n2/z', 'n2/a']
        publication['signature'] = sign(
            publication['manifest']['publisher'], publication['manifest'])
        malicious_log = authority.log + [signed_receipt(
            'n1', len(authority.log) + 1, commitment(authority.log[-1]), 0,
            'publish', publication)]
        committee = WitnessCommittee('n1')
        committee.advance(1)
        body = {
            'op': 'checkpoint', 'ns': 'n1', 'count': len(malicious_log),
            'tip': commitment(malicious_log[-1]), 'issued': 1,
        }
        self.assertEqual(committee.signatures(body, malicious_log), [])

    def test_signed_slot_bound_preserves_retry_but_rejects_new_slot(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        authority.append('publish', manifest('n1', 'leaf', []), 0)
        witness = Witness('n1', 'w1')
        first = {
            'op': 'checkpoint', 'ns': 'n1', 'count': len(authority.log),
            'tip': commitment(authority.log[-1]), 'issued': 1,
        }
        witness.advance(1)
        with patch.object(witness_delta, 'MAX_SIGNED_SLOTS', 1):
            self.assertIsNotNone(witness.certify(first, authority.log))
            witness.advance(2)
            retry = dict(first, issued=2)
            self.assertIsNotNone(witness.certify(retry, authority.log))
            authority.append('revoke', {'target': 'n1/leaf'}, 2)
            second = {
                'op': 'checkpoint', 'ns': 'n1',
                'count': len(authority.log),
                'tip': commitment(authority.log[-1]), 'issued': 2,
            }
            self.assertIsNone(witness.certify(second, authority.log))
        self.assertEqual(len(witness.signed_slots), 1)

    def test_valid_cross_namespace_closure(self):
        authorities = world(); _, _, caches = registered(authorities)
        self.assertTrue(check_witness_scopes(caches, 'n0/root', 2)['serve'])

    def test_valid_empty_projection_renews_after_unrelated_event(self):
        authorities = world(); _, services, caches = registered(authorities)
        authorities['n1'].append('publish', manifest('n1', 'unrelated', []), 2)
        cert = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(cert['body']['conflicts'], [])
        self.assertEqual(cert['body']['revoked_keys'], [])
        self.assertEqual(cert['body']['revoked_caps'], [])
        caches['n1'].apply_renew(cert, 2)
        self.assertTrue(check_witness_scopes(caches, 'n0/root', 2)['serve'])

    def test_omitted_artifact_revocation_gets_only_faulty_signature(self):
        authorities = world(); committees, services, caches = registered(authorities, faulty=('w0',))
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        committees['n1'].advance(2)
        body = malicious_renew_body(services['n1'], caches['n1'], 2)
        sigs = committees['n1'].signatures(body, authorities['n1'].log)
        self.assertEqual([item['id'] for item in sigs], ['w0'])
        with self.assertRaises(QuorumUnavailable):
            committees['n1'].certify(body, authorities['n1'].log)

    def test_omitted_capability_revocation_gets_only_faulty_signature(self):
        authorities = world(); committees, services, caches = registered(
            authorities, root2=True, faulty=('w0',))
        authorities['n1'].append('revoke_cap', {'target': 'cap:n1:0'}, 2)
        committees['n1'].advance(2)
        body = malicious_renew_body(services['n1'], caches['n1'], 2)
        self.assertEqual(len(committees['n1'].signatures(body, authorities['n1'].log)), 1)

    def test_omitted_conflict_gets_only_faulty_signature(self):
        authorities = world(); committees, services, caches = registered(authorities, faulty=('w0',))
        authorities['n1'].append('publish', manifest('n1', 'leaf', [], blob='forked-object'), 2)
        committees['n1'].advance(2)
        body = malicious_renew_body(services['n1'], caches['n1'], 2)
        self.assertEqual(len(committees['n1'].signatures(body, authorities['n1'].log)), 1)

    def test_valid_revocation_is_certified_and_invalidates_closure(self):
        authorities = world(); _, services, caches = registered(authorities, faulty=('w0',))
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        cert = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        self.assertEqual(len(cert['witnesses']), QUORUM)
        self.assertEqual(cert['body']['revoked_keys'], ['n1/leaf'])
        caches['n1'].apply_renew(cert, 2)
        self.assertFalse(check_witness_scopes(caches, 'n0/root', 2)['serve'])

    def test_fewer_than_three_reachable_witnesses_abstains(self):
        authorities = world()
        committee = WitnessCommittee('n1')
        service = WitnessedScopeService(authorities['n1'], committee)
        with self.assertRaises(QuorumUnavailable):
            service.register(['n1/leaf'], 1, available=('w0', 'w1'))
        cert = service.register(['n1/leaf'], 1, available=('w0', 'w1', 'w2'))
        self.assertEqual([item['id'] for item in cert['witnesses']], ['w0', 'w1', 'w2'])

    def test_duplicate_or_unknown_signers_are_rejected(self):
        authorities = world(); _, services, caches = registered(authorities)
        cert = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        duplicate = deepcopy(cert)
        duplicate['witnesses'] = [deepcopy(cert['witnesses'][0]) for _ in range(3)]
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(duplicate, 2)
        unknown = deepcopy(cert)
        unknown['witnesses'][0]['id'] = 'w9'
        unknown['witnesses'][0]['signature'] = sign('witness:n1:w9', unknown['body'])
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(unknown, 2)


    def test_honest_witness_rejects_unbounded_sequencer_timestamp(self):
        authorities = world(); committees, services, caches = registered(
            authorities, faulty=('w0',))
        valid = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        bad_body = deepcopy(valid['body'])
        bad_body['issued'] = 100
        signatures = committees['n1'].signatures(bad_body, authorities['n1'].log)
        self.assertEqual([item['id'] for item in signatures], ['w0'])

    def test_honest_witness_rejects_history_after_report_timestamp(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        authority.append('publish', manifest('n1', 'leaf', []), 2)
        committee = WitnessCommittee('n1', faulty=('w0',))
        committee.advance(1)
        body = {
            'op': 'checkpoint', 'ns': 'n1', 'count': len(authority.log),
            'tip': commitment(authority.log[-1]), 'issued': 1,
        }
        signatures = committee.signatures(body, authority.log)
        self.assertEqual([item['id'] for item in signatures], ['w0'])

    def test_tampered_body_or_authority_signature_is_rejected(self):
        authorities = world(); _, services, caches = registered(authorities)
        cert = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        bad = deepcopy(cert); bad['body']['count'] += 1
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(bad, 2)
        bad = deepcopy(cert); bad['authority_signature'] = 'A' * 88
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(bad, 2)

    def test_malformed_projection_does_not_pin_honest_witness_log(self):
        authorities = world(); committees, services, caches = registered(authorities)
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        committees['n1'].advance(2)
        malformed = malicious_renew_body(services['n1'], caches['n1'], 2)
        self.assertEqual(committees['n1'].signatures(malformed, authorities['n1'].log), [])
        old_count = caches['n1'].count
        self.assertTrue(all(len(w.log) == old_count for w in committees['n1'].witnesses.values()))
        valid = services['n1'].renew(caches['n1'].scope, old_count, 2)
        self.assertEqual(len(valid['witnesses']), QUORUM)


    def test_unacknowledged_private_event_is_outside_effective_frontier(self):
        authorities = world(); committees, services, caches = registered(
            authorities, faulty=('w0',))
        old_log = deepcopy(authorities['n1'].log)
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        committees['n1'].advance(2)
        # A sequencer-only receipt is not yet effective under the witnessed
        # contract.  A fresh report at the last quorum-visible frontier can be
        # certified until the revocation itself obtains a quorum checkpoint.
        body = {
            'op': 'renew', 'ns': 'n1', 'scope': caches['n1'].scope,
            'from': caches['n1'].count, 'count': len(old_log),
            'tip': commitment(old_log[-1]), 'issued': 2,
            'conflicts': [], 'revoked_keys': [], 'revoked_caps': [],
        }
        cert = committees['n1'].certify(body, old_log)
        self.assertEqual(len(cert['witnesses']), QUORUM)

    def test_quorum_acknowledged_revocation_cannot_be_omitted_later(self):
        authorities = world(); committees, services, caches = registered(
            authorities, faulty=('w0',))
        old_log = deepcopy(authorities['n1'].log)
        authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 2)
        committees['n1'].advance(2)
        checkpoint = {
            'op': 'checkpoint', 'ns': 'n1',
            'count': len(authorities['n1'].log),
            'tip': commitment(authorities['n1'].log[-1]), 'issued': 2,
        }
        acknowledged = committees['n1'].certify(
            checkpoint, authorities['n1'].log)
        self.assertEqual(len(acknowledged['witnesses']), QUORUM)
        committees['n1'].advance(3)
        stale = {
            'op': 'renew', 'ns': 'n1', 'scope': caches['n1'].scope,
            'from': caches['n1'].count, 'count': len(old_log),
            'tip': commitment(old_log[-1]), 'issued': 3,
            'conflicts': [], 'revoked_keys': [], 'revoked_caps': [],
        }
        signatures = committees['n1'].signatures(stale, old_log)
        self.assertEqual([item['id'] for item in signatures], ['w0'])

    def test_conflicting_forks_cannot_both_reach_quorum(self):
        base = Authority('n1')
        base.append('grant', grant('n1'), 0)
        base.append('publish', manifest('n1', 'leaf', []), 0)
        left = deepcopy(base); right = deepcopy(base)
        left.append('revoke', {'target': 'n1/leaf'}, 2)
        right.append('publish', manifest('n1', 'leaf', [], blob='conflict'), 2)
        committee = WitnessCommittee('n1', faulty=('w0',))
        committee.advance(2)
        left_body = {
            'op': 'checkpoint', 'ns': 'n1', 'count': len(left.log),
            'tip': commitment(left.log[-1]), 'issued': 2,
        }
        right_body = {
            'op': 'checkpoint', 'ns': 'n1', 'count': len(right.log),
            'tip': commitment(right.log[-1]), 'issued': 2,
        }
        first = committee.certify(left_body, left.log, available=('w0', 'w1', 'w2'))
        self.assertEqual(len(first['witnesses']), QUORUM)
        with self.assertRaises(QuorumUnavailable):
            committee.certify(right_body, right.log, available=('w0', 'w2', 'w3'))

    def test_lost_extension_response_is_retry_safe(self):
        authorities = world(); _, services, caches = registered(authorities)
        old = caches['n1'].scope
        first = services['n1'].extend(old, caches['n1'].count, ['n1/leaf2'], 2)
        renewal = services['n1'].renew(old, caches['n1'].count, 2)
        caches['n1'].apply_renew(renewal, 2)
        retry = services['n1'].extend(old, caches['n1'].count, ['n1/leaf2'], 2)
        self.assertEqual(first['body']['scope'], retry['body']['scope'])
        caches['n1'].apply_extend(retry, 2)
        self.assertEqual(set(caches['n1'].objects), {'n1/leaf', 'n1/leaf2'})

    def test_expiry_and_floor_are_enforced(self):
        authorities = world(); _, services, caches = registered(authorities)
        cert = services['n1'].renew(caches['n1'].scope, caches['n1'].count, 2)
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(cert, 12)
        with self.assertRaises(ValueError):
            caches['n1'].apply_renew(cert, 2, floor=99)

    def test_quorum_intersection_enumeration(self):
        audit = quorum_intersection_audit()
        self.assertEqual(audit['committee_size'], 4)
        self.assertEqual(audit['fault_bound'], 1)
        self.assertEqual(audit['quorum'], 3)
        self.assertEqual(audit['quorum_sets'], 4)
        self.assertEqual(audit['minimum_intersection'], 2)
        self.assertEqual(audit['honest_intersection_failures'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
