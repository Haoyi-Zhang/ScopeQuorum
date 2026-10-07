"""Six finite pure regressions, explicitly run by scientific CI; no I/O campaign."""
from __future__ import annotations
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import encode, manifest
from fixtures import grant
from model import Authority
from scope_delta import _status, _statuses
from witness_delta import WitnessCommittee, WitnessScopeCache, WitnessedScopeService, _projection


def histories():
    """256 admitted signed paths, H<=16, K=4; later transfer grants are genuine."""
    for choices in itertools.product(range(4), repeat=4):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        for name in ('a', 'b'):
            authority.append('publish', manifest('n1', name, []), 0)
        for tick, choice in enumerate(choices, 1):
            if choice == 0:
                # Use current epoch: same-key publication after transfer is a conflict.
                authority.append('publish', manifest('n1', 'a', [], epoch=authority.epoch), tick)
            elif choice == 1:
                authority.append('publish', manifest('n1', 'b', [], epoch=authority.epoch, blob='different'), tick)
            elif choice == 2:
                authority.append('revoke', {'target': 'n1/a'}, tick)
            else:
                authority.append('transfer', {'epoch': authority.epoch + 1}, tick)
                authority.append('grant', grant('n1', authority.epoch), tick)
        authority.append('revoke_cap', {'target': 'cap:n1:0'}, 5)
        authority.append('revoke_cap', {'target': 'cap:n1:0'}, 5)
        yield authority.log


def reference_status(log, key, count=None):
    """Independent finite-set specification, not a historical implementation."""
    prefix = log if count is None else log[:count]
    publications = [row['body']['data']['manifest'] for row in prefix
                    if row['body']['kind'] == 'publish' and row['body']['data']['manifest']['key'] == key]
    distinct = {json.dumps(item, sort_keys=True, separators=(',', ':')) for item in publications}
    revoked_keys = {row['body']['data']['target'] for row in prefix if row['body']['kind'] == 'revoke'}
    revoked_caps = {row['body']['data']['target'] for row in prefix if row['body']['kind'] == 'revoke_cap'}
    first = publications[0] if publications else None
    return {'key': key, 'manifest': first, 'valid': bool(first is not None and len(distinct) == 1
            and key not in revoked_keys and first['cap'] not in revoked_caps)}


def reference_projection(log, keys, start, end):
    previous = {key: reference_status(log, key, start) for key in keys}
    if any(item['manifest'] is None for item in previous.values()):
        raise ValueError('scope frontier predates registration')
    suffix = log[start:end]
    conflicts = set()
    for event in suffix:
        body = event['body']
        if body['kind'] == 'publish':
            published = body['data']['manifest']
            key = published['key']
            if key in previous and previous[key]['valid'] and published != previous[key]['manifest']:
                conflicts.add(key)
    caps = {item['manifest']['cap'] for item in previous.values() if item['valid']}
    return {'conflicts': sorted(conflicts),
            'revoked_keys': sorted({row['body']['data']['target'] for row in suffix
                                  if row['body']['kind'] == 'revoke' and row['body']['data']['target'] in previous}),
            'revoked_caps': sorted({row['body']['data']['target'] for row in suffix
                                  if row['body']['kind'] == 'revoke_cap' and row['body']['data']['target'] in caps})}


class StatusFoldRegression(unittest.TestCase):
    def test_all_admitted_prefixes_match_two_references(self):
        keys = ('n1/a', 'n1/b', 'n1/missing', 'n1/unused')
        count = 0
        for log in histories():
            self.assertLessEqual(len(log), 16)
            before = deepcopy(log)
            for frontier in range(len(log) + 1):
                expected = {key: reference_status(log, key, frontier) for key in keys}
                self.assertEqual(_statuses(log, keys, frontier), expected)
                self.assertEqual({key: _status(log, key, frontier) for key in keys}, expected)
            self.assertEqual(_statuses(log, keys), {key: reference_status(log, key) for key in keys})
            self.assertEqual(log, before)
            count += 1
        self.assertEqual(count, 256)

    def test_projection_all_legal_prefix_pairs(self):
        for log in histories():
            for start in range(3, len(log) + 1):
                for end in range(start, len(log) + 1):
                    self.assertEqual(_projection(log, ('n1/a', 'n1/b'), start, end),
                                     reference_projection(log, ('n1/a', 'n1/b'), start, end))

    def test_prepublication_revocation_and_permanent_conflict(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        authority.append('revoke', {'target': 'n1/a'}, 0)
        authority.append('publish', manifest('n1', 'a', []), 0)
        first = manifest('n1', 'b', [])
        authority.append('publish', first, 0)
        authority.append('publish', manifest('n1', 'b', [], blob='conflict'), 0)
        authority.append('publish', first, 0)
        folded = _statuses(authority.log, ('n1/a', 'n1/b'))
        self.assertFalse(folded['n1/a']['valid'])
        self.assertFalse(folded['n1/b']['valid'])
        self.assertEqual(folded['n1/b']['manifest'], first['manifest'])

    def test_frontier_and_missing_key_errors_unchanged(self):
        log = next(histories())
        for start, end in ((-1, 3), (True, 3), (4, 3), (0, len(log) + 1)):
            with self.assertRaisesRegex(ValueError, 'invalid projection frontier'):
                _projection(log, ('n1/a',), start, end)
        with self.assertRaisesRegex(ValueError, 'scope frontier predates registration'):
            _projection(log, ('n1/missing',), 3, len(log))
        self.assertEqual(_statuses([], ('n1/a',)), {'n1/a': {'key': 'n1/a', 'manifest': None, 'valid': False}})

    def test_no_cross_request_fold_state(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        authority.append('publish', manifest('n1', 'a', []), 0)
        folded = _statuses(authority.log, ('n1/a',))
        folded['n1/a']['valid'] = False
        self.assertTrue(_statuses(authority.log, ('n1/a',))['n1/a']['valid'])
        authority.append('revoke', {'target': 'n1/a'}, 1)
        self.assertFalse(_statuses(authority.log, ('n1/a',))['n1/a']['valid'])
        self.assertTrue(_statuses(authority.log, ('n1/a',), 2)['n1/a']['valid'])

    def test_real_signed_witness_renewal_and_retry(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 0)
        authority.append('publish', manifest('n1', 'a', []), 0)
        committee = WitnessCommittee('n1', faulty=('w0',))
        service = WitnessedScopeService(authority, committee)
        cache = WitnessScopeCache('n1')
        cache.apply_register(service.register(['n1/a'], 1), 1)
        start = cache.count
        authority.append('revoke', {'target': 'n1/a'}, 2)
        certificate = service.renew(cache.scope, start, 2)
        retry = service.renew(cache.scope, start, 2)
        self.assertEqual(encode(certificate), encode(retry))
        self.assertEqual(certificate['body']['revoked_keys'], ['n1/a'])
        cache.apply_renew(certificate, 2)
        self.assertFalse(cache.objects['n1/a']['valid'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
