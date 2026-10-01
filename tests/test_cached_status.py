"""Checks for the cache-aware compact status reference."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import sys, unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cached_status import CachedStatus, check_cached, produce_compact
from codec import manifest
from fixtures import grant
from model import Authority
from status_reference import produce


def world():
    a0,a1=Authority('n0'),Authority('n1')
    a0.append('grant',grant('n0'),0);a1.append('grant',grant('n1'),0)
    a1.append('publish',manifest('n1','leaf',[]),0)
    a0.append('publish',manifest('n0','root',['n1/leaf']),0)
    return {'n0':a0,'n1':a1}


def caches(a,now=1):
    out={}
    for ns,keys in [('n0',['n0/root']),('n1',['n1/leaf'])]:
        c=CachedStatus(ns);c.apply_full(produce(ns,a[ns].log,keys,now),now);out[ns]=c
    return out

class CachedStatusTests(unittest.TestCase):
    def test_compact_status_rejects_issuance_before_latest_event(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 2)
        authority.append('publish', manifest('n1', 'leaf', []), 2)
        with self.assertRaises(ValueError):
            produce_compact('n1', authority.log, ['n1/leaf'], 1)
        report = produce_compact('n1', authority.log, ['n1/leaf'], 2)
        self.assertEqual(report['body']['issued'], 2)

    def test_full_then_compact_after_unrelated_update(self):
        a=world();c=caches(a)
        a['n1'].append('publish',manifest('n1','other',[]),2)
        c['n1'].apply_compact(produce_compact('n1',a['n1'].log,['n1/leaf'],2),['n1/leaf'],2)
        self.assertTrue(check_cached(c,'n0/root',2)['serve'])

    def test_compact_revocation_denies(self):
        a=world();c=caches(a)
        a['n1'].append('revoke',{'target':'n1/leaf'},2)
        c['n1'].apply_compact(produce_compact('n1',a['n1'].log,['n1/leaf'],2),['n1/leaf'],2)
        self.assertFalse(check_cached(c,'n0/root',2)['serve'])

    def test_fresh_head_renews_unchanged_frontier(self):
        a=world();c=caches(a)
        c['n0'].apply_head(a['n0'].head(10),10)
        c['n1'].apply_head(a['n1'].head(10),10)
        self.assertTrue(check_cached(c,'n0/root',10)['serve'])

    def test_refreshing_one_subset_does_not_advance_another(self):
        a=world();c=caches(a)
        # Cache a second object at the old frontier, then advance only leaf.
        a['n1'].append('publish',manifest('n1','other',[]),1)
        c['n1'].apply_full(produce('n1',a['n1'].log,['n1/other'],1),1)
        a['n1'].append('revoke',{'target':'n1/other'},2)
        c['n1'].apply_compact(produce_compact('n1',a['n1'].log,['n1/leaf'],2),['n1/leaf'],2)
        # The unrelated stale object retains its own frontier rather than
        # inheriting leaf's newer count.
        self.assertLess(c['n1'].objects['n1/other']['count'],
                        c['n1'].objects['n1/leaf']['count'])

    def test_mixed_frontier_closure_fails_closed(self):
        a0,a1=Authority('n0'),Authority('n1')
        a0.append('grant',grant('n0'),0);a1.append('grant',grant('n1'),0)
        a1.append('publish',manifest('n1','a',[]),0)
        a1.append('publish',manifest('n1','b',[]),0)
        a0.append('publish',manifest('n0','root',['n1/a','n1/b']),0)
        c0=CachedStatus('n0');c1=CachedStatus('n1')
        c0.apply_full(produce('n0',a0.log,['n0/root'],1),1)
        c1.apply_full(produce('n1',a1.log,['n1/a','n1/b'],1),1)
        a1.append('publish',manifest('n1','unrelated',[]),2)
        c1.apply_compact(produce_compact('n1',a1.log,['n1/a'],2),['n1/a'],2)
        self.assertEqual(check_cached({'n0':c0,'n1':c1},'n0/root',2)['reason'],
                         'MIXED_FRONTIER')

    def test_commitment_or_key_order_tampering_fails(self):
        a=world();c=caches(a)
        report=produce_compact('n1',a['n1'].log,['n1/leaf'],2)
        bad=deepcopy(report);bad['body']['states'][0]['manifest']='A'*44
        with self.assertRaises(ValueError):c['n1'].apply_compact(bad,['n1/leaf'],2)
        with self.assertRaises(ValueError):c['n1'].apply_compact(report,['n1/other'],2)

    def test_stale_full_report_cannot_roll_back_one_object(self):
        a=world(); c=caches(a)
        old=produce('n1',a['n1'].log,['n1/leaf'],1)
        a['n1'].append('publish',manifest('n1','unrelated',[]),2)
        c['n1'].apply_compact(
            produce_compact('n1',a['n1'].log,['n1/leaf'],2),['n1/leaf'],2)
        before=deepcopy(c['n1'].objects['n1/leaf'])
        with self.assertRaises(ValueError): c['n1'].apply_full(old,2)
        self.assertEqual(c['n1'].objects['n1/leaf'],before)

if __name__=='__main__':unittest.main(verbosity=2)
