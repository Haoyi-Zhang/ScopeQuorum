"""Benign, locally signed fixtures; no external services or production keys."""
from __future__ import annotations
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from codec import commitment, manifest, make_head, sign, signed_receipt
from model import Authority, Replica
from fixtures import grant, graph
from client import check
from oracle import truth
from status_reference import produce, check_status
from transport import Node


def setup_world():
    authorities = {n: Authority(n) for n in ['n0', 'n1']}
    for n,a in authorities.items(): a.append('grant', grant(n), 0)
    authorities['n1'].append('publish', manifest('n1','leaf',[]),0)
    authorities['n0'].append('publish', manifest('n0','root',['n1/leaf']),0)
    return authorities


def certificate(authorities, now=1, root='n0/root'):
    replica=Replica()
    for a in authorities.values():
        for e in a.log: replica.ingest(e)
        replica.cache_head(a.head(now))
    return replica.certificate(root)


def replace_chain(cert, namespace, edits):
    """Re-sign intentionally inadmissible toy receipts to test semantic checks."""
    c=deepcopy(cert);events=c['streams'][namespace]['events'];previous=''
    for index,e in enumerate(events):
        b=deepcopy(e['body'])
        if index in edits: edits[index](b)
        b['previous']=previous
        events[index]={'body':b,'signature':sign('authority:'+namespace,b)}
        previous=commitment(events[index])
    c['streams'][namespace]['head']=make_head(namespace,events,1)
    return c


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.a=setup_world();self.c=certificate(self.a)

    def test_positive(self):
        self.assertTrue(check(self.c,'n0/root',2)['serve'])
        self.assertTrue(truth({n:a.log for n,a in self.a.items()},'n0/root',2))

    def test_root_substitution(self):
        self.assertFalse(check(self.c,'n0/other',2)['serve'])

    def test_expiry_strict_endpoint(self):
        self.assertTrue(check(self.c,'n0/root',10)['serve'])
        self.assertEqual(check(self.c,'n0/root',11)['reason'],'EXPIRED')

    def test_clock_error_guard(self):
        self.assertTrue(check(self.c,'n0/root',8,epsilon=1)['serve'])
        self.assertEqual(check(self.c,'n0/root',9,epsilon=1)['reason'],'EXPIRED')

    def test_future_head(self):
        self.assertEqual(check(certificate(self.a,now=10),'n0/root',1)['reason'],'FUTURE_CHECKPOINT')

    def test_authority_rejects_head_before_last_accepted_event(self):
        self.a['n1'].append('revoke', {'target': 'n1/leaf'}, 3)
        with self.assertRaises(ValueError):
            self.a['n1'].head(2)

    def test_full_status_rejects_issuance_before_latest_event(self):
        authority = Authority('n1')
        authority.append('grant', grant('n1'), 2)
        authority.append('publish', manifest('n1', 'leaf', []), 2)
        with self.assertRaises(ValueError):
            produce('n1', authority.log, ['n1/leaf'], 1)
        report = produce('n1', authority.log, ['n1/leaf'], 2)
        self.assertEqual(report['body']['issued'], 2)

    def test_client_rejects_event_accepted_after_head_issuance(self):
        def move_publication_after_head(body):
            body['accepted'] = 2
        c = replace_chain(self.c, 'n1', {1: move_publication_after_head})
        self.assertEqual(check(c, 'n0/root', 2)['reason'], 'BAD_CHAIN')

    def test_historical_frontier_is_not_freshness(self):
        self.a['n1'].append('revoke',{'target':'n1/leaf'},3)
        self.assertTrue(check(self.c,'n0/root',100,policy='frontier')['serve'])
        self.assertFalse(truth({n:a.log for n,a in self.a.items()},'n0/root',100))

    def test_immediate_policy_abstains(self):
        self.assertEqual(check(self.c,'n0/root',2,policy='immediate')['reason'],'FRESH_AUTHORITY_REQUIRED')

    def test_wrong_head_signature(self):
        c=deepcopy(self.c);c['streams']['n1']['head']['signature']='A'*88
        self.assertFalse(check(c,'n0/root',2)['serve'])

    def test_wrong_receipt_signature(self):
        c=deepcopy(self.c);c['streams']['n1']['events'][1]['signature']='A'*88
        self.assertEqual(check(c,'n0/root',2)['reason'],'BAD_RECEIPT')

    def test_prefix_omission(self):
        c=deepcopy(self.c);c['streams']['n1']['events'].pop(0)
        self.assertFalse(check(c,'n0/root',2)['serve'])

    def test_namespace_omission(self):
        c=deepcopy(self.c);c['streams'].pop('n1')
        self.assertEqual(check(c,'n0/root',2)['reason'],'MISSING_NAMESPACE')

    def test_wrong_chain(self):
        c=deepcopy(self.c);e=c['streams']['n1']['events'][1]
        e['body']['previous']='';e['signature']=sign('authority:n1',e['body'])
        c['streams']['n1']['head']=make_head('n1',c['streams']['n1']['events'],1)
        self.assertEqual(check(c,'n0/root',2)['reason'],'BAD_CHAIN')

    def test_wrong_tip(self):
        c=deepcopy(self.c);h=c['streams']['n1']['head'];h['body']['tip']=''
        h['signature']=sign('authority:n1',h['body'])
        self.assertEqual(check(c,'n0/root',2)['reason'],'BAD_TIP')

    def test_boolean_count(self):
        c=deepcopy(self.c);h=c['streams']['n1']['head'];h['body']['count']=True
        h['signature']=sign('authority:n1',h['body'])
        self.assertFalse(check(c,'n0/root',2)['serve'])

    def test_boolean_grant_epoch(self):
        c=replace_chain(self.c,'n1',{0:lambda b:b['data'].update(epoch=False)})
        self.assertEqual(check(c,'n0/root',2)['reason'],'INVALID_GRANT')

    def test_bad_publisher_signature(self):
        c=replace_chain(self.c,'n1',{1:lambda b:b['data'].update(signature='A'*88)})
        self.assertEqual(check(c,'n0/root',2)['reason'],'BAD_MANIFEST_AUTHORITY')

    def test_authority_rejects_noncanonical_dependency_order(self):
        authority = Authority('n0')
        authority.append('grant', grant('n0'), 0)
        publication = manifest('n0', 'unordered', ['n1/a', 'n1/z'])
        publication['manifest']['deps'] = ['n1/z', 'n1/a']
        publication['signature'] = sign(
            publication['manifest']['publisher'], publication['manifest'])
        with self.assertRaises(ValueError):
            authority.append('publish', publication, 0)

    def test_client_rejects_noncanonical_dependency_order(self):
        def make_noncanonical(body):
            manifest_body = body['data']['manifest']
            manifest_body['deps'] = ['n1/z', 'n1/leaf']
            body['data']['signature'] = sign(
                manifest_body['publisher'], manifest_body)
        c = replace_chain(self.c, 'n0', {1: make_noncanonical})
        self.assertEqual(
            check(c, 'n0/root', 2)['reason'], 'BAD_MANIFEST_AUTHORITY')

    def test_cross_namespace_revoke(self):
        self.a['n1'].append('revoke',{'target':'n1/leaf'},1)
        c=certificate(self.a)
        c=replace_chain(c,'n1',{2:lambda b:b['data'].update(target='n0/root')})
        self.assertEqual(check(c,'n0/root',2)['reason'],'INVALID_REVOCATION')

    def test_artifact_revocation_is_sticky_under_replay(self):
        original=deepcopy(self.a['n1'].log[1]['body']['data'])
        self.a['n1'].append('revoke',{'target':'n1/leaf'},1)
        self.a['n1'].append('publish',original,1)
        self.assertEqual(check(certificate(self.a),'n0/root',2)['reason'],'REVOKED')

    def test_capability_revocation(self):
        self.a['n1'].append('revoke_cap',{'target':'cap:n1:0'},1)
        self.assertEqual(check(certificate(self.a),'n0/root',2)['reason'],'CAPABILITY_REVOKED')
        with self.assertRaises(ValueError):self.a['n1'].append('publish',manifest('n1','later',[]),2)

    def test_equivocation_pair(self):
        self.a['n1'].append('publish',manifest('n1','leaf',[],blob='another-object'),1)
        result=check(certificate(self.a),'n0/root',2)
        self.assertEqual(result['reason'],'EQUIVOCATION')
        self.assertEqual(result['witness']['pair'],[['n1',2],['n1',3]])

    def test_identical_duplicate_is_not_equivocation(self):
        self.a['n1'].append('publish',deepcopy(self.a['n1'].log[1]['body']['data']),1)
        self.assertTrue(check(certificate(self.a),'n0/root',2)['serve'])

    def test_transfer_keeps_old_immutable_publication(self):
        self.a['n1'].append('transfer',{'epoch':1},1)
        self.a['n1'].append('grant',grant('n1',1),1)
        self.assertTrue(check(certificate(self.a),'n0/root',2)['serve'])
        with self.assertRaises(ValueError):self.a['n1'].append('publish',manifest('n1','old-right',[]),1)
        self.a['n1'].append('publish',manifest('n1','new-right',[],epoch=1),1)
        self.assertTrue(check(certificate(self.a,root='n1/new-right'),'n1/new-right',2)['serve'])

    def test_missing_shortest_path(self):
        self.a['n0'].append('publish',manifest('n0','long',['n1/missing']),1)
        self.a['n0'].append('publish',manifest('n0','start',['n0/long','n1/missing']),1)
        result=check(certificate(self.a,root='n0/start'),'n0/start',2)
        self.assertEqual(result['reason'],'MISSING_DEPENDENCY')
        self.assertEqual(result['witness']['path'],['n0/start','n1/missing'])

    def test_dependency_cycle(self):
        self.a['n0'].append('publish',manifest('n0','loop',['n0/loop']),1)
        self.assertEqual(check(certificate(self.a,root='n0/loop'),'n0/loop',2)['reason'],'DEPENDENCY_CYCLE')

    def test_diamond_is_not_cycle(self):
        self.a['n0'].append('publish',manifest('n0','left',['n1/leaf']),1)
        self.a['n0'].append('publish',manifest('n0','right',['n1/leaf']),1)
        self.a['n0'].append('publish',manifest('n0','diamond',['n0/left','n0/right']),1)
        self.assertTrue(check(certificate(self.a,root='n0/diamond'),'n0/diamond',2)['serve'])

    def test_depth_32_and_33(self):
        a={'n0':Authority('n0')};a['n0'].append('grant',grant('n0'),0)
        for i in range(34):a['n0'].append('publish',manifest('n0',f'd{i}',[] if i==0 else [f'n0/d{i-1}']),0)
        self.assertTrue(check(certificate(a,root='n0/d32'),'n0/d32',2)['serve'])
        self.assertEqual(check(certificate(a,root='n0/d33'),'n0/d33',2)['reason'],'DEPTH_BOUND')

    def test_client_floor_after_rollback(self):
        self.assertEqual(check(self.c,'n0/root',2,floors={'n1':3})['reason'],'ROLLBACK')

    def test_denial_still_pins_authenticated_count(self):
        self.a['n1'].append('revoke',{'target':'n1/leaf'},1)
        out=check(certificate(self.a),'n0/root',2)
        self.assertEqual(out['observed']['n1'],3)
        self.assertFalse(out['serve'])

    def test_root_only_freshness_negative_control(self):
        c=deepcopy(self.c);c['streams']['n0']['head']=self.a['n0'].head(14)
        self.assertTrue(check(c,'n0/root',14,root_fresh_ablation=True)['serve'])
        self.assertEqual(check(c,'n0/root',14)['reason'],'EXPIRED')

    def test_unrelated_namespace_does_not_block(self):
        self.assertTrue(check(self.c,'n0/root',2)['serve'])
        self.assertEqual(check(self.c,'n0/root',2,require_all=True)['reason'],'MISSING_BARRIER_DOMAIN')

    def test_out_of_order_and_duplicate_delivery(self):
        events=[e for a in self.a.values() for e in a.log]
        r=Replica()
        for e in reversed(events):self.assertTrue(r.ingest(e))
        for e in events:self.assertTrue(r.ingest(e))
        for a in self.a.values():r.cache_head(a.head(1))
        self.assertTrue(check(r.certificate('n0/root'),'n0/root',2)['serve'])
        self.assertEqual(r.replayed,4)

    def test_holes_are_not_filled_by_high_sequence(self):
        r=Replica();r.ingest(self.a['n1'].log[1]);r.cache_head(self.a['n1'].head(1))
        self.assertEqual(r.prefix('n1'),[])
        self.assertFalse(check(r.certificate('n1/leaf'),'n1/leaf',2)['serve'])

    def test_conflicting_authority_receipt_quarantines(self):
        r=Replica();r.ingest(self.a['n1'].log[0])
        altered=signed_receipt('n1',1,'',0,'grant',{**grant('n1'),'rights':[]})
        self.assertFalse(r.ingest(altered));self.assertIn('n1',r.quarantine)

    def test_malformed_inputs_fail_closed(self):
        samples=[None,[],{},'not a certificate',{'root':'n0/root','streams':[], 'quarantined':[]}]
        for value in samples:
            with self.subTest(value=value):self.assertFalse(check(value,'n0/root',2)['serve'])
        for now in [None,False,-1,'2']:
            with self.subTest(now=now):self.assertFalse(check(self.c,'n0/root',now)['serve'])

    def test_exact_locked_graph_projection(self):
        p=Path(__file__).resolve().parents[1]/'data/lock_projection.json'
        d=json.loads(p.read_text());self.assertEqual(len(d['packages']),61)
        self.assertEqual(sum(len(x['dependencies']) for x in d['packages']),131)
        for span in [1,3,6]:
            g,root,dim=graph('public-lock',span)
            self.assertEqual(dim['closure_nodes'],62);self.assertEqual(dim['edges'],132)
            self.assertIn(root,g)

    def test_status_baseline_matches_prefix_predicate(self):
        for action in ['none','revoke','cap','equivocate','transfer']:
            a=setup_world()
            if action=='revoke':a['n1'].append('revoke',{'target':'n1/leaf'},1)
            if action=='cap':a['n1'].append('revoke_cap',{'target':'cap:n1:0'},1)
            if action=='equivocate':a['n1'].append('publish',manifest('n1','leaf',[],blob='other'),1)
            if action=='transfer':a['n1'].append('transfer',{'epoch':1},1)
            cert={'n0':produce('n0',a['n0'].log,['n0/root'],1),'n1':produce('n1',a['n1'].log,['n1/leaf'],1)}
            with self.subTest(action=action):
                self.assertEqual(check_status(cert,'n0/root',2,{})['serve'],check(certificate(a),'n0/root',2)['serve'])

    def test_rpc_cannot_choose_issuer_clock(self):
        node=Node(0)
        for op in ['append','snapshot','status']:
            request={'op':op,'ns':'n0','now':999,'kind':'grant','data':grant('n0'),'keys':['n0/root']}
            self.assertEqual(node.dispatch(request),{'error':'CLOCK_MISMATCH'})
        self.assertEqual(node.authorities['n0'].log,[])
        self.assertEqual(node.dispatch({'op':'advance','now':999}),{'error':'UNKNOWN_OPERATION'})

    def test_local_clock_is_monotone_and_signs_checkpoint(self):
        node=Node(0);node.advance(5)
        response=node.dispatch({'op':'snapshot','ns':'n0','now':5})
        self.assertEqual(response['heads'][0]['body']['issued'],5)
        with self.assertRaises(ValueError):node.advance(4)
        with self.assertRaises(ValueError):node.advance(True)


if __name__=='__main__':unittest.main(verbosity=2)
