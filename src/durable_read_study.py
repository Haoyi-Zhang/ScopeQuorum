"""Owned two-namespace root reads across durable TCP witness recovery.

The client runs in the coordinator. Four witness processes each hold separate
namespace state files. Logical clock annotations are fixed, not wall-time
performance measurements. No external endpoint or production key is used.
"""
from __future__ import annotations
import argparse, asyncio, json, os, platform
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from codec import commitment, manifest, sign, encode
from fixtures import grant
from model import Authority
from durable_witness_network import DurableWitnessProcessNetwork
from witness_client import WitnessClient
from witness_delta import QUORUM, _scope_id, _projection
from scope_delta import check_scopes, _status

EPSILON, DELTA = 2, 10
WINDOWS = ('before-commit', 'after-temp-fsync', 'after-replace')
KINDS = ('revoke', 'revoke_cap', 'conflict')

async def run_case(root: Path, kind: str, window: str) -> dict:
    if kind not in KINDS or window not in WINDOWS:
        raise ValueError('unknown fixed case')
    authorities = {ns: Authority(ns) for ns in ('n0', 'n1')}
    for ns, authority in authorities.items():
        authority.append('grant', grant(ns), 10)
    authorities['n1'].append('publish', manifest('n1', 'leaf', []), 10)
    authorities['n0'].append('publish', manifest('n0', 'root', ['n1/leaf']), 10)
    authorities['n0'].append('publish', manifest('n0', 'control', []), 10)
    keys_by_ns = {'n0':('n0/control','n0/root'), 'n1':('n1/leaf',)}
    def frontier(ns, issued):
        log=authorities[ns].log
        return {'count':len(log), 'tip':commitment(log[-1]), 'issued':issued}
    client = WitnessClient(['n0', 'n1'], delta=DELTA, epsilon=EPSILON)
    certificates = []
    observations = []
    async with DurableWitnessProcessNetwork(root) as network:
        for ns in authorities:
            await network.configure(ns, ns, faulty=('w0',), clock_epsilon=EPSILON)
            await network.advance(ns, 12)
        initial_pids = dict(network.pids)
        network.blocked = {'w0'}

        async def certify(ns, body, crash=None, require_quorum=True):
            signatures = await network.signatures(ns, body, authorities[ns].log, crash=crash)
            if not require_quorum:
                return signatures
            if len(signatures) < QUORUM:
                raise AssertionError('durable quorum missing')
            certificate = {'body': deepcopy(body), 'authority_signature': sign('authority:'+ns, body),
                           'witnesses': signatures[:QUORUM]}
            certificates.append(certificate)
            return certificate

        for ns, keys in keys_by_ns.items():
            body = {'op':'register', 'ns':ns, 'scope':_scope_id(ns,keys),
                    **frontier(ns,14), 'objects':[_status(authorities[ns].log,k) for k in keys]}
            client.apply(await certify(ns, body), 12)
        stale = WitnessClient.restore(client.snapshot(), namespaces=['n0', 'n1'],
                    delta=DELTA, epsilon=EPSILON, minimum_floors=client.floors)
        if not client.check('n0/root', 12)['serve']:
            raise AssertionError('initial dependency root did not serve')
        old_remote = deepcopy(authorities['n1'].log)
        if kind == 'revoke':
            authorities['n1'].append('revoke', {'target': 'n1/leaf'}, 13)
        elif kind == 'revoke_cap':
            authorities['n1'].append('revoke_cap', {'target': 'cap:n1:0'}, 13)
        else:
            authorities['n1'].append('publish', manifest('n1', 'leaf', [], blob='conflict'), 13)
        for ns in authorities:
            replies = await network.advance(ns, 15, strict=False)
            if any(replies[w] is None or replies[w].get('ok') is not True for w in ('w1','w2','w3')):
                raise AssertionError('honest clock advance failed')
        cache = client.views['n1']
        body = {'op':'renew','ns':'n1','scope':cache.scope,'from':cache.count,
                **frontier('n1',17), **_projection(authorities['n1'].log,keys_by_ns['n1'],cache.count)}
        partial = await certify('n1', body, crash={'w1': window}, require_quorum=False)
        if len(partial) != 2:
            raise AssertionError('crash/withholding failed to prevent quorum')
        crashed=network.processes['w1']
        crashed.join(timeout=2)
        injected_exit=crashed.exitcode
        if crashed.is_alive() or injected_exit != 73:
            raise AssertionError('expected injected process exit 73 did not occur')
        await network.restart('w1')
        if initial_pids['w1'] == network.pids['w1']:
            raise AssertionError('honest witness process was not replaced')
        recovered = (await network.status('n1'))['w1']['summary']
        recovered_state=json.loads(network.state_path('w1','n1').read_text())['state']
        if recovered_state['ns'] != 'n1' or recovered_state['clock_epsilon'] != EPSILON:
            raise AssertionError('recovered namespace/clock policy changed')
        expected_count = len(authorities['n1'].log) if window == 'after-replace' else len(old_remote)
        if recovered['count'] != expected_count:
            raise AssertionError('wrong recovered invalidation frontier')
        certificate = await certify('n1', body)
        client.apply(certificate, 15)
        invalidated = client.check('n0/root', 15)
        control = client.check('n0/control', 15)
        before_expiry = stale.check('n0/root', 17)
        at_expiry = stale.check('n0/root', 18)
        weak_guard = check_scopes(stale.views, 'n0/root', 18, delta=DELTA, epsilon=EPSILON)
        if (invalidated['serve'] or not control['serve'] or not before_expiry['serve']
                or at_expiry['serve'] or at_expiry['reason'] != 'EXPIRED' or not weak_guard['serve']):
            raise AssertionError('root/control/strict-clock distinction failed')
        for ns in authorities:
            replies = await network.advance(ns, 18, strict=False)
            if any(replies[w] is None or replies[w].get('ok') is not True for w in ('w1','w2','w3')):
                raise AssertionError('honest clock advance failed')
        cache = client.views['n0']
        head = {'op':'head','ns':'n0','scope':cache.scope,**frontier('n0',20)}
        client.apply(await certify('n0', head), 18)
        if not client.check('n0/control', 18)['serve'] or client.check('n0/root', 18)['serve']:
            raise AssertionError('refresh did not preserve independent control')
        stale_body = {'op': 'checkpoint', 'ns': 'n1', 'count': len(old_remote),
                      'tip': commitment(old_remote[-1]), 'issued': 20}
        stale_signatures = await network.signatures('n1', stale_body, old_remote)
        if stale_signatures:
            raise AssertionError('transport accepted stale branch')
        direct_rejections=0
        for witness in ('w1','w2','w3'):
            reply=await network.rpc(witness,{'op':'certify','case':'n1','body':stale_body,
                                            'log':old_remote,'crash':None})
            if reply is None or reply.get('reject') is not True or 'signature' in reply:
                raise AssertionError('recovered signer did not directly refuse stale branch')
            direct_rejections+=1
        restored = WitnessClient.restore(client.snapshot(), namespaces=['n0','n1'],
                    delta=DELTA, epsilon=EPSILON, minimum_floors=client.floors)
        if restored.check('n0/root',18)['serve'] or not restored.check('n0/control',18)['serve']:
            raise AssertionError('client transcript replay changed root decisions')
        observations = [
            {'phase':'initial', 'client_clock':12, 'root_serve':True},
            {'phase':'invalidation_after_restart', 'client_clock':15, 'root_serve':False, 'control_serve':True},
            {'phase':'isolated_old_cache_before_expiry', 'client_clock':17, 'root_serve':True},
            {'phase':'isolated_old_cache_strict_expiry', 'client_clock':18, 'root_serve':False,
             'reason':at_expiry['reason'], 'two_epsilon_control_serve':weak_guard['serve']},
            {'phase':'unrelated_refresh', 'client_clock':18, 'root_serve':False, 'control_serve':True},
            {'phase':'client_reconstruction', 'client_clock':18, 'root_serve':False, 'control_serve':True}]
        return {'kind':kind, 'crash_window':window, 'epsilon':EPSILON, 'delta':DELTA,
                'faulty_withholding':'w0', 'crashed_honest':'w1',
                'distinct_initial_processes':len(set(initial_pids.values())),
                'honest_process_replaced':initial_pids['w1'] != network.pids['w1'],
                'injected_exit_code':injected_exit, 'direct_stale_signer_rejections':direct_rejections,
                'partial_signatures':len(partial), 'effective_frontier':body['count'],
                'recovered_frontier_before_retry':recovered['count'],
                'effective_tip':body['tip'], 'stale_branch_signatures':len(stale_signatures),
                'observations':observations, 'certificates':certificates,
                'counters':asdict(network.counters)}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    if os.name != 'posix':
        raise SystemExit('Requires POSIX directory fsync; no portable durability substitute.')
    if not __debug__:
        raise SystemExit('Assertions must remain enabled.')
    args.output.mkdir(parents=True, exist_ok=False)
    rows=[]
    for kind in KINDS:
        for window in WINDOWS:
            label=kind+'-'+window
            row=asyncio.run(run_case(args.output/'state'/label,kind,window))
            (args.output/(label+'.json')).write_bytes(encode(row)+b'\n')
            rows.append(row)
    summary={'cases':len(rows), 'passed':len(rows), 'logical_schedule':True,
             'root_checks':sum(len(r['observations']) for r in rows),
             'guard_difference_controls':sum(r['observations'][3]['two_epsilon_control_serve'] for r in rows),
             'separate_witness_processes':4, 'namespace_instances_per_process':2,
             'platform':platform.platform(), 'python':platform.python_version(),
             'scope':'Owned single-host integration; client is local, certification uses TCP; not a latency or PQ-signature study.'}
    (args.output/'summary.json').write_bytes(encode(summary)+b'\n')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':
    main()
