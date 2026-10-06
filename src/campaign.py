"""Bounded six-replica experiments. All external inputs are read-only metadata.

Each campaign runs all seven policies sequentially from fresh stores against the
same immutable graph and authority operations. Network timing is measured but
logical event time, not wall time, controls the finite freshness experiment.
"""
from __future__ import annotations
import asyncio
import json
import sys
try:
    import resource
except ImportError:
    resource = None
import time
from pathlib import Path
from codec import NAMESPACES, encode,manifest,ns_of
from model import Authority
from transport import Network,owner
from fixtures import graph,grant,POLICIES
from client import check
from oracle import truth
from status_reference import check_status

async def append(net,ns,kind,data,now,histories):
    net.advance(now)
    answer=await net.rpc(owner(ns),owner(ns),dict(op='append',ns=ns,kind=kind,data=data,now=now))
    if 'event' in answer: histories[ns].append(answer['event'])
    return answer

async def refresh(net:Network, root:str, policy:str, now:int):
    refreshed=set()
    for _ in range(34):
        if policy=='all-namespaces': needed=set(NAMESPACES)
        elif policy=='root-only': needed={ns_of(root)}
        else:
            discovery=await net.rpc(0,0,{'op':'discover','root':root})
            needed=set(discovery['support'])
        new=needed-refreshed
        if not new: break
        for ns in sorted(new):
            inv=await net.rpc(0,0,{'op':'inventory'}); start=inv['counts'][ns]
            for _ in range(33):
                answer=await net.rpc(0,owner(ns),dict(op='snapshot',ns=ns,start=start,now=now,batch=128))
                if answer is None: break
                delivered=await net.rpc(0,0,{'op':'deliver',**answer})
                start+=len(answer['events'])
                if start>=answer['heads'][0]['body']['count']: break
            else: raise RuntimeError('snapshot fetch bound')
        refreshed |= new
    else: raise RuntimeError('discovery round bound')


def legacy(certificate:dict, policy:str) -> dict:
    # Reference policies implemented here, not replicas of upstream software.
    publications={}; revoked=set(); revoked_caps=set()
    for stream in certificate['streams'].values():
        for event in stream['events']:
            b=event['body']; d=b['data']
            if b['kind']=='publish': publications[d['manifest']['key']]=d['manifest']
            elif b['kind']=='revoke': revoked.add(d['target'])
            elif b['kind']=='revoke_cap':revoked_caps.add(d['target'])
    root=certificate['root']; keep=root in publications
    if keep and policy=='signed-index':
        keep=root not in revoked and publications[root]['cap'] not in revoked_caps
    if keep and policy=='transparency-only':
        pending=[root];seen=set()
        while pending:
            v=pending.pop()
            if v in seen:continue
            seen.add(v)
            if v not in publications: keep=False;break
            pending.extend(publications[v]['deps'])
    return {'serve':keep,'reason':'SERVE' if keep else 'MISSING_OR_ROOT_REVOKED','observed':{},'support':[],'closure':[],'witness':{}}

async def query(net,root,policy,now,floors,histories,phase):
    net.advance(now)
    b0=net.bytes;m0=net.messages;d0=net.drops;start=time.perf_counter()
    if policy=='status-proof':
        info=await net.rpc(0,0,{'op':'discover','root':root})
        needed={}
        for k in info['closure']:needed.setdefault(ns_of(k),[]).append(k)
        if not hasattr(net,'status_cache'):net.status_cache={}
        cert={}
        for ns,keys in sorted(needed.items()):
            reply=await net.rpc(0,owner(ns),{'op':'status','ns':ns,'keys':keys,'now':now})
            if reply is not None:net.status_cache[(ns,tuple(keys))]=reply
            report=net.status_cache.get((ns,tuple(keys)))
            if report is not None:cert[ns]=report
    else:
        if policy in {'scoped','all-namespaces','root-only'}:
            await refresh(net,root,policy,now)
        cert=await net.rpc(0,0,{'op':'certificate','root':root,'full':policy=='all-namespaces'})
    certify_start=time.perf_counter()
    if policy=='status-proof':
        verdict=check_status(cert,root,now,floors)
        for ns,count in verdict['observed'].items():floors[ns]=max(floors.get(ns,0),count)
    elif policy in {'scoped','all-namespaces','root-only'}:
        verdict=check(cert,root,now,floors=floors,require_all=policy=='all-namespaces',root_fresh_ablation=policy=='root-only')
        for ns,count in verdict['observed'].items(): floors[ns]=max(floors.get(ns,0),count)
    else: verdict=legacy(cert,policy)
    verify_ms=(time.perf_counter()-certify_start)*1000
    return dict(phase=phase,root=root,logical_time=now,serve=verdict['serve'],reason=verdict['reason'],
                immediate_truth=truth(histories,root,now),bounded_truth=truth(histories,root,now,lag=10),
                bounded_violation=verdict['serve'] and not truth(histories,root,now,lag=10),
                immediate_violation=verdict['serve'] and not truth(histories,root,now),
                certificate_bytes=len(encode(cert)),messages=net.messages-m0,bytes=net.bytes-b0,
                drops=net.drops-d0,elapsed_ms=(time.perf_counter()-start)*1000,
                verify_ms=verify_ms,support_count=len(verdict['support']),
                closure_count=len(verdict['closure']),witness=verdict['witness'])

async def run_policy(case:dict,policy:str,batch:int=128) -> dict:
    started=time.perf_counter();cpu=time.process_time()
    g,root,dimensions=graph(case['family'],case['span']); target=dimensions['target'];target_ns=ns_of(target)
    histories={n:[] for n in NAMESPACES};queries=[];floors={};rejected=0;probes=[]
    async with Network() as net:
        for ns in NAMESPACES:
            ans=await append(net,ns,'grant',grant(ns),0,histories);assert 'event' in ans
        # Concurrent namespaces have no imposed shared log; this deterministic
        # order only fixes the controller's input schedule for reproduction.
        for artifact,deps in sorted(g.items()):
            ns,name=artifact.split('/',1)
            ans=await append(net,ns,'publish',manifest(ns,name,deps),0,histories);assert 'event' in ans
        for _ in range(12):await net.gossip(batch)
        expected={n:len(h) for n,h in histories.items()}
        for r in range(6):
            inv=await net.rpc(r,r,{'op':'inventory'});assert inv['counts']==expected,'initial convergence failed'
        queries.append(await query(net,root,policy,1,floors,histories,'base'))
        # Capture neutral base receipts in memory for the explicit replay fault.
        oldcert=await net.rpc(0,0,{'op':'certificate','root':root,'full':True})
        s=case['scenario']
        if s=='rollback':
            await append(net,target_ns,'revoke',{'target':target},2,histories)
            for _ in range(6):await net.gossip(batch)
            # Each policy must establish any client floor using its OWN evidence.
            seen=await query(net,root,policy,2,floors,histories,'pin-before-rollback')
            probes.append(seen)
        net.isolate(5 if s=='partition' else 0)
        if s=='revocation':
            await append(net,target_ns,'revoke',{'target':target},3,histories)
        elif s=='grant_revocation':
            await append(net,target_ns,'revoke_cap',{'target':f'cap:{target_ns}:0'},3,histories)
        elif s=='transfer':
            await append(net,target_ns,'transfer',{'epoch':1},3,histories)
            await append(net,target_ns,'grant',grant(target_ns,1),3,histories)
            bad=manifest(target_ns,'old-grant-publication',[],epoch=0)
            rejected+=int('error' in await append(net,target_ns,'publish',bad,3,histories))
            good=manifest(target_ns,'new-owner-publication',[],epoch=1)
            await append(net,target_ns,'publish',good,3,histories)
        elif s=='equivocation':
            first=next(e['body']['data']['manifest'] for e in histories[target_ns]
                       if e['body']['kind']=='publish' and e['body']['data']['manifest']['key']==target)
            altered=manifest(target_ns,target.split('/',1)[1],first['deps'],blob='different-object')
            await append(net,target_ns,'publish',altered,3,histories)
        elif s=='missing':
            badroot='n0/missing-bundle'
            await append(net,'n0','publish',manifest('n0','missing-bundle',[root,target_ns+'/absent']),3,histories)
            root=badroot
        elif s=='malformed':
            bad=manifest('n0','bad-signature',[]);bad['manifest']['blob']='tampered-after-signing'
            rejected+=int('error' in await append(net,'n0','publish',bad,3,histories))
            await append(net,'n0','publish',manifest('n0','cycle-a',['n0/cycle-b']),3,histories)
            await append(net,'n0','publish',manifest('n0','cycle-b',['n0/cycle-a']),3,histories)
            root='n0/cycle-a'
        elif s=='rollback':
            await net.rpc(0,0,{'op':'rollback'})
            for stream in oldcert['streams'].values():
                events=stream['events']
                for at in range(0,len(events),128):
                    await net.rpc(0,0,{'op':'deliver','events':events[at:at+128],'heads':[]})
                await net.rpc(0,0,{'op':'deliver','events':[],'heads':[stream['head']]})
        queries.append(await query(net,root,policy,4,floors,histories,'partition-young'))
        queries.append(await query(net,root,policy,14,floors,histories,'partition-expired'))
        extra={'partition':0,'revocation':1,'grant_revocation':1,
               'transfer':3,'equivocation':1,'missing':1,'malformed':2,'rollback':1}[s]
        assert sum(map(len,histories.values()))==len(NAMESPACES)+len(g)+extra,'fault injection was not accepted'
        assert rejected==int(s in {'transfer','malformed'}),'negative admission control did not reject'
        net.blocked.clear();recovery=None
        for step in range(1,13):
            await net.gossip(batch)
            counts=[]
            for r in range(6):
                counts.append((await net.rpc(r,r,{'op':'inventory'}))['counts'])
            if recovery is None and all(c=={n:len(h) for n,h in histories.items()} for c in counts):recovery=step
        queries.append(await query(net,root,policy,27,floors,histories,'recovered'))
        if s=='transfer':
            for name in ['old-grant-publication','new-owner-publication']:
                probes.append(await query(net,target_ns+'/'+name,policy,27,floors,histories,'transfer-probe'))
        assert recovery is not None,'recovery bound exceeded'
        if s=='transfer':
            assert len(probes)==2 and not probes[0]['serve'] and probes[1]['serve'],'transfer probe mismatch'
        if policy in {'scoped','all-namespaces','status-proof'}:
            assert not any(q['bounded_violation'] for q in queries+probes),'soundness failure'
        stats=[await net.rpc(i,i,{'op':'stats'}) for i in range(6)]
        # The complete neutral operation schedule is generated from case fields;
        # raw transport trace retains ordering, sizes, drops and timings, not keys.
        return dict(policy=policy,dimensions=dimensions,queries=queries,probes=probes,
                    rejected_publications=rejected,recovery_rounds=recovery,
                    events=sum(map(len,histories.values())),messages=net.messages,bytes=net.bytes,
                    drops=net.drops,stats=stats,transport=net.log,
                    elapsed_seconds=time.perf_counter()-started,cpu_seconds=time.process_time()-cpu,
                    peak_rss_kib=(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                                  if sys.platform.startswith('linux') and resource else None))

async def run_case(case:dict,policies=POLICIES,batch:int=128) -> dict:
    result={**case,'replicas':6,'workers':1,'batch_events':batch,'delta_ticks':10,'epsilon_ticks':0,'policies':[]}
    for policy in policies:
        mark=time.perf_counter()
        print(case['case'], policy, 'start', flush=True)
        result['policies'].append(await run_policy(case,policy,batch))
        print(case['case'], policy, 'done', round(time.perf_counter()-mark,3), flush=True)
    return result
