"""Stronger honest-issuer baseline: signed, batched per-object status assertions.

This is NOT a WAVE implementation. It deliberately uses the SAME honest
namespace-authority assumption as the prefix protocol. Its authority computes
object status; its client need not replay complete namespace histories. It has
no Byzantine-storage/nonexistence proof claim or historical-prefix audit claim.
"""
from __future__ import annotations
from codec import issuance_covers, ns_of,sign,verify,natural

def produce(ns:str,log:list[dict],keys:list[str],now:int)->dict:
    if len(keys)>256 or len(keys)!=len(set(keys)) or any(ns_of(k)!=ns for k in keys):
        raise ValueError('status request bound')
    if not issuance_covers(log, now):
        raise ValueError('status time precedes accepted frontier')
    objects=[]
    for key in keys:
        ms=[e['body']['data']['manifest'] for e in log if e['body']['kind']=='publish' and e['body']['data']['manifest']['key']==key]
        m=ms[0] if ms else None
        valid=bool(ms) and all(other==m for other in ms)
        for e in log:
            b=e['body']
            if b['kind']=='revoke' and b['data']['target']==key: valid=False
            if m and b['kind']=='revoke_cap' and b['data']['target']==m['cap']:valid=False
        objects.append({'key':key,'manifest':m,'valid':valid})
    body={'ns':ns,'count':len(log),'issued':now,'objects':objects}
    return {'body':body,'signature':sign('authority:'+ns,body)}

def check_status(cert:dict,root:str,now:int,floors:dict,delta:int=10)->dict:
    observed={}; support=set(); reached=[]
    def result(reason):
        return dict(serve=reason=='SERVE',reason=reason,observed=observed,support=sorted(support),closure=reached,witness={})
    try:
        objects={}
        for report in cert.values():
            b=report['body'];ns=b['ns']
            if set(b)!={'ns','count','issued','objects'} or not natural(b['count']) or not natural(b['issued']) or not verify('authority:'+ns,b,report['signature']):return result('BAD_STATUS')
            if b['count']<floors.get(ns,0):return result('ROLLBACK')
            observed[ns]=b['count']
            if b['issued']>now or now-b['issued']>=delta:return result('EXPIRED')
            for o in b['objects']:
                if ns_of(o['key'])!=ns or o['key'] in objects:return result('BAD_STATUS')
                if o['manifest'] and o['manifest']['key']!=o['key']:return result('BAD_STATUS')
                objects[o['key']]=o
        pending=[root];seen=set();deps={}
        while pending:
            k=pending.pop()
            if k in seen:continue
            seen.add(k);reached.append(k);support.add(ns_of(k))
            if len(seen)>4096:return result('BOUND')
            if k not in objects or objects[k]['valid'] is not True:return result('INVALID_OR_MISSING_STATUS')
            m=objects[k]['manifest']
            if not m:return result('INVALID_OR_MISSING_STATUS')
            deps[k]=m['deps'];pending.extend(m['deps'])
        left=set(seen);depth={}
        for _ in range(34):
            ready={v for v in left if set(deps[v])<=depth.keys()}
            if not ready:break
            update={v:max((depth[d]+1 for d in deps[v]),default=0) for v in ready}
            left-=ready;depth.update(update)
        return result('SERVE' if not left and depth[root]<=32 else 'CYCLE_OR_DEPTH')
    except (KeyError,TypeError,ValueError):return result('BAD_STATUS')
