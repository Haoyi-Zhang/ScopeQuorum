"""Global unsigned reference predicate, independent of client and producer.

The oracle receives accepted authority histories. It is not a deployable source
of global knowledge. It computes graph closure to a fixed point rather than
replaying certificates or using the producer's indices.
"""
from __future__ import annotations

def truth(histories: dict[str,list[dict]], root: str, now: int,
          lag: int = 0) -> bool:
    records=[e['body'] for log in histories.values() for e in log if e['body']['accepted'] <= now]
    publications={}
    for event in records:
        if event['kind']=='publish':
            m=event['data']['manifest']
            publications.setdefault(m['key'],[]).append((m,event['accepted']))
    reachable={root}
    while True:
        if not reachable <= publications.keys(): return False
        grown=reachable | {d for v in reachable for d in publications[v][0][0]['deps']}
        if grown==reachable: break
        reachable=grown
        if len(reachable)>4096: return False
    for vertex in reachable:
        p=publications[vertex]; first=p[0][0]
        for other,at in p[1:]:
            if other != first and now >= at+lag: return False
        for event in records:
            if now < event['accepted']+lag: continue
            if event['kind']=='revoke' and event['data']['target']==vertex: return False
            if event['kind']=='revoke_cap' and event['data']['target']==first['cap']: return False
    # Leaf-elimination fixed point establishes acyclicity and depth, without DFS.
    distances={}; remaining=set(reachable)
    for _ in range(34):
        eligible=[v for v in remaining if set(publications[v][0][0]['deps']) <= distances.keys()]
        if not eligible: break
        updates={v:max((distances[d]+1 for d in publications[v][0][0]['deps']),default=0) for v in eligible}
        distances.update(updates);remaining.difference_update(eligible)
    return not remaining and distances[root]<=32
