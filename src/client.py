"""Independent certificate verifier: does not import the producer or the oracle.

All non-monotone decisions are made from complete authenticated namespace
prefixes, not from a list of selected positive publication receipts. The caller,
not the certificate, chooses policy, current time, clock bound, root, and floors.
"""
from __future__ import annotations
from collections import deque
from codec import (NAMESPACES, MAX_EVENTS, authenticated, commitment,
                   natural, ns_of, verify)


def check(certificate: dict, expected_root: str, now: int, *, delta: int = 10,
          epsilon: int = 0, floors: dict[str,int] | None = None,
          policy: str = 'bounded', root_fresh_ablation: bool = False,
          require_all: bool = False) -> dict:
    seen_heads: dict[str,int] = {}
    support: set[str] = set()
    reached: list[str] = []

    def result(reason: str, witness: dict | None = None) -> dict:
        return dict(serve=reason=='SERVE', reason=reason,
                    witness=witness or {}, support=sorted(support),
                    closure=sorted(reached), observed=seen_heads.copy())

    try:
        ns_of(expected_root)
        if (not natural(now) or not natural(delta) or not natural(epsilon) or
                policy not in {'bounded','frontier','immediate'}):
            return result('BAD_POLICY')
        if policy == 'immediate':
            # No online linearizable authority protocol is claimed by this artifact.
            return result('FRESH_AUTHORITY_REQUIRED')
        if (not isinstance(certificate,dict) or
            set(certificate) != {'root','streams','quarantined'} or
            certificate['root'] != expected_root or not isinstance(certificate['streams'],dict) or
            len(certificate['streams']) > len(NAMESPACES) or
            not isinstance(certificate['quarantined'],list)):
            return result('BAD_CERTIFICATE')
        if certificate['quarantined']:
            return result('AUTHORITY_EQUIVOCATION')
        streams=certificate['streams']
        if require_all and set(streams) != set(NAMESPACES):
            return result('MISSING_BARRIER_DOMAIN')
        pubs: dict[str,list[tuple[dict,tuple[str,int]]]] = {}
        tombstones=set(); revoked_caps=set(); issue_times={}
        for ns, stream in streams.items():
            if ns not in NAMESPACES or set(stream) != {'head','events'}:
                return result('BAD_STREAM')
            head=stream['head']; events=stream['events']
            if head is None: return result('MISSING_HEAD',{'namespace':ns})
            h=head['body']
            if (set(head) != {'body','signature'} or
                set(h) != {'ns','count','tip','issued'} or h['ns'] != ns or
                not natural(h['count']) or not natural(h['issued']) or
                h['count'] > MAX_EVENTS or not isinstance(events,list) or
                len(events) != h['count'] or
                not verify('authority:'+ns,h,head['signature'])):
                return result('INCOMPLETE_OR_UNAUTHENTICATED_PREFIX',{'namespace':ns})
            if h['count'] < (floors or {}).get(ns,0):
                return result('ROLLBACK',{'namespace':ns})
            previous=''; accepted=0; epoch=0; grants={}; killed=set()
            for sequence,e in enumerate(events,1):
                if not authenticated(e): return result('BAD_RECEIPT',{'namespace':ns})
                b=e['body']; data=b['data']; kind=b['kind']
                if (b['ns'] != ns or b['seq'] != sequence or b['previous'] != previous or
                    b['accepted'] < accepted or b['accepted'] > h['issued']):
                    return result('BAD_CHAIN',{'namespace':ns,'sequence':sequence})
                previous=commitment(e); accepted=b['accepted']
                if kind == 'grant':
                    if (set(data) != {'cap','publisher','epoch','rights'} or
                        not natural(data['epoch']) or data['epoch'] != epoch or
                        data['cap'] != f'cap:{ns}:{epoch}' or
                        data['publisher'] != f'publisher:{ns}:{epoch}' or
                        data['rights'] != ['publish'] or data['cap'] in grants):
                        return result('INVALID_GRANT')
                    grants[data['cap']]=data
                elif kind == 'transfer':
                    if (set(data) != {'epoch'} or type(data['epoch']) is not int or
                        data['epoch'] != epoch+1): return result('INVALID_TRANSFER')
                    epoch=data['epoch']
                elif kind == 'revoke':
                    if set(data) != {'target'} or ns_of(data['target']) != ns:
                        return result('INVALID_REVOCATION')
                    tombstones.add(data['target'])
                elif kind == 'revoke_cap':
                    if set(data) != {'target'} or data['target'] not in grants:
                        return result('INVALID_REVOCATION')
                    revoked_caps.add(data['target']); killed.add(data['target'])
                elif kind == 'publish':
                    if set(data) != {'manifest','signature'}: return result('BAD_MANIFEST')
                    m=data['manifest']
                    if (set(m) != {'ns','key','deps','epoch','publisher','cap','blob'} or
                        m['ns'] != ns or ns_of(m['key']) != ns or
                        not natural(m['epoch']) or m['epoch'] != epoch or
                        not isinstance(m['deps'],list) or len(m['deps'])>256 or
                        any(not isinstance(dep, str) for dep in m['deps']) or
                        m['deps'] != sorted(m['deps']) or
                        len(m['deps']) != len(set(m['deps'])) or
                        not isinstance(m['blob'],str) or len(m['blob'])>256 or
                        m['cap'] not in grants or m['cap'] in killed or
                        grants[m['cap']]['publisher'] != m['publisher'] or
                        grants[m['cap']]['epoch'] != m['epoch'] or
                        not verify(m['publisher'],m,data['signature'])):
                        return result('BAD_MANIFEST_AUTHORITY')
                    for dep in m['deps']: ns_of(dep)
                    pubs.setdefault(m['key'],[]).append((m,(ns,sequence)))
                else:
                    return result('UNKNOWN_EVENT')
            if previous != h['tip']:
                return result('BAD_TIP',{'namespace':ns})
            seen_heads[ns]=h['count']; issue_times[ns]=h['issued']
        # Breadth-first traversal gives a shortest dependency-path witness.
        queue=deque([expected_root]); parent={expected_root:None}; graph={}
        def witness_path(artifact):
            path=[]
            while artifact is not None:
                path.append(artifact);artifact=parent[artifact]
            return list(reversed(path))
        visited=set()
        while queue:
            artifact=queue.popleft()
            visited.add(artifact); reached.append(artifact)
            if len(visited)>4096: return result('CLOSURE_BOUND')
            ns=ns_of(artifact); support.add(ns)
            if ns not in streams:
                return result('MISSING_NAMESPACE',{'path':witness_path(artifact)})
            occurrences=pubs.get(artifact,[])
            if not occurrences:
                return result('MISSING_DEPENDENCY',{'path':witness_path(artifact),'frontier':seen_heads.copy()})
            m,location=occurrences[0]
            different=next(((other,loc) for other,loc in occurrences if other != m),None)
            if different:
                return result('EQUIVOCATION',{'path':witness_path(artifact),'pair':[list(location),list(different[1])]})
            if artifact in tombstones:
                return result('REVOKED',{'path':witness_path(artifact)})
            if m['cap'] in revoked_caps:
                return result('CAPABILITY_REVOKED',{'path':witness_path(artifact)})
            graph[artifact]=m['deps']
            for dep in sorted(m['deps']):
                if dep not in parent:
                    parent[dep]=artifact;queue.append(dep)
            # One predecessor per discovered key, not a full copied path per edge.
            if len(parent)>4096: return result('CLOSURE_BOUND')
        # Iterative DFS avoids recursion-dependent acceptance; longest path is
        # separately computed on the resulting topological order.
        gray=set(); black=set(); topo=[]; stack=[(expected_root,False)]
        while stack:
            vertex,leaving=stack.pop()
            if leaving:
                gray.remove(vertex); black.add(vertex); topo.append(vertex); continue
            if vertex in gray: return result('DEPENDENCY_CYCLE',{'vertex':vertex})
            if vertex in black: continue
            gray.add(vertex); stack.append((vertex,True))
            for child in reversed(graph[vertex]):
                if child in gray: return result('DEPENDENCY_CYCLE',{'vertex':child})
                if child not in black: stack.append((child,False))
        depth={}
        for vertex in topo:
            depth[vertex]=max((depth[d]+1 for d in graph[vertex]),default=0)
        if depth[expected_root] > 32: return result('DEPTH_BOUND')
        fresh_domains=set(streams) if require_all else support
        if root_fresh_ablation: fresh_domains={ns_of(expected_root)}
        if policy == 'bounded':
            for ns in sorted(fresh_domains):
                issued=issue_times[ns]
                if issued > now + 2*epsilon:
                    return result('FUTURE_CHECKPOINT',{'namespace':ns})
                # Strict upper endpoint: age==delta is no longer admissible.
                if now-issued+2*epsilon >= delta:
                    return result('EXPIRED',{'namespace':ns})
        return result('SERVE')
    except (KeyError,TypeError,ValueError,IndexError,RecursionError):
        return result('MALFORMED')
