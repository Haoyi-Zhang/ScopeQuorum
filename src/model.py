"""Registry producer, honest namespace issuers, and independently stored replicas."""
from __future__ import annotations
from collections import deque
from copy import deepcopy
from codec import (NAMESPACES, MAX_EVENTS, authenticated, commitment, make_head,
                   manifest, natural, ns_of, signed_receipt, verify)

class Authority:
    """Single honest sequencer per namespace; no leader failover or consensus claim."""
    def __init__(self, ns: str):
        if ns not in NAMESPACES:
            raise ValueError('unknown namespace')
        self.ns = ns
        self.log: list[dict] = []
        self.epoch = 0
        self.caps: dict[str,dict] = {}
        self.revoked_caps: set[str] = set()

    def append(self, kind: str, data: dict, now: int) -> dict:
        if not natural(now) or len(self.log) >= MAX_EVENTS:
            raise ValueError('admission bound')
        if self.log and now < self.log[-1]['body']['accepted']:
            raise ValueError('clock moved backwards')
        ns = self.ns
        if kind == 'grant':
            if (set(data) != {'cap','publisher','epoch','rights'} or
                not natural(data['epoch']) or data['epoch'] != self.epoch or
                data['cap'] != f'cap:{ns}:{self.epoch}' or
                data['publisher'] != f'publisher:{ns}:{self.epoch}' or
                data['rights'] != ['publish'] or data['cap'] in self.caps):
                raise ValueError('invalid capability')
        elif kind == 'publish':
            if set(data) != {'manifest','signature'}:
                raise ValueError('invalid publication fields')
            m = data['manifest']
            if (set(m) != {'ns','key','deps','epoch','publisher','cap','blob'} or
                m['ns'] != ns or ns_of(m['key']) != ns or
                not natural(m['epoch']) or m['epoch'] != self.epoch or
                not isinstance(m['deps'],list) or len(m['deps']) > 256 or
                any(not isinstance(dep, str) for dep in m['deps']) or
                m['deps'] != sorted(m['deps']) or
                len(m['deps']) != len(set(m['deps'])) or
                not isinstance(m['blob'],str) or len(m['blob']) > 256 or
                m['cap'] not in self.caps or m['cap'] in self.revoked_caps or
                self.caps[m['cap']]['publisher'] != m['publisher'] or
                self.caps[m['cap']]['epoch'] != m['epoch'] or
                not verify(m['publisher'], m, data['signature'])):
                raise ValueError('publication lacks active authority')
            for d in m['deps']:
                ns_of(d)
        elif kind == 'transfer':
            if set(data) != {'epoch'} or type(data['epoch']) is not int or data['epoch'] != self.epoch + 1:
                raise ValueError('invalid transfer')
        elif kind == 'revoke':
            if set(data) != {'target'} or ns_of(data['target']) != ns:
                raise ValueError('cross-namespace revocation')
        elif kind == 'revoke_cap':
            if set(data) != {'target'} or data['target'] not in self.caps:
                raise ValueError('unknown capability')
        else:
            raise ValueError('unknown event kind')
        e = signed_receipt(ns, len(self.log)+1,
                           commitment(self.log[-1]) if self.log else '', now, kind, deepcopy(data))
        self.log.append(e)
        if kind == 'grant': self.caps[data['cap']] = deepcopy(data)
        if kind == 'transfer': self.epoch = data['epoch']
        if kind == 'revoke_cap': self.revoked_caps.add(data['target'])
        return deepcopy(e)

    def head(self, now: int) -> dict:
        if (not natural(now)
                or (self.log and now < self.log[-1]['body']['accepted'])):
            raise ValueError('invalid head time')
        return make_head(self.ns, self.log, now)

class Replica:
    def __init__(self):
        self.events: dict[str,dict[int,dict]] = {n:{} for n in NAMESPACES}
        self.heads: dict[str,dict] = {}
        self.quarantine: set[str] = set()
        self.verified = 0
        self.replayed = 0

    def ingest(self, event: dict) -> bool:
        if not authenticated(event):
            return False
        self.verified += 1
        b = event['body']; ns=b['ns']; seq=b['seq']
        if seq > MAX_EVENTS:
            return False
        prior=self.events[ns].get(seq)
        if prior is not None:
            self.replayed += 1
            if prior != event: self.quarantine.add(ns)
            return prior == event
        self.events[ns][seq]=deepcopy(event)
        return True

    def cache_head(self, head: dict) -> bool:
        try:
            b=head['body']; ns=b['ns']
            if (set(head) != {'body','signature'} or set(b) != {'ns','count','tip','issued'} or
                ns not in NAMESPACES or not natural(b['count']) or b['count'] > MAX_EVENTS or
                not natural(b['issued']) or not verify('authority:'+ns,b,head['signature'])):
                return False
            old=self.heads.get(ns)
            if old and (old['body']['count']>b['count'] or old['body']['issued']>b['issued']):
                return False
            self.heads[ns]=deepcopy(head); return True
        except (KeyError,TypeError): return False

    def prefix(self, ns: str) -> list[dict]:
        out=[]; previous=''
        for seq in range(1,len(self.events[ns])+1):
            e=self.events[ns].get(seq)
            if e is None: break
            if e['body']['previous'] != previous:
                self.quarantine.add(ns); break
            out.append(e); previous=commitment(e)
        return out

    def index(self) -> tuple[dict,dict,dict,set,set]:
        pubs={}; copies={}; receipts={}; dead=set(); dead_caps=set()
        for ns in NAMESPACES:
            for e in self.prefix(ns):
                b=e['body']; d=b['data']; kind=b['kind']
                if kind=='publish':
                    m=d['manifest']; k=m['key']
                    pubs.setdefault(k,m)
                    copies.setdefault(k,set()).add(commitment(m))
                    receipts.setdefault(k,[]).append((ns,b['seq']))
                elif kind=='revoke': dead.add(d['target'])
                elif kind=='revoke_cap': dead_caps.add(d['target'])
        return pubs,copies,receipts,dead,dead_caps

    def discover(self, root: str) -> tuple[list[str],set[str]]:
        pubs,_,_,_,_=self.index(); seen=set(); queue=deque([root]); support=set()
        while queue:
            k=queue.popleft()
            if k in seen: continue
            seen.add(k); support.add(ns_of(k))
            if len(seen)>4096: raise ValueError('closure bound')
            if k in pubs: queue.extend(pubs[k]['deps'])
        return sorted(seen),support

    def certificate(self, root: str, full: bool = False) -> dict:
        closure,support=self.discover(root)
        if full: support=set(NAMESPACES)
        streams={}
        for ns in sorted(support):
            head=self.heads.get(ns)
            log=self.prefix(ns)
            # Never truncate a local prefix to conceal a known invalidator.
            streams[ns]=dict(head=head,events=log)
        return dict(root=root,streams=streams,quarantined=sorted(self.quarantine & support))

    def rollback(self) -> None:
        # This is an emulator fault, not a supported production storage API.
        self.events={n:{} for n in NAMESPACES}; self.heads={};self.quarantine=set()
