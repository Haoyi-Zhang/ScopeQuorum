"""Frozen graph selection and benign generated authority histories."""
from __future__ import annotations
import json
from pathlib import Path
from codec import NAMESPACES,manifest

ROOT=Path(__file__).resolve().parents[1]
SCENARIOS=('partition','revocation','grant_revocation','transfer',
           'equivocation','missing','malformed','rollback')
POLICIES=('lww','signed-index','transparency-only','root-only','all-namespaces','scoped','status-proof')
SPANS=(1,3,6)

def graph(family: str, span: int) -> tuple[dict[str,list[str]],str,dict]:
    if family=='public-lock':
        data=json.loads((ROOT/'data/lock_projection.json').read_text())
        packages=data['packages']; lookup={p['name']:p for p in packages}
        if len(lookup)!=len(packages): raise ValueError('ambiguous package name')
        raw={p['name']+'@'+p['version']:[d+'@'+lookup[d]['version'] for d in p['dependencies']] for p in packages}
        source_root='ripgrep@14.1.1'
    elif family=='generated':
        raw={}
        for i in range(128):
            layer,col=divmod(i,16)
            raw[f'item-{i:03d}']=([] if layer==0 else [f'item-{(layer-1)*16+col:03d}',f'item-{(layer-1)*16+(col+1)%16:03d}'])
        raw['top']=[f'item-{i:03d}' for i in range(112,128)]
        source_root='top'
    else: raise ValueError('unknown family')
    # No edge pruning or dependency resolution beyond the unique locked names.
    order=sorted(raw); names={k:f'n{1+i%span}/{k}' for i,k in enumerate(order)}
    g={names[k]:[names[d] for d in ds] for k,ds in raw.items()}
    root='n0/bundle';g[root]=[names[source_root]]
    # Disjoint public records outside the root closure remain in the registry.
    for n in NAMESPACES: g[n+'/unrelated']=[]
    reachable={root}
    while True:
        new=reachable|{d for k in reachable for d in g[k]}
        if new==reachable:break
        reachable=new
    leaves=sorted(k for k in reachable if not g[k] and k.startswith('n1/'))
    if not leaves: raise ValueError('fixture needs a remote relevant leaf')
    return g,root,dict(target=leaves[0],nodes=len(g),edges=sum(map(len,g.values())),
                      closure_nodes=len(reachable),support=sorted({k.split('/')[0] for k in reachable}))

def grant(ns: str, epoch: int = 0) -> dict:
    return {'cap':f'cap:{ns}:{epoch}','publisher':f'publisher:{ns}:{epoch}',
            'epoch':epoch,'rights':['publish']}

def cases() -> list[dict]:
    return [dict(case=f'case-{i:02d}',scenario=s,family=f,span=p)
            for i,(s,f,p) in enumerate(((s,f,p) for s in SCENARIOS
                                       for f in ('public-lock','generated') for p in SPANS),1)]
