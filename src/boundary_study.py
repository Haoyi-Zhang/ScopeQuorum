"""Execute benign split-branch schedules using actual witness signatures.

This is an availability counterexample, not a safety violation. All candidate
histories are local fixtures; no third-party system or account is contacted.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import json
from pathlib import Path
from codec import commitment, manifest, verify
from fixtures import grant
from model import Authority
from witness_delta import WitnessCommittee, QUORUM


def split_case(left_count: int, byzantine_signs: bool) -> dict:
    base = Authority('n1')
    base.append('grant', grant('n1'), 0)
    left, right = deepcopy(base), deepcopy(base)
    left.append('publish', manifest('n1', 'leaf', [], blob='left'), 1)
    right.append('publish', manifest('n1', 'leaf', [], blob='right'), 1)
    def body(authority):
        return {'op':'checkpoint','ns':'n1','count':len(authority.log),
                'tip':commitment(authority.log[-1]),'issued':1}
    committee = WitnessCommittee('n1', faulty=('w0',))
    committee.advance(1)
    honest = ['w1','w2','w3']
    left_ids, right_ids = honest[:left_count], honest[left_count:]
    first_left = committee.signatures(body(left), left.log, left_ids)
    first_right = committee.signatures(body(right), right.log, right_ids)
    reachable = honest + (['w0'] if byzantine_signs else [])
    after_left = committee.signatures(body(left), left.log, reachable)
    after_right = committee.signatures(body(right), right.log, reachable)
    for items,b in ((after_left,body(left)),(after_right,body(right))):
        assert all(verify('witness:n1:'+x['id'],b,x['signature']) for x in items)
    counts = (len(after_left),len(after_right))
    assert counts == (left_count+int(byzantine_signs),3-left_count+int(byzantine_signs))
    assert not (counts[0]>=QUORUM and counts[1]>=QUORUM)
    return {'left_honest_locks':left_count,'byzantine_signs':byzantine_signs,
            'honest_reachable':3,'first_left_signatures':len(first_left),
            'first_right_signatures':len(first_right),'later_left_signatures':counts[0],
            'later_right_signatures':counts[1],
            'any_quorum':max(counts)>=QUORUM,'both_quorums':False}


def run() -> dict:
    rows=[split_case(k,b) for k in range(4) for b in (False,True)]
    blocked=[r for r in rows if 0<r['left_honest_locks']<3 and not r['byzantine_signs']]
    assert len(blocked)==2 and all(not r['any_quorum'] for r in blocked)
    return {'case_count':len(rows),'passed':len(rows),'dual_quorum_failures':0,
            'honest_reachability_counterexamples':len(blocked),'cases':rows,
            'interpretation':'persisted branch refusal preserves safety but does not implement branch reconciliation or consensus liveness'}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    result=run();args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},sort_keys=True))
