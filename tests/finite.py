"""Exhaustive finite symbolic checks, not a mechanized general proof.

Three fixed accepted histories; all delivery permutations and every two-replica split.
This checker does not execute or import the network/cryptographic implementation.
Clock combinations are a separate finite boundary check.
"""
from itertools import permutations, product
from pathlib import Path
import json
import time
import resource

EVENTS=(('a',1,'grant'),('a',2,'publish_root'),('b',1,'grant'),
        ('b',2,'publish_leaf'),('b',3,'revoke_leaf'),
        ('b',4,'replay_leaf'),('b',5,'equivocate_leaf'))

FAMILIES={'revocation':EVENTS,
          'equivocation':EVENTS[:4]+(('b',3,'equivocate_leaf'),('b',4,'replay_leaf')),
          'replay':EVENTS[:4]+(('b',3,'replay_leaf'),)}


def prefix(events,namespace):
    mapping={e[1]:e for e in events if e[0]==namespace}
    result=[]
    while len(result)+1 in mapping:result.append(mapping[len(result)+1])
    return result


def reduce_replica(events):
    accepted=prefix(events,'a')+prefix(events,'b')
    root=False;leaf=False;dead=False;conflict=False
    for _,_,kind in accepted:
        if kind=='publish_root':root=True
        elif kind=='publish_leaf':leaf=True
        elif kind=='revoke_leaf':dead=True
        elif kind=='equivocate_leaf':conflict=True
        elif kind=='replay_leaf':leaf=True
    return root and leaf and not(dead or conflict)


def exact_reference(events,family):
    # Direct explicit state predicate; independent of reducer and prefix helper.
    a={e[1] for e in events if e[0]=='a'}
    b={e[1] for e in events if e[0]=='b'}
    return {1,2}<=a and {1,2}<=b and (family=='replay' or not {1,2,3}<=b)


def run():
    start=time.perf_counter();cpu=time.process_time();schedules=0;decisions=0;merges=0
    family_counts={}
    for family,events in FAMILIES.items():
        fs=0;fd=0;fm=0
        for order in permutations(events):
            schedules+=1;fs+=1
            for cut in range(len(events)+1):
                left=set(order[:cut]);right=set(order[cut:])
                for view in (left,right):
                    assert reduce_replica(view)==exact_reference(view,family)
                    decisions+=1;fd+=1
                    if family!='replay' and {events[2],events[3],events[4]}<=view:
                        repeats={e for e in events if e[2]=='replay_leaf'}
                        assert not reduce_replica(view|repeats)
                assert left|right==right|left==set(events)
                assert (left|left)==left
                assert reduce_replica(left|right)==(family=='replay')
                merges+=1;fm+=1
        family_counts[family]={'events':len(events),'schedules':fs,'state_decisions':fd,'merge_checks':fm}
    clock_cases=0;unsafe_without_error_margin=0
    issue_real=3;epsilon=1
    for now_real,delta,issuer_error,client_error in product(range(3,17),range(1,13),range(-1,2),range(-1,2)):
        issued=issue_real+issuer_error;now=now_real+client_error
        accept=issued<=now+2*epsilon and now-issued+2*epsilon<delta
        assert not accept or now_real-issue_real<delta
        naive=issued<=now+2*epsilon and now-issued<delta
        unsafe_without_error_margin+=int(naive and now_real-issue_real>=delta)
        clock_cases+=1
    assert schedules==5880 and decisions==92160 and unsafe_without_error_margin>0
    return dict(scope='three fixed histories / two replicas; not all registry histories',
                families=family_counts,
                schedules=schedules,state_decisions=decisions,
                merge_checks=merges,clock_boundary_cases=clock_cases,
                negative_control_unsafe_clock_cases=unsafe_without_error_margin,
                violations=0,cpu_seconds=time.process_time()-cpu,
                elapsed_seconds=time.perf_counter()-start,
                peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    out=run();text=json.dumps(out,indent=2,sort_keys=True)+'\n';print(text,end='')
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(text)
