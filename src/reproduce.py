"""Resumable campaign driver; one worker, bounded memory, atomic case records."""
from __future__ import annotations
import argparse
import asyncio
import gzip
import json
import os
from pathlib import Path
import resource
import sys
import time
from campaign import run_policy
from fixtures import cases, POLICIES

ROOT=Path(__file__).resolve().parents[1]

def write(path:Path,value:dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    if path.suffix=='.gz':
        with gzip.open(tmp,'wt',encoding='utf-8') as f: json.dump(value,f,separators=(',',':'),sort_keys=True)
    else: tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    os.replace(tmp,path)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--pilot',action='store_true')
    parser.add_argument('--all',action='store_true')
    parser.add_argument('--cases',help='inclusive start:end campaign indices')
    parser.add_argument('--output',type=Path,default=ROOT/'results')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    if sum([args.pilot,args.all,bool(args.cases)])!=1: parser.error('choose exactly one execution scope')
    if hasattr(os,'sched_getaffinity'):
        available=os.sched_getaffinity(0);os.sched_setaffinity(0,{min(available)})
    resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(900,900))
    campaign=cases()
    if args.pilot:
        chosen=[dict(case='pilot',scenario='revocation',family='public-lock',span=3)]
    elif args.all: chosen=campaign
    else:
        lo,hi=map(int,args.cases.split(':'))
        if not 1<=lo<=hi<=48:parser.error('case range must lie in 1:48')
        chosen=campaign[lo-1:hi]
    for case in chosen:
        path=args.output/(case['case']+'.json.gz')
        if args.resume and path.exists():
            with gzip.open(path,'rt') as f: old=json.load(f)
            if any(old.get(k)!=v for k,v in case.items()) or [p.get('policy') for p in old.get('policies',[])]!=list(POLICIES):
                raise RuntimeError('invalid resume record')
            print('retained',case['case'],flush=True);continue
        progress=args.output/'progress'/(case['case']+'.json.gz')
        result={**case,'replicas':6,'workers':1,'batch_events':128,
                'delta_ticks':10,'epsilon_ticks':0,'policies':[]}
        if args.resume and progress.exists():
            with gzip.open(progress,'rt') as f: result=json.load(f)
            if any(result.get(k)!=v for k,v in case.items()):
                raise RuntimeError('progress case mismatch')
            completed=[p['policy'] for p in result['policies']]
            if completed!=list(POLICIES[:len(completed)]):
                raise RuntimeError('progress policy mismatch')
        for policy in POLICIES[len(result['policies']):]:
            print(case['case'],policy,'start',flush=True)
            result['policies'].append(asyncio.run(run_policy(case,policy)))
            write(progress,result)
            print(case['case'],policy,'done',flush=True)
        # Active policy time excludes between-invocation pauses and checkpoint I/O.
        # Earlier complete records retain their originally measured driver time.
        result['driver_cpu_seconds']=sum(p['cpu_seconds'] for p in result['policies'])
        result['driver_elapsed_seconds']=sum(p['elapsed_seconds'] for p in result['policies'])
        result['driver_time_basis']='sum of completed policy runs; checkpoint I/O and pauses excluded'
        write(path,result)
        progress.unlink()
        if progress.parent.exists() and not any(progress.parent.iterdir()):progress.parent.rmdir()
        print(case['case'],json.dumps({'seconds':result['driver_elapsed_seconds'],
              'safe_violations':sum(q['bounded_violation'] for p in result['policies'] if p['policy'] in ['scoped','all-namespaces'] for q in p['queries']),
              'ablation_violations':sum(q['bounded_violation'] for p in result['policies'] if p['policy']=='root-only' for q in p['queries'])}),flush=True)

if __name__=='__main__':main()
