#!/usr/bin/env python3
"""Recheck the bounded artifact without paper files or external services.

This quick gate reruns unit tests, finite checks, the real-signature split cases,
and the independent Go set enumerator. It validates, but does not rerun, every
retained network/cost study. Run the README's study commands for those reruns.
"""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from analyze import load, semantic

ROOT = Path(__file__).resolve().parents[1]
# Exact host-diagnostic fields; logical timestamps/frontiers remain compared.
HOST_FIELDS = {
    'cpu_seconds', 'elapsed_seconds', 'peak_rss_kib',
    'median_restart_and_retry_ms_host_diagnostic',
    'p95_restart_and_retry_ms_host_diagnostic',
    'first_attempt_ms', 'restart_and_retry_ms',
}

def read_json(path: Path):
    if path.suffix == '.gz':
        with gzip.open(path, 'rt', encoding='utf-8') as handle:
            return json.load(handle)
    return json.loads(path.read_text(encoding='utf-8'))

def without_host(value):
    if isinstance(value, list):
        return [without_host(item) for item in value]
    if isinstance(value, dict):
        return {key: without_host(item) for key, item in value.items() if key not in HOST_FIELDS}
    return value

def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)

def retained_comparison() -> dict:
    results = ROOT / 'results'
    repeat = results / 'journal-repetition'
    canonical = load(results)
    require(semantic(canonical) == read_json(results / 'semantic-reference.json.gz'),
            'canonical protocol observations differ from semantic reference')
    require(semantic(canonical) == semantic(load(results / 'clean-repetition')),
            'canonical histories differ from retained complete clean repetition')
    pairs = []
    for family in ['renewal', 'witness', 'witness-network', 'durable-witness']:
        for original in sorted((results / family).glob('*')):
            if original.suffix not in {'.json', '.gz'}:
                continue
            relative = original.relative_to(results)
            repeated = repeat / relative
            if family == 'renewal' and original.name.startswith('selector-'):
                repeated = repeat / 'renewal' / 'selector' / original.name
            require(repeated.exists(), f'missing repeated result {relative}')
            require(without_host(read_json(original)) == without_host(read_json(repeated)),
                    f'repetition mismatch {relative}')
            pairs.append(str(relative))
    for name in ['finite.json', 'witness-finite.json']:
        require(without_host(read_json(results/name)) == without_host(read_json(repeat/name)),
                f'repetition mismatch {name}')
        pairs.append(name)
    new_main = sorted((repeat/'main').glob('case-*.json.gz'))
    require(len(new_main) == 6, 'six current main repeats must be present')
    for path in new_main:
        require(semantic(read_json(path)) == semantic(read_json(results/path.name)),
                f'logical main-case mismatch {path.name}')
    differential = read_json(repeat/'differential.json')
    require(differential['iterations_completed'] == 500 and differential['mismatch_count'] == 0,
            'fresh-seed differential evidence does not pass')
    require(differential['seed'] == 20260923, 'unexpected differential seed')
    return {
        'canonical_main_cases_checked': len(canonical),
        'retained_complete_repetition_equal': True,
        'current_main_cases_rerun_and_equal': len(new_main),
        'equal_result_files': pairs,
        'excluded_host_fields': sorted(HOST_FIELDS),
        'fresh_seed_differential_histories': 500,
        'differential_seed': 20260923,
        'differential_mismatches': 0,
    }

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--retained-only', action='store_true',
                        help='only validate stored records; this does not execute tests')
    args=parser.parse_args(); output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    report={'scope':'quick bounded gate, not a fresh complete network campaign',
            'retained':retained_comparison(), 'commands':[]}
    if not args.retained_only:
        require(shutil.which('go') is not None, 'local Go toolchain required')
        env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','GOMAXPROCS':'2'}
        jobs=[
            ('unit',[sys.executable,'-m','unittest','discover','-s','tests','-p','test_*.py','-v']),
            ('finite',[sys.executable,'tests/finite.py','--output',str(output/'finite.json')]),
            ('witness-finite',[sys.executable,'tests/witness_finite.py','--output',str(output/'witness-finite.json')]),
            ('boundary',[sys.executable,'src/boundary_study.py','--output',str(output/'boundary.json')]),
            ('quorum',['go','run','checks/quorum.go']),
        ]
        for name, command in jobs:
            start=time.monotonic()
            run=subprocess.run(command,cwd=ROOT,env=env,stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,text=True,timeout=180,check=False)
            text=run.stdout.replace(str(ROOT),'.').replace(str(output),'OUTPUT')
            (output/(name+'.log')).write_text(text,encoding='utf-8')
            require(run.returncode==0,f'{name} failed; see {name}.log')
            row={'name':name,'exit_code':run.returncode,'elapsed_seconds_host_diagnostic':round(time.monotonic()-start,3)}
            if name=='unit':
                match=re.search(r'Ran (\d+) tests',run.stdout)
                require(match is not None,'unit-test result count missing')
                row['passed_tests']=int(match.group(1));require(row['passed_tests']==134,'unit count changed')
            if name=='quorum':
                actual=json.loads(run.stdout)
                require(actual==read_json(ROOT/'results/quorum-general.json'),'independent quorum output changed')
                (output/'quorum.json').write_text(json.dumps(actual,indent=2)+'\n')
            if name=='boundary':
                require(read_json(output/'boundary.json')==read_json(ROOT/'results/journal-boundary.json'),
                        'actual-signature boundary output changed')
            report['commands'].append(row)
    report['passed']=True
    (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'executed_commands':len(report['commands']),
                      'current_main_cases_rerun':6,'canonical_main_cases_validated':48},indent=2))
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(f'verification failed: {error}',file=sys.stderr)
        raise SystemExit(1)
