"""Validate all frozen cases and derive tables without selecting favorable runs."""
from __future__ import annotations
import argparse,csv,gzip,json,statistics
from pathlib import Path
from fixtures import cases,POLICIES

ROOT=Path(__file__).resolve().parents[1]
SAFE={'all-namespaces','scoped','status-proof'}

def load(directory:Path):
    out=[]
    for c in cases():
        with gzip.open(directory/(c['case']+'.json.gz'),'rt') as f:r=json.load(f)
        assert all(r[k]==v for k,v in c.items()),'case definition changed'
        assert [p['policy'] for p in r['policies']]==list(POLICIES),'missing policy'
        assert r['replicas']==6 and r['workers']==1
        for p in r['policies']:
            assert [q['phase'] for q in p['queries']]==['base','partition-young','partition-expired','recovered']
            assert p['recovery_rounds'] is not None
            assert len(p['queries'])==4
            for q in p['queries']+p['probes']:
                assert q['bounded_violation']==(q['serve'] and not q['bounded_truth'])
                assert q['immediate_violation']==(q['serve'] and not q['immediate_truth'])
                if p['policy'] in SAFE:assert not q['bounded_violation']
        out.append(r)
    return out

def csv_write(path,rows):
    assert rows
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def semantic(value):
    """Ignore ONLY measured host durations/RSS; retain logical time and all decisions."""
    if isinstance(value,list):return [semantic(x) for x in value]
    if not isinstance(value,dict):return value
    ignored={'elapsed_ms','verify_ms','elapsed_seconds','cpu_seconds','peak_rss_kib',
             'driver_cpu_seconds','driver_elapsed_seconds','driver_time_basis'}
    return {k:semantic(v) for k,v in value.items() if k not in ignored}

def main():
    a=argparse.ArgumentParser();a.add_argument('--results',type=Path,default=ROOT/'results')
    a.add_argument('--output',type=Path,default=ROOT/'results'/'analysis')
    a.add_argument('--compare',type=Path)
    a.add_argument('--compare-semantic',type=Path,help='compare retained logical observations, excluding host timing and RSS')
    a.add_argument('--export-semantic',type=Path,help='retain full logical observations, not a checksum')
    args=a.parse_args()
    rs=load(args.results);args.output.mkdir(parents=True,exist_ok=True)
    if args.export_semantic:
        with gzip.open(args.export_semantic,'wt',encoding='utf-8') as f:
            json.dump(semantic(rs),f,sort_keys=True,separators=(',',':'))
    if args.compare_semantic:
        with gzip.open(args.compare_semantic,'rt',encoding='utf-8') as f: prior=json.load(f)
        assert semantic(rs)==prior,'logical reproduction differs'
        (args.output/'semantic-reproduction.json').write_text(json.dumps(dict(
            cases=48,policy_runs=336,semantic_equal=True,
            comparison='all ordered protocol observations except host durations, peak RSS, and driver timing basis',
            observed_policy_cpu_seconds=sum(p['cpu_seconds'] for r in rs for p in r['policies']),
            observed_peak_rss_kib=max(p['peak_rss_kib'] for r in rs for p in r['policies'])),indent=2)+'\n')
    if args.compare:
        other=load(args.compare)
        assert semantic(rs)==semantic(other),'clean reproduction differs beyond host timing/memory'
        (args.output/'reproduction.json').write_text(json.dumps(dict(cases=48,policies=336,semantic_equal=True,
          compared='all result fields except explicitly named measured durations, peak RSS and driver timing basis',
          primary_policy_cpu_seconds=sum(p['cpu_seconds'] for r in rs for p in r['policies']),
          primary_peak_rss_kib=max(p['peak_rss_kib'] for r in rs for p in r['policies']),
          comparison_policy_cpu_seconds=sum(p['cpu_seconds'] for r in other for p in r['policies']),
          comparison_peak_rss_kib=max(p['peak_rss_kib'] for r in other for p in r['policies'])),indent=2)+'\n')
    queries=[];case_rows=[]
    for r in rs:
        for p in r['policies']:
            case_rows.append(dict(case=r['case'],scenario=r['scenario'],family=r['family'],span=r['span'],policy=p['policy'],
                nodes=p['dimensions']['nodes'],edges=p['dimensions']['edges'],events=p['events'],
                recovery_rounds=p['recovery_rounds'],messages=p['messages'],bytes=p['bytes'],drops=p['drops'],
                rejected_publications=p['rejected_publications'],cpu_seconds=p['cpu_seconds'],
                elapsed_seconds=p['elapsed_seconds'],peak_rss_kib=p['peak_rss_kib']))
            for kind,qs in [('main',p['queries']),('probe',p['probes'])]:
                for q in qs:
                    queries.append({**{k:r[k] for k in ('case','scenario','family','span')},'policy':p['policy'],'kind':kind,
                                    **{k:v for k,v in q.items() if k!='witness'}})
    csv_write(args.output/'queries.csv',queries);csv_write(args.output/'campaigns.csv',case_rows)
    summary=[]
    for policy in POLICIES:
        q=[x for x in queries if x['policy']==policy and x['kind']=='main']
        valid=[x for x in q if x['bounded_truth']]
        expired=[x for x in q if x['phase']=='partition-expired' and x['scenario']=='partition']
        summary.append(dict(policy=policy,queries=len(q),served=sum(x['serve'] for x in q),
            bounded_violations=sum(x['bounded_violation'] for x in q),immediate_violations=sum(x['immediate_violation'] for x in q),
            valid_queries=len(valid),valid_served=sum(x['serve'] for x in valid),
            partition_expired_served=sum(x['serve'] for x in expired),
            probe_violations=sum(x['bounded_violation'] for x in queries if x['policy']==policy and x['kind']=='probe'),
            median_certificate_bytes=statistics.median(x['certificate_bytes'] for x in q),
            median_verify_ms=statistics.median(x['verify_ms'] for x in q)))
    csv_write(args.output/'policy-summary.csv',summary)
    scenario=[]
    for s in dict.fromkeys(r['scenario'] for r in rs):
        for pol in POLICIES:
            qs=[q for q in queries if q['scenario']==s and q['policy']==pol and q['kind']=='main']
            scenario.append(dict(scenario=s,policy=pol,queries=len(qs),served=sum(q['serve'] for q in qs),
                                 violations=sum(q['bounded_violation'] for q in qs)))
    csv_write(args.output/'scenario-summary.csv',scenario)
    sizes=[]
    for family in ['public-lock','generated']:
        for span in [1,3,6]:
            row={'family':family,'span':span,'support':span+1}
            for policy in ['all-namespaces','scoped','status-proof']:
                vs={q['certificate_bytes'] for q in queries if q['family']==family and q['span']==span and q['policy']==policy and q['phase']=='base'}
                assert len(vs)==1,'base certificates changed across fault scenarios'
                row[policy]=vs.pop()
            sizes.append(row)
    csv_write(args.output/'base-certificate-bytes.csv',sizes)
    totals=dict(cases=len(rs),policy_runs=len(case_rows),main_queries=sum(q['kind']=='main' for q in queries),
        probes=sum(q['kind']=='probe' for q in queries),accepted_events=sum(p['events'] for r in rs for p in r['policies']),
        min_events_per_policy_run=min(p['events'] for r in rs for p in r['policies']),
        max_events_per_policy_run=max(p['events'] for r in rs for p in r['policies']),
        max_recovery_rounds=max(p['recovery_rounds'] for r in rs for p in r['policies']),
        total_application_messages=sum(p['messages'] for r in rs for p in r['policies']),
        total_application_bytes=sum(p['bytes'] for r in rs for p in r['policies']),
        main_policy_cpu_seconds=sum(p['cpu_seconds'] for r in rs for p in r['policies']),
        main_policy_wall_seconds=sum(p['elapsed_seconds'] for r in rs for p in r['policies']),
        peak_rss_kib=max(p['peak_rss_kib'] for r in rs for p in r['policies']))
    (args.output/'totals.json').write_text(json.dumps(totals,indent=2)+'\n')
    # Plain TeX rows, no document settings. The paper imports these exact facts.
    tex=[]
    for row in summary:
        tex.append(f"{row['policy']} & {row['served']} & {row['bounded_violations']} & {row['valid_served']}/{row['valid_queries']} \\\\")
    (args.output/'policy-table.tex').write_text('\n'.join(tex)+'\n')
    tex=[]
    for row in sizes:
        tex.append(f"{row['family']} & {row['support']} & {row['all-namespaces']:,} & {row['scoped']:,} & {row['status-proof']:,} \\\\")
    (args.output/'size-table.tex').write_text('\n'.join(tex)+'\n')
    (args.output/'summary.json').write_text(json.dumps({'totals':totals,'policies':summary,'sizes':sizes},indent=2)+'\n')
    print(json.dumps(totals,indent=2))

if __name__=='__main__':main()
