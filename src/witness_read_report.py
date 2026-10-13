"""Validate and tabulate a retained witness_read_study campaign; no networking."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

from witness_read_study import compare


def report(source, output, generated):
    output.mkdir(parents=True, exist_ok=False)
    summary = json.loads((source / 'summary.json').read_text(encoding='utf-8'))
    traces = [json.loads(p.read_text(encoding='utf-8'))
              for p in sorted(source.glob('*.json')) if p.name != 'summary.json']
    indexed = {(r['family'], r['span'], r['churn'], r['mode']): r for r in traces}
    if len(indexed) != len(traces):
        raise AssertionError('duplicate raw read trace identity')
    keys = {(row['family'], row['span'], row['churn']) for row in summary['comparisons']}
    expected = {(*key, mode) for key in keys for mode in ('prefix', 'scope')}
    if (len(keys) != len(summary['comparisons']) or set(indexed) != expected
            or summary['traces'] != len(keys) or summary['modes'] != 2):
        raise AssertionError('read comparison inventory mismatch')
    if summary['read_pairs'] != sum(len(indexed[(*key, 'prefix')]['rows']) for key in keys):
        raise AssertionError('read comparison pair count mismatch')
    for row in summary['comparisons']:
        key = row['family'], row['span'], row['churn']
        if compare(indexed[(*key, 'prefix')], indexed[(*key, 'scope')]) != row:
            raise AssertionError('comparison export mismatch')
    for trace in traces:
        c = trace['witness_counters']
        if (c['wire_bytes'] != sum(c[k] for k in ('prefix_wire_bytes', 'sync_wire_bytes',
                                                  'reset_wire_bytes', 'certify_wire_bytes'))
                or trace['total_wire_bytes'] != trace['client_wire_bytes'] + c['wire_bytes']):
            raise AssertionError('counter accounting mismatch')
    costs = {}
    for mode in ('prefix', 'scope'):
        subset = [r for r in traces if r['mode'] == mode]
        costs[mode] = {
            'median_peak_serialized_components': {
                k: statistics.median(r['peak_state'][k] for r in subset)
                for k in ('sequencer_bytes', 'client_bytes', 'accepted_witness_bytes', 'staging_bytes',
                          'aggregate_serialized_bytes', 'protocol_heap_estimate_bytes')},
            'max_protocol_heap_estimate_bytes': max(r['peak_state']['protocol_heap_estimate_bytes'] for r in subset),
            'max_tracemalloc_peak_bytes_including_diagnostics': max(r['tracemalloc_peak_bytes'] for r in subset),
            'state_diagnostic_cpu_seconds': sum(row['state']['measurement_cpu_seconds'] for r in subset for row in r['rows']),
        }
    result = {'validated_traces': len(traces), 'validated_read_pairs': summary['read_pairs'],
              'costs': costs,
              'raw_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(source.glob('*.json'))}}
    (output / 'accounting.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    with (output / 'comparisons.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary['comparisons'][0]))
        writer.writeheader()
        writer.writerows(summary['comparisons'])
    lifecycle = []
    for trace in traces:
        previous_client = previous_witness = previous_events = previous_drops = 0
        for row in trace['rows']:
            c = row['witness_counters']
            item = {k: trace[k] for k in ('family', 'span', 'churn', 'fault', 'mode')}
            item.update(step=row['step'], root=row['root'], reason=row['verdict']['reason'],
                        client_bytes=row['client_wire_bytes'] - previous_client,
                        witness_bytes=c['wire_bytes'] - previous_witness,
                        witness_history_events=c['history_events'] - previous_events,
                        blocked_rpc_attempts=c['drops'] - previous_drops,
                        protocol_state_bytes=row['state']['aggregate_serialized_bytes'],
                        read_cpu_seconds=row['cpu_seconds'], read_wall_seconds=row['wall_seconds'])
            item['total_bytes'] = item['client_bytes'] + item['witness_bytes']
            lifecycle.append(item)
            previous_client, previous_witness = row['client_wire_bytes'], c['wire_bytes']
            previous_events, previous_drops = c['history_events'], c['drops']
    with (output / 'lifecycle.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(lifecycle[0]))
        writer.writeheader()
        writer.writerows(lifecycle)
    lines = [r'\begin{tabular}{@{}lrrrrrr@{}}', r'\toprule',
             r'Graph & Span & Churn & Client P & Client S & Total P & Total S \\',
             r' & & & \multicolumn{4}{c}{canonical framed bytes} \\', r'\midrule']
    for row in summary['comparisons']:
        label = 'Lock' if row['family'] == 'public-lock' else 'Layered'
        values = [row[k] for k in ('span', 'churn', 'prefix_client_bytes', 'scope_client_bytes',
                                   'prefix_total_bytes', 'scope_total_bytes')]
        lines.append(label + ' & ' + ' & '.join(f'{v:,}' for v in values) + r' \\')
    lines += [r'\bottomrule', r'\end{tabular}', '']
    generated.mkdir(parents=True, exist_ok=True)
    (generated / 'witness-read-table.tex').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh directory')
    parser.add_argument('--generated', type=Path, required=True)
    args = parser.parse_args()
    report(args.source, args.output, args.generated)
