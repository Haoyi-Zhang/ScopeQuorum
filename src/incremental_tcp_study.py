#!/usr/bin/env python3
"""Benign full-history versus suffix TCP comparison on nine growing histories.

Sixteen identical checkpoint bodies per mode/case, four honest loopback signers.
Counts come from actual serialized request/reply frames, including prefix/reset
metadata and newlines. Snapshot counts use the same serializer as persistence,
including its commitment envelope, but this portable experiment does not fsync
snapshots or measure physical writes. It does not reproduce the 96-trace client
prefix-versus-scope crossover, or establish new security/latency claims.
"""
from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import platform
from importlib.metadata import version

from codec import encode, manifest, verify
from durable_witness import snapshot_wire, witness_payload
from fixtures import grant
from model import Authority
from witness_delta import WITNESS_IDS
from witness_network import WitnessTCPNetwork
from witness_sync import prefix

ROUNDS = 16
INITIAL_PUBLICATIONS = (1, 32, 128)
GROWTH = (0, 1, 8)


async def one_mode(initial: int, growth: int, incremental: bool) -> dict:
    authority = Authority('n1')
    authority.append('grant', grant('n1'), 0)
    for index in range(initial):
        authority.append('publish', manifest('n1', f'initial-{index:03d}', []), 0)
    rows = []
    payloads = []
    signatures_by_round = []
    async with WitnessTCPNetwork(incremental=incremental) as network:
        network.configure('growth', 'n1')
        for step in range(ROUNDS):
            now = step + 1
            if step:
                for index in range(growth):
                    authority.append('publish', manifest(
                        'n1', f'growth-{step:03d}-{index:03d}', []), now)
            network.advance('growth', now)
            body = {'op': 'checkpoint', **prefix(authority.log, 'n1'), 'issued': now}
            before = deepcopy(network.counters)
            signatures = await network.signatures('growth', body, authority.log)
            if (len(signatures) != 4 or any(not verify(
                    'witness:n1:' + item['id'], body, item['signature'])
                    for item in signatures)):
                raise RuntimeError('benign checkpoint did not certify')
            states = [witness_payload(network.states[wid]['growth']) for wid in WITNESS_IDS]
            payloads.append(states)
            signatures_by_round.append(signatures)
            rows.append({
                'round': step, 'count': len(authority.log),
                **{key: value - asdict(before)[key]
                   for key, value in asdict(network.counters).items()},
                'payload_bytes': sum(len(encode(state)) for state in states),
                'snapshot_bytes': sum(len(snapshot_wire(state)) for state in states),
                'staging_bytes': sum(len(encode(network.sessions[wid]['growth'].candidate))
                                     for wid in WITNESS_IDS),
            })
        counters = asdict(network.counters)
    return {
        'counters': counters, 'rounds': rows,
        'final_count': len(authority.log),
        'final_snapshot_bytes': rows[-1]['snapshot_bytes'],
        'snapshot_serializations_bytes': sum(row['snapshot_bytes'] for row in rows),
        '_states': payloads, '_signatures': signatures_by_round,
    }


async def run(output: Path, generated: Path | None = None) -> dict:
    if output.exists():
        raise ValueError('use a new output directory')
    cases = []
    for initial in INITIAL_PUBLICATIONS:
        for growth in GROWTH:
            full = await one_mode(initial, growth, False)
            incremental = await one_mode(initial, growth, True)
            same = (full.pop('_states') == incremental.pop('_states')
                    and full.pop('_signatures') == incremental.pop('_signatures'))
            if not same:
                raise RuntimeError('full/suffix accepted state or signature mismatch')
            if incremental['counters']['history_events'] != 4 * incremental['final_count']:
                raise RuntimeError('suffix history was retransmitted')
            if any(row['history_events'] != 4 * growth
                   for row in incremental['rounds'][1:]):
                raise RuntimeError('warm suffix transfer count mismatch')
            cases.append({'initial_publications': initial, 'growth_per_round': growth,
                          'state_and_signature_parity': same,
                          'full': full, 'incremental': incremental})
    result = {
        'cases': len(cases), 'rounds_per_mode_case': ROUNDS,
        'certification_rounds': len(cases) * ROUNDS * 2,
        'witnesses': 4, 'single_process': True, 'all_honest': True,
        'runtime': {'python': platform.python_version(), 'platform': platform.platform(),
                    'cryptography': version('cryptography')},
        'traffic': 'actual canonical JSON request/reply frames including newline and metadata; no TCP/IP or TLS headers',
        'persistence': 'serialized production snapshot payload plus commitment envelope and newline; no durable I/O or physical write measurement',
        'snapshot_serializations_bytes': 'sum of four snapshot lengths after each successful certificate; excludes configuration and clock-only snapshots',
        'client_plane': 'not measured; this is not the 96-trace prefix-versus-scope comparison',
        'rows': cases,
    }
    output.mkdir(parents=True)
    (output / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if generated is not None:
        generated.mkdir(parents=True, exist_ok=True)
        lines = ['% Generated by artifact/src/incremental_tcp_study.py.',
                 r'\begin{tabular}{@{}rrrrr@{}}', r'\toprule',
                 r'Initial & Growth & Full & Suffix & State \\',
                 r'\midrule']
        for case in cases:
            full = case['full']['counters']['wire_bytes'] / 1024
            suffix = case['incremental']['counters']['wire_bytes'] / 1024
            snapshot = case['incremental']['final_snapshot_bytes'] / 1024
            lines.append(f"{case['initial_publications']} & {case['growth_per_round']} & {full:.1f} & {suffix:.1f} & {snapshot:.1f} " + r'\\')
        lines += [r'\bottomrule', r'\end{tabular}']
        (generated / 'incremental-tcp-table.tex').write_text('\n'.join(lines) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--generated')
    args = parser.parse_args()
    result = asyncio.run(run(Path(args.output),
                             Path(args.generated) if args.generated else None))
    print(json.dumps({key: result[key] for key in (
        'cases', 'rounds_per_mode_case', 'certification_rounds', 'runtime')}, sort_keys=True))


if __name__ == '__main__':
    main()
