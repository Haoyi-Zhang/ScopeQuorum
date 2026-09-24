#!/usr/bin/env python3
"""Crash/recovery study for process-isolated durable witnesses.

The study has four bounded parts:

* 24 recovery cases: two graph families, four update classes, and three crash
  windows on one required honest witness;
* six full-committee restart/fork cases across two families and three spans;
* two corrupt-state fail-closed cases; and
* one logical-clock rollback case after a full restart.

Timings are retained only as host diagnostics.  Safety and recovery outcomes,
message counts, canonical bytes, recovered frontiers, and state-file sizes are
the claim-bearing observations.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
from statistics import median
import tempfile
import time

from codec import commitment, encode, manifest
from durable_witness import CRASH_PHASES
from durable_witness_network import (
    DurableNetworkCounters,
    DurableWitnessProcessNetwork,
)
from witness_delta import QUORUM, WitnessScopeCache, _projection
from witness_network_study import (
    FAMILIES, UPDATES, apply_update, build_condition, certificate, frontier,
    register_body,
)

RECOVERY_SPAN = 3


def _counter_delta(after: DurableNetworkCounters,
                   before: DurableNetworkCounters) -> dict[str, int]:
    left = asdict(after); right = asdict(before)
    return {key: left[key] - right[key] for key in left}


def _combine_counters(items: list[DurableNetworkCounters]) -> dict[str, int]:
    keys = asdict(DurableNetworkCounters()).keys()
    return {key: sum(getattr(item, key) for item in items) for key in keys}


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def _valid_objects(cache: WitnessScopeCache) -> bool:
    return bool(cache.objects) and all(item['valid'] for item in cache.objects.values())


async def _initialize_scope(network: DurableWitnessProcessNetwork, case_id: str,
                            authority, keys: list[str], *, faulty=('w0',)) -> WitnessScopeCache:
    await network.configure(case_id, authority.ns, faulty=faulty)
    await network.advance(case_id, 1)
    body = register_body(authority, keys, 1)
    signatures = await network.signatures(case_id, body, authority.log)
    if len(signatures) < QUORUM:
        raise RuntimeError('durable registration did not reach quorum')
    cache = WitnessScopeCache(authority.ns)
    cache.apply_register(certificate(body, signatures), 1)
    return cache


async def _recovery_matrix(root: Path) -> tuple[list[dict], DurableNetworkCounters]:
    rows: list[dict] = []
    async with DurableWitnessProcessNetwork(root) as network:
        case_number = 0
        for family in FAMILIES:
            for update in UPDATES:
                for phase in CRASH_PHASES:
                    case_number += 1
                    case_id = f'recovery-{case_number:03d}'
                    authority, keys, target, graph_map = build_condition(
                        family, RECOVERY_SPAN)
                    before = deepcopy(network.counters)
                    cache = await _initialize_scope(
                        network, case_id, authority, keys, faulty=('w0',))
                    old_count = cache.count
                    expected_valid = apply_update(
                        authority, graph_map, target, update)
                    await network.advance(case_id, 2)
                    body = {
                        'op': 'renew', 'ns': authority.ns,
                        'scope': cache.scope, 'from': cache.count,
                        **frontier(authority, 2),
                        **_projection(authority.log, tuple(keys), cache.count),
                    }
                    network.blocked = {'w0'}
                    started = time.perf_counter_ns()
                    first = await network.signatures(
                        case_id, body, authority.log, crash={'w1': phase})
                    first_ms = (time.perf_counter_ns() - started) / 1_000_000
                    started = time.perf_counter_ns()
                    recovered = await network.restart('w1', cases=(case_id,))
                    pre_retry = await network.status(case_id)
                    recovered_count = pre_retry['w1']['summary']['count']
                    second = await network.signatures(
                        case_id, body, authority.log)
                    recovery_ms = (time.perf_counter_ns() - started) / 1_000_000
                    network.blocked = set()
                    accepted = len(second) >= QUORUM
                    if accepted:
                        cache.apply_renew(certificate(body, second), 2)
                    post = await network.status(case_id)
                    state_bytes = [
                        reply['summary']['state_bytes']
                        for reply in post.values()
                        if reply is not None and reply.get('ok') is True
                    ]
                    expected_recovered_count = (
                        len(authority.log) if phase == 'after-replace'
                        else old_count
                    )
                    temp_files = list(
                        network.state_path('w1', case_id).parent.glob(
                            f'.{case_id}.json.tmp-*'))
                    passed = (
                        len(first) == 2 and recovered and accepted
                        and recovered_count == expected_recovered_count
                        and _valid_objects(cache) is expected_valid
                        and not temp_files
                    )
                    rows.append({
                        'case': case_id,
                        'category': 'crash-recovery',
                        'family': family,
                        'span': RECOVERY_SPAN,
                        'update': update,
                        'crash_phase': phase,
                        'first_signatures': len(first),
                        'retry_signatures': len(second),
                        'recovered_count_before_retry': recovered_count,
                        'expected_recovered_count': expected_recovered_count,
                        'old_count': old_count,
                        'new_count': len(authority.log),
                        'serve_after_update': _valid_objects(cache),
                        'expected_serve_after_update': expected_valid,
                        'state_bytes_total': sum(state_bytes),
                        'state_bytes_max': max(state_bytes),
                        'first_attempt_ms': round(first_ms, 3),
                        'restart_and_retry_ms': round(recovery_ms, 3),
                        'passed': passed,
                        **_counter_delta(network.counters, before),
                    })
        counters = deepcopy(network.counters)
    return rows, counters


async def _durable_fork_matrix(root: Path) -> tuple[list[dict], DurableNetworkCounters]:
    rows: list[dict] = []
    async with DurableWitnessProcessNetwork(root) as network:
        case_number = 0
        for family in FAMILIES:
            for span in (1, 3, 6):
                case_number += 1
                case_id = f'fork-{case_number:03d}'
                base, _, target, graph_map = build_condition(family, span)
                left = deepcopy(base); right = deepcopy(base)
                left.append('revoke', {'target': target}, 2)
                ns, name = target.split('/', 1)
                right.append('publish', manifest(
                    ns, name, graph_map[target], blob='durable-fork'), 2)
                before = deepcopy(network.counters)
                await network.configure(case_id, ns, faulty=('w0',))
                await network.advance(case_id, 2)
                network.blocked = {'w3'}
                first_body = {
                    'op': 'checkpoint', 'ns': ns,
                    'count': len(left.log), 'tip': commitment(left.log[-1]),
                    'issued': 2,
                }
                first = await network.signatures(
                    case_id, first_body, left.log)
                network.blocked = set()
                started = time.perf_counter_ns()
                restarted = await network.restart_all(cases=(case_id,))
                restart_ms = (time.perf_counter_ns() - started) / 1_000_000
                after_restart = await network.status(case_id)
                retained = {
                    witness_id: reply['summary']['count']
                    for witness_id, reply in after_restart.items()
                    if reply is not None and reply.get('ok') is True
                }
                await network.advance(case_id, 3)
                network.blocked = {'w1'}
                second_body = {
                    'op': 'checkpoint', 'ns': ns,
                    'count': len(right.log), 'tip': commitment(right.log[-1]),
                    'issued': 3,
                }
                second = await network.signatures(
                    case_id, second_body, right.log)
                network.blocked = set()
                passed = (
                    len(first) == QUORUM and restarted
                    and retained.get('w1') == len(left.log)
                    and retained.get('w2') == len(left.log)
                    and len(second) < QUORUM
                )
                rows.append({
                    'case': case_id,
                    'category': 'full-restart-fork',
                    'family': family,
                    'span': span,
                    'update': 'conflicting-branch',
                    'crash_phase': 'full-committee-restart',
                    'first_signatures': len(first),
                    'retry_signatures': len(second),
                    'recovered_count_before_retry': min(retained.values()),
                    'expected_recovered_count': len(base.log),
                    'old_count': len(base.log),
                    'new_count': len(left.log),
                    'serve_after_update': False,
                    'expected_serve_after_update': False,
                    'state_bytes_total': sum(
                        reply['summary']['state_bytes']
                        for reply in after_restart.values()
                        if reply is not None and reply.get('ok') is True),
                    'state_bytes_max': max(
                        reply['summary']['state_bytes']
                        for reply in after_restart.values()
                        if reply is not None and reply.get('ok') is True),
                    'first_attempt_ms': 0.0,
                    'restart_and_retry_ms': round(restart_ms, 3),
                    'passed': passed,
                    **_counter_delta(network.counters, before),
                })
        counters = deepcopy(network.counters)
    return rows, counters


async def _corruption_case(root: Path, mode: str) -> tuple[dict, DurableNetworkCounters]:
    async with DurableWitnessProcessNetwork(root) as network:
        case_id = f'corrupt-{mode}'
        value, _, _, _ = build_condition('public-lock', 1)
        before = deepcopy(network.counters)
        await network.configure(case_id, value.ns)
        await network.advance(case_id, 1)
        body = {
            'op': 'checkpoint', 'ns': value.ns,
            'count': len(value.log), 'tip': commitment(value.log[-1]),
            'issued': 1,
        }
        initial = await network.signatures(case_id, body, value.log)
        network.stop('w1')
        path = network.state_path('w1', case_id)
        if mode == 'truncated':
            path.write_text('{"state":')
        elif mode == 'commitment':
            envelope = json.loads(path.read_text())
            envelope['commitment'] = 'A' * 44
            path.write_bytes(encode(envelope) + b'\n')
        else:
            raise ValueError(mode)
        recovered = await network.restart('w1', strict=False, cases=(case_id,))
        after = await network.signatures(case_id, body, value.log)
        row = {
            'case': case_id,
            'category': 'corrupt-state',
            'family': 'public-lock',
            'span': 1,
            'update': mode,
            'crash_phase': 'corrupt-file',
            'first_signatures': len(initial),
            'retry_signatures': len(after),
            'recovered_count_before_retry': -1,
            'expected_recovered_count': -1,
            'old_count': len(value.log),
            'new_count': len(value.log),
            'serve_after_update': True,
            'expected_serve_after_update': True,
            'state_bytes_total': 0,
            'state_bytes_max': 0,
            'first_attempt_ms': 0.0,
            'restart_and_retry_ms': 0.0,
            'passed': (
                len(initial) == 4 and not recovered and len(after) == QUORUM),
            **_counter_delta(network.counters, before),
        }
        counters = deepcopy(network.counters)
    return row, counters


async def _clock_case(root: Path) -> tuple[dict, DurableNetworkCounters]:
    async with DurableWitnessProcessNetwork(root) as network:
        case_id = 'clock-rollback'
        value, _, _, _ = build_condition('public-lock', 1)
        before = deepcopy(network.counters)
        await network.configure(case_id, value.ns)
        await network.advance(case_id, 5)
        restarted = await network.restart_all(cases=(case_id,))
        backward = await network.advance(case_id, 4, strict=False)
        status = await network.status(case_id)
        retained = [
            reply['summary']['clock']
            for reply in status.values()
            if reply is not None and reply.get('ok') is True
        ]
        await network.advance(case_id, 6)
        rejected = all(
            reply is not None and reply.get('ok') is not True
            for reply in backward.values()
        )
        row = {
            'case': case_id,
            'category': 'clock-recovery',
            'family': 'public-lock',
            'span': 1,
            'update': 'clock-backstep',
            'crash_phase': 'full-committee-restart',
            'first_signatures': 0,
            'retry_signatures': 0,
            'recovered_count_before_retry': 0,
            'expected_recovered_count': 0,
            'old_count': 0,
            'new_count': 0,
            'serve_after_update': True,
            'expected_serve_after_update': True,
            'state_bytes_total': sum(
                reply['summary']['state_bytes']
                for reply in status.values()
                if reply is not None and reply.get('ok') is True),
            'state_bytes_max': max(
                reply['summary']['state_bytes']
                for reply in status.values()
                if reply is not None and reply.get('ok') is True),
            'first_attempt_ms': 0.0,
            'restart_and_retry_ms': 0.0,
            'passed': restarted and rejected and retained == [5, 5, 5, 5],
            **_counter_delta(network.counters, before),
        }
        counters = deepcopy(network.counters)
    return row, counters


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        'case', 'category', 'family', 'span', 'update', 'crash_phase',
        'first_signatures', 'retry_signatures',
        'recovered_count_before_retry', 'expected_recovered_count',
        'old_count', 'new_count', 'serve_after_update',
        'expected_serve_after_update', 'state_bytes_total', 'state_bytes_max',
        'first_attempt_ms', 'restart_and_retry_ms', 'passed',
        'messages', 'wire_bytes', 'certify_messages', 'certify_wire_bytes',
        'control_messages', 'control_wire_bytes', 'drops',
        'injected_crashes', 'restarts',
    ]
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def _write_generated(generated: Path, summary: dict) -> None:
    generated.mkdir(parents=True, exist_ok=True)
    macros = (
        f"\\newcommand{{\\DurableCaseCount}}{{{summary['cases']}}}\n"
        f"\\newcommand{{\\DurablePassed}}{{{summary['passed']}}}\n"
        f"\\newcommand{{\\DurableCrashCases}}{{{summary['crash_recovery_cases']}}}\n"
        f"\\newcommand{{\\DurableForkCases}}{{{summary['full_restart_fork_cases']}}}\n"
        f"\\newcommand{{\\DurableCorruptionCases}}{{{summary['corruption_cases']}}}\n"
        f"\\newcommand{{\\DurableCertMessages}}{{{summary['certify_messages']}}}\n"
        f"\\newcommand{{\\DurableCertKiB}}{{{summary['certify_wire_bytes']/1024:.1f}}}\n"
        f"\\newcommand{{\\DurableMedianStateKiB}}{{{summary['median_state_bytes_total']/1024:.1f}}}\n"
    )
    (generated / 'durable-witness-macros.tex').write_text(macros)
    phases = summary['crash_phase_summary']
    lines = [
        r'Crash window & $n$ & Recovered & Retry \\',
        r'\midrule',
    ]
    labels = {
        'before-commit': 'Pre-commit',
        'after-temp-fsync': 'Temp fsync',
        'after-replace': 'Post-replace',
    }
    for phase in CRASH_PHASES:
        item = phases[phase]
        frontier_text = ('old' if item['recovered_old'] == item['cases']
                         else 'new' if item['recovered_new'] == item['cases']
                         else 'mixed')
        lines.append(
            f"{labels[phase]} & {item['cases']} & {frontier_text} & "
            f"{item['passed']}/{item['cases']} \\\\")
    (generated / 'durable-witness-table.tex').write_text('\n'.join(lines) + '\n')


async def run(output: Path, generated: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='durable-witness-') as directory:
        work = Path(directory)
        recovery, c1 = await _recovery_matrix(work / 'recovery')
        forks, c2 = await _durable_fork_matrix(work / 'forks')
        corrupt_a, c3 = await _corruption_case(work / 'corrupt-a', 'truncated')
        corrupt_b, c4 = await _corruption_case(work / 'corrupt-b', 'commitment')
        clock, c5 = await _clock_case(work / 'clock')
    rows = recovery + forks + [corrupt_a, corrupt_b, clock]
    counters = _combine_counters([c1, c2, c3, c4, c5])
    recovery_times = [row['restart_and_retry_ms'] for row in recovery]
    state_totals = [row['state_bytes_total'] for row in rows if row['state_bytes_total'] > 0]
    phase_summary = {}
    for phase in CRASH_PHASES:
        selected = [row for row in recovery if row['crash_phase'] == phase]
        phase_summary[phase] = {
            'cases': len(selected),
            'passed': sum(row['passed'] for row in selected),
            'recovered_old': sum(
                row['recovered_count_before_retry'] == row['old_count']
                for row in selected),
            'recovered_new': sum(
                row['recovered_count_before_retry'] == row['new_count']
                for row in selected),
        }
    result = {
        'processes': 4,
        'separate_processes': True,
        'stable_storage_assumption': 'state file retained and not maliciously rewritten',
        'cases': len(rows),
        'passed': sum(row['passed'] for row in rows),
        'crash_recovery_cases': len(recovery),
        'full_restart_fork_cases': len(forks),
        'corruption_cases': 2,
        'clock_recovery_cases': 1,
        'crash_phase_summary': phase_summary,
        'median_restart_and_retry_ms_host_diagnostic': median(recovery_times),
        'p95_restart_and_retry_ms_host_diagnostic': _p95(recovery_times),
        'median_state_bytes_total': median(state_totals),
        'max_state_bytes_total': max(state_totals),
        **counters,
        'traffic_scope': 'canonical TCP application frames; certification and harness control reported separately',
        'timing_claim': False,
        'rows': rows,
    }
    (output / 'summary.json').write_text(
        json.dumps(result, indent=2, sort_keys=True) + '\n')
    _write_csv(output / 'cases.csv', rows)
    if generated is not None:
        _write_generated(generated, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--generated')
    args = parser.parse_args()
    result = asyncio.run(run(
        Path(args.output), Path(args.generated) if args.generated else None))
    keys = (
        'cases', 'passed', 'crash_recovery_cases',
        'full_restart_fork_cases', 'corruption_cases',
        'certify_messages', 'certify_wire_bytes', 'restarts',
        'injected_crashes',
    )
    print(json.dumps({key: result[key] for key in keys}, sort_keys=True))


if __name__ == '__main__':
    main()
