#!/usr/bin/env python3
"""Finite quorum-set and reachability enumeration for the witnessed design."""
from __future__ import annotations

import argparse
import json
from itertools import combinations, product
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from witness_delta import FAULT_BOUND, QUORUM, WITNESS_IDS, quorum_intersection_audit


def subsets(items):
    items = tuple(items)
    for size in range(len(items) + 1):
        yield from map(set, combinations(items, size))


def run() -> dict:
    identities = set(WITNESS_IDS)
    fault_sets = [set()] + [{wid} for wid in WITNESS_IDS]
    quorum_sets = [set(group) for group in combinations(WITNESS_IDS, QUORUM)]
    safety_checks = 0
    safety_failures = []
    for first in quorum_sets:
        for second in quorum_sets:
            for faulty in fault_sets:
                safety_checks += 1
                if not ((first & second) - faulty):
                    safety_failures.append({
                        'first': sorted(first), 'second': sorted(second),
                        'faulty': sorted(faulty),
                    })
    availability_rows = []
    for reachable in subsets(WITNESS_IDS):
        for faulty in fault_sets:
            honest_reachable = reachable - faulty
            availability_rows.append({
                'reachable': sorted(reachable), 'faulty': sorted(faulty),
                'honest_reachable': len(honest_reachable),
                'honest_signer_threshold_feasible': len(honest_reachable) >= QUORUM,
                'signer_threshold_feasible_if_faulty_cooperates': len(reachable) >= QUORUM,
            })
    guaranteed_counts = {
        str(size): sum(
            row['honest_signer_threshold_feasible']
            for row in availability_rows if len(row['reachable']) == size
        )
        for size in range(len(WITNESS_IDS) + 1)
    }
    # Concurrent-fork schedule abstraction.  The Byzantine identity may sign
    # both branches; each honest identity signs only the first branch it sees.
    # Enumerating every honest first-arrival assignment checks that two 3-of-4
    # quorums can never form simultaneously.
    concurrent_fork_assignments = 0
    concurrent_dual_quorum_failures = []
    for faulty_id in WITNESS_IDS:
        honest = [wid for wid in WITNESS_IDS if wid != faulty_id]
        for choices in product(('left', 'right'), repeat=len(honest)):
            concurrent_fork_assignments += 1
            left = {faulty_id}
            right = {faulty_id}
            for wid, choice in zip(honest, choices):
                (left if choice == 'left' else right).add(wid)
            if len(left) >= QUORUM and len(right) >= QUORUM:
                concurrent_dual_quorum_failures.append({
                    'faulty': faulty_id,
                    'left': sorted(left),
                    'right': sorted(right),
                })
    # Clock boundary: a common report time may be epsilon away from an
    # honest witness reading, while witness and client clocks are each epsilon
    # from real time.  Three epsilon is therefore the conservative margin.
    epsilon = 2; delta = 10
    clock_cases = 0; clock_failures = []; two_epsilon_unsafe = 0
    sign_real = 10
    for witness_error in range(-epsilon, epsilon + 1):
        witness_reading = sign_real + witness_error
        for proposal_offset in range(-epsilon, epsilon + 1):
            issued = witness_reading + proposal_offset
            if issued < 0:
                continue
            for check_real in range(sign_real, sign_real + 2 * delta + 1):
                for client_error in range(-epsilon, epsilon + 1):
                    client_now = check_real + client_error
                    if client_now < 0:
                        continue
                    clock_cases += 1
                    three_guard = (issued <= client_now + 3 * epsilon
                                   and client_now - issued + 3 * epsilon < delta)
                    if three_guard and check_real - sign_real >= delta:
                        clock_failures.append({
                            'witness_error': witness_error,
                            'proposal_offset': proposal_offset,
                            'client_error': client_error,
                            'check_real': check_real,
                        })
                    two_guard = (issued <= client_now + 2 * epsilon
                                 and client_now - issued + 2 * epsilon < delta)
                    if two_guard and check_real - sign_real >= delta:
                        two_epsilon_unsafe += 1

    audit = quorum_intersection_audit()
    return {
        'committee_size': len(WITNESS_IDS), 'fault_bound': FAULT_BOUND,
        'quorum': QUORUM,
        'quorum_sets': len(quorum_sets),
        'fault_sets': len(fault_sets),
        'ordered_quorum_fault_checks': safety_checks,
        'safety_failures': safety_failures,
        'reachability_fault_cases': len(availability_rows),
        'concurrent_fork_assignments': concurrent_fork_assignments,
        'concurrent_dual_quorum_failures': concurrent_dual_quorum_failures,
        'honest_signer_threshold_rows_by_reachable_count': guaranteed_counts,
        'threshold_scope': ('reachability/cardinality only; certification also requires '
                            'a valid timely proposal compatible with retained branches, '
                            'available state capacity and successful persistence; '
                            'reachable split branches do not guarantee progress'),
        'clock_cases': clock_cases,
        'three_epsilon_clock_failures': clock_failures,
        'two_epsilon_negative_controls': two_epsilon_unsafe,
        'audit': audit,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = run()
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({
        'ordered_quorum_fault_checks': result['ordered_quorum_fault_checks'],
        'reachability_fault_cases': result['reachability_fault_cases'],
        'safety_failures': len(result['safety_failures']),
        'concurrent_dual_quorum_failures': len(
            result['concurrent_dual_quorum_failures']),
        'three_epsilon_clock_failures': len(result['three_epsilon_clock_failures']),
        'two_epsilon_negative_controls': result['two_epsilon_negative_controls'],
    }, sort_keys=True))
    if (result['safety_failures'] or result['concurrent_dual_quorum_failures']
            or result['three_epsilon_clock_failures']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
