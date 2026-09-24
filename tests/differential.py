#!/usr/bin/env python3
"""Deterministic random differential check for prefix/status/oracle decisions.

This is a finite randomized checker over generated, fully owned toy histories.
It is not a general proof and performs no network or package execution.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from client import check
from codec import NAMESPACES, manifest, ns_of
from fixtures import grant
from model import Authority, Replica
from oracle import truth
from status_reference import check_status, produce


def run(iterations: int, seed: int) -> dict:
    randomizer = random.Random(seed)
    mismatches = []
    reason_counts: dict[str, int] = {}
    completed = 0
    for index in range(iterations):
        namespaces = NAMESPACES[:randomizer.randint(1, 4)]
        authorities = {ns: Authority(ns) for ns in namespaces}
        histories = {ns: [] for ns in NAMESPACES}
        for ns in namespaces:
            event = authorities[ns].append('grant', grant(ns), 0)
            histories[ns].append(event)

        keys: list[str] = []
        for number in range(randomizer.randint(1, 12)):
            ns = randomizer.choice(namespaces)
            key = f'{ns}/k{number}'
            deps = (randomizer.sample(keys, k=randomizer.randint(0, min(3, len(keys))))
                    if keys else [])
            event = authorities[ns].append(
                'publish', manifest(ns, f'k{number}', deps), 0)
            histories[ns].append(event)
            keys.append(key)
            if randomizer.random() < 0.10:
                duplicate = authorities[ns].append(
                    'publish', manifest(ns, f'k{number}', deps), 0)
                histories[ns].append(duplicate)

        root = randomizer.choice(keys)
        if randomizer.random() < 0.08:
            ns = randomizer.choice(namespaces)
            missing = f'{randomizer.choice(namespaces)}/absent-{index}'
            name = f'missing-root-{index}'
            event = authorities[ns].append(
                'publish', manifest(ns, name, [root, missing]), 0)
            histories[ns].append(event)
            root = f'{ns}/{name}'
            keys.append(root)

        now = randomizer.randint(0, 3)
        operation = randomizer.choice(
            ['none', 'revoke', 'revoke_cap', 'conflict', 'transfer', 'cycle'])
        if operation == 'revoke':
            target = randomizer.choice(keys)
            ns = ns_of(target)
            histories[ns].append(
                authorities[ns].append('revoke', {'target': target}, now))
        elif operation == 'revoke_cap':
            ns = randomizer.choice(namespaces)
            histories[ns].append(authorities[ns].append(
                'revoke_cap', {'target': f'cap:{ns}:0'}, now))
        elif operation == 'conflict':
            target = randomizer.choice(keys)
            ns = ns_of(target)
            name = target.split('/', 1)[1]
            original = next(
                event['body']['data']['manifest']
                for event in histories[ns]
                if event['body']['kind'] == 'publish'
                and event['body']['data']['manifest']['key'] == target)
            histories[ns].append(authorities[ns].append(
                'publish', manifest(ns, name, original['deps'],
                                    blob=f'conflict-{index}'), now))
        elif operation == 'transfer':
            ns = randomizer.choice(namespaces)
            histories[ns].append(authorities[ns].append(
                'transfer', {'epoch': 1}, now))
            histories[ns].append(authorities[ns].append(
                'grant', grant(ns, 1), now))
            if randomizer.random() < 0.5:
                name = f'new-{index}'
                histories[ns].append(authorities[ns].append(
                    'publish', manifest(ns, name, [], epoch=1), now))
        elif operation == 'cycle':
            ns = randomizer.choice(namespaces)
            left = f'{ns}/a-{index}'
            right = f'{ns}/b-{index}'
            histories[ns].append(authorities[ns].append(
                'publish', manifest(ns, f'a-{index}', [right]), now))
            histories[ns].append(authorities[ns].append(
                'publish', manifest(ns, f'b-{index}', [left]), now))
            if randomizer.random() < 0.5:
                root = left

        replica = Replica()
        for ns in namespaces:
            for event in histories[ns]:
                if not replica.ingest(event):
                    raise AssertionError('generated authority event rejected')
            if not replica.cache_head(authorities[ns].head(now)):
                raise AssertionError('generated authority head rejected')

        prefix_certificate = replica.certificate(root, False)
        prefix = check(prefix_certificate, root, now, delta=10, floors={})
        reached, support = replica.discover(root)
        status_certificate = {
            ns: produce(ns, authorities[ns].log,
                        [key for key in reached if ns_of(key) == ns], now)
            for ns in support
        }
        status = check_status(status_certificate, root, now, {}, delta=10)
        oracle = truth(histories, root, now)
        key = f"prefix={prefix['serve']},status={status['serve']},oracle={oracle}"
        reason_counts[key] = reason_counts.get(key, 0) + 1
        completed += 1
        if prefix['serve'] != status['serve'] or prefix['serve'] != oracle:
            mismatches.append({
                'iteration': index, 'operation': operation, 'root': root,
                'prefix': prefix, 'status': status, 'oracle': oracle,
            })
            break

    return {
        'iterations_requested': iterations,
        'iterations_completed': completed,
        'seed': seed,
        'mismatches': mismatches,
        'mismatch_count': len(mismatches),
        'decision_counts': reason_counts,
        'scope': 'finite generated toy histories; not a proof',
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--iterations', type=int, default=500)
    parser.add_argument('--seed', type=int, default=20260911)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.iterations < 1 or args.iterations > 10000:
        raise SystemExit('iterations must be in [1, 10000]')
    result = run(args.iterations, args.seed)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end='')
    if result['mismatch_count']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
