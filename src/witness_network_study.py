#!/usr/bin/env python3
"""Four-listener network checks for witnessed exact-scope reports.

The matrix reuses the two dependency families, three namespace spans, and four
single-update classes from the renewal study.  For every condition it sends a
valid report through four distinct loopback witness listeners; for each
invalidating update it also sends an omission attack in a fresh case.  Separate
availability and fork cases exercise partition and quorum-intersection paths.
All listener traffic uses the actual Ed25519 fixture and canonical JSON framing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from copy import deepcopy
from pathlib import Path

from codec import commitment, manifest, sign
from fixtures import graph, grant
from model import Authority
from renewal_study import closure
from witness_delta import (
    QUORUM, WitnessScopeCache, _projection, _scope_id, _status,
)
from witness_network import NetworkCounters, WitnessTCPNetwork

FAMILIES = ('public-lock', 'generated')
SPANS = (1, 3, 6)
UPDATES = ('unrelated-publication', 'artifact-revocation',
           'capability-revocation', 'conflicting-publication')


def delta(now: NetworkCounters, before: NetworkCounters) -> dict[str, int]:
    return {
        'messages': now.messages - before.messages,
        'wire_bytes': now.wire_bytes - before.wire_bytes,
        'drops': now.drops - before.drops,
    }


def frontier(authority: Authority, now: int) -> dict:
    return {
        'count': len(authority.log),
        'tip': commitment(authority.log[-1]) if authority.log else '',
        'issued': now,
    }


def certificate(body: dict, signatures: list[dict]) -> dict:
    return {
        'body': deepcopy(body),
        'authority_signature': sign('authority:' + body['ns'], body),
        'witnesses': signatures[:QUORUM],
    }


def build_condition(family: str, span: int) -> tuple[Authority, list[str], str, dict[str, list[str]]]:
    graph_map, root, dimensions = graph(family, span)
    reached = closure(graph_map, root)
    target = dimensions['target']; target_ns = target.split('/', 1)[0]
    authority = Authority(target_ns)
    authority.append('grant', grant(target_ns), 0)
    for key, deps in sorted(graph_map.items()):
        ns, name = key.split('/', 1)
        if ns == target_ns:
            authority.append('publish', manifest(ns, name, deps), 0)
    keys = sorted(key for key in reached if key.startswith(target_ns + '/'))
    if target not in keys or not keys:
        raise ValueError('target scope construction failed')
    return authority, keys, target, graph_map


def register_body(authority: Authority, keys: list[str], now: int) -> dict:
    ordered = tuple(keys)
    return {
        'op': 'register', 'ns': authority.ns,
        'scope': _scope_id(authority.ns, ordered),
        **frontier(authority, now),
        'objects': [_status(authority.log, key) for key in ordered],
    }


def apply_update(authority: Authority, graph_map: dict[str, list[str]],
                 target: str, update: str) -> bool:
    ns, name = target.split('/', 1)
    if update == 'unrelated-publication':
        authority.append('publish', manifest(ns, 'network-unrelated', []), 2)
        return True
    if update == 'artifact-revocation':
        authority.append('revoke', {'target': target}, 2)
        return False
    if update == 'capability-revocation':
        authority.append('revoke_cap', {'target': f'cap:{ns}:0'}, 2)
        return False
    if update == 'conflicting-publication':
        authority.append('publish', manifest(
            ns, name, graph_map[target], blob='network-conflict'), 2)
        return False
    raise ValueError(update)


async def initialize_case(network: WitnessTCPNetwork, case_id: str,
                          authority: Authority, keys: list[str], *,
                          faulty=('w0',)) -> tuple[WitnessScopeCache, NetworkCounters]:
    before = deepcopy(network.counters)
    network.configure(case_id, authority.ns, faulty=faulty)
    network.advance(case_id, 1)
    body = register_body(authority, keys, 1)
    signatures = await network.signatures(case_id, body, authority.log)
    if len(signatures) < QUORUM:
        raise RuntimeError('registration did not reach quorum')
    cache = WitnessScopeCache(authority.ns)
    cache.apply_register(certificate(body, signatures), 1)
    return cache, before


async def run(output: Path) -> dict:
    rows = []
    async with WitnessTCPNetwork() as network:
        case_number = 0

        for family in FAMILIES:
            for span in SPANS:
                for update in UPDATES:
                    case_number += 1
                    case_id = f'case-{case_number:03d}-valid'
                    authority, keys, target, graph_map = build_condition(family, span)
                    cache, before = await initialize_case(
                        network, case_id, authority, keys)
                    expected_serve = apply_update(authority, graph_map, target, update)
                    network.advance(case_id, 2)
                    body = {
                        'op': 'renew', 'ns': authority.ns, 'scope': cache.scope,
                        'from': cache.count, **frontier(authority, 2),
                        **_projection(authority.log, tuple(keys), cache.count),
                    }
                    signatures = await network.signatures(case_id, body, authority.log)
                    accepted = len(signatures) >= QUORUM
                    if accepted:
                        cache.apply_renew(certificate(body, signatures), 2)
                    rows.append({
                        'case': case_id, 'family': family, 'span': span,
                        'update': update, 'variant': 'valid',
                        'expected': 'accept', 'accepted': accepted,
                        'signatures': len(signatures),
                        'expected_serve_after_update': expected_serve,
                        **delta(network.counters, before),
                    })

                    if update != 'unrelated-publication':
                        case_number += 1
                        case_id = f'case-{case_number:03d}-omission'
                        authority, keys, target, graph_map = build_condition(family, span)
                        cache, before = await initialize_case(
                            network, case_id, authority, keys)
                        apply_update(authority, graph_map, target, update)
                        network.advance(case_id, 2)
                        body = {
                            'op': 'renew', 'ns': authority.ns, 'scope': cache.scope,
                            'from': cache.count, **frontier(authority, 2),
                            'conflicts': [], 'revoked_keys': [], 'revoked_caps': [],
                        }
                        signatures = await network.signatures(case_id, body, authority.log)
                        rows.append({
                            'case': case_id, 'family': family, 'span': span,
                            'update': update, 'variant': 'omission',
                            'expected': 'reject',
                            'accepted': len(signatures) >= QUORUM,
                            'signatures': len(signatures),
                            'expected_serve_after_update': False,
                            **delta(network.counters, before),
                        })

        # Availability uses an unchanged valid scope so only reachability differs.
        for blocked, expected in ((('w2', 'w3'), 'reject'), (('w3',), 'accept')):
            case_number += 1
            case_id = f'case-{case_number:03d}-availability'
            authority, keys, _, _ = build_condition('public-lock', 1)
            cache, before = await initialize_case(
                network, case_id, authority, keys, faulty=())
            network.advance(case_id, 2)
            body = {
                'op': 'renew', 'ns': authority.ns, 'scope': cache.scope,
                'from': cache.count, **frontier(authority, 2),
                **_projection(authority.log, tuple(keys), cache.count),
            }
            network.blocked = set(blocked)
            signatures = await network.signatures(case_id, body, authority.log)
            network.blocked = set()
            rows.append({
                'case': case_id, 'family': 'public-lock', 'span': 1,
                'update': 'none', 'variant': f'{4-len(blocked)}-responsive',
                'expected': expected, 'accepted': len(signatures) >= QUORUM,
                'signatures': len(signatures), 'expected_serve_after_update': True,
                **delta(network.counters, before),
            })

        # Quorum-acknowledge one branch, then try a conflicting branch whose
        # second quorum overlaps in one Byzantine and one honest witness.
        case_number += 1
        case_id = f'case-{case_number:03d}-fork'
        base, _, target, graph_map = build_condition('public-lock', 1)
        left = deepcopy(base); right = deepcopy(base)
        left.append('revoke', {'target': target}, 2)
        ns, name = target.split('/', 1)
        right.append('publish', manifest(ns, name, graph_map[target], blob='fork'), 2)
        before = deepcopy(network.counters)
        network.configure(case_id, ns, faulty=('w0',))
        network.advance(case_id, 2)
        left_body = {'op':'checkpoint','ns':ns,**frontier(left,2)}
        network.blocked = {'w3'}
        first = await network.signatures(case_id, left_body, left.log)
        network.blocked = {'w1'}
        right_body = {'op':'checkpoint','ns':ns,**frontier(right,2)}
        second = await network.signatures(case_id, right_body, right.log)
        network.blocked = set()
        rows.append({
            'case': case_id, 'family': 'public-lock', 'span': 1,
            'update': 'fork', 'variant': 'conflicting-after-quorum',
            'expected': 'reject', 'accepted': len(second) >= QUORUM,
            'first_signatures': len(first), 'signatures': len(second),
            'expected_serve_after_update': False,
            **delta(network.counters, before),
        })

    passed = sum(
        (row['expected'] == 'accept') == row['accepted']
        and row.get('first_signatures', QUORUM) >= QUORUM
        for row in rows
    )
    valid_rows = [row for row in rows if row['variant'] == 'valid']
    omission_rows = [row for row in rows if row['variant'] == 'omission']
    result = {
        'listener_count': 4,
        'single_process': True,
        'cases': len(rows),
        'valid_matrix_cases': len(valid_rows),
        'omission_attack_cases': len(omission_rows),
        'passed': passed,
        'messages': sum(row['messages'] for row in rows),
        'wire_bytes': sum(row['wire_bytes'] for row in rows),
        'drops': sum(row['drops'] for row in rows),
        'rows': rows,
        'timing_claim': False,
        'traffic_scope': 'registration plus one post-registration report per case',
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = asyncio.run(run(Path(args.output)))
    print(json.dumps({key: result[key] for key in (
        'cases','valid_matrix_cases','omission_attack_cases','passed',
        'messages','wire_bytes')}, sort_keys=True))


if __name__ == '__main__':
    main()
