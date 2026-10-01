#!/usr/bin/env python3
"""Deterministic cache-renewal size study for three honest-issuer evidence paths.

The study uses the protocol's canonical JSON encoder and fixed-length stand-ins
for Ed25519 signatures and SHA-256 commitments.  Because both encodings have
fixed lengths in the executable fixture, this produces exact byte lengths for
the modeled schemas without spending the campaign on repeated cryptography.
A cryptographic parity check compares independently built model objects with
actual reports, and directed actual-protocol checks exercise every update type.

This is an encoded-size study, not a latency or production-throughput benchmark.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import random
import statistics
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from codec import NAMESPACES, encode
from fixtures import graph

SIGNATURE = 'S' * 88
DIGEST = 'D' * 44
SCOPE = 'H' * 44
BATCH = 128
DELTA = 10
QUERIES = 32
SEED = 20260911
STRATEGIES = ('prefix', 'cached-status', 'scope-delta')
ORDERS = ('increasing', 'decreasing', 'random', 'hot')
CHURN_LEVELS = (0, 1, 4, 16)
FAMILIES = ('public-lock', 'generated')
SPANS = (1, 3, 6)


def wire_bytes(value: object) -> int:
    return len(encode(value) + b'\n')


def tx(request: dict, response: dict) -> dict[str, int]:
    return {
        'wire_bytes': wire_bytes(request) + wire_bytes(response),
        'reply_bytes': wire_bytes(response),
        'messages': 2,
    }


def add_cost(total: dict[str, int], delta: dict[str, int]) -> None:
    for key in ('wire_bytes', 'reply_bytes', 'messages'):
        total[key] += delta[key]


def ns_of(key: str) -> str:
    return key.split('/', 1)[0]


def closure(graph_map: dict[str, list[str]], root: str) -> set[str]:
    seen: set[str] = set()
    pending = [root]
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        pending.extend(graph_map[key])
    return seen


def manifest_data(ns: str, name: str, deps: Iterable[str], *,
                  blob: str | None = None) -> dict:
    manifest = {
        'ns': ns,
        'key': f'{ns}/{name}',
        'deps': sorted(deps),
        'epoch': 0,
        'publisher': f'publisher:{ns}:0',
        'cap': f'cap:{ns}:0',
        'blob': blob if blob is not None else 'object:' + name,
    }
    return {'manifest': manifest, 'signature': SIGNATURE}


def receipt(ns: str, seq: int, kind: str, data: dict, now: int) -> dict:
    body = {
        'ns': ns, 'seq': seq,
        'previous': '' if seq == 1 else DIGEST,
        'accepted': now, 'kind': kind, 'data': deepcopy(data),
    }
    return {'body': body, 'signature': SIGNATURE}


class ModelAuthority:
    def __init__(self, ns: str):
        self.ns = ns
        self.log: list[dict] = []

    def append(self, kind: str, data: dict, now: int) -> None:
        self.log.append(receipt(self.ns, len(self.log) + 1, kind, data, now))

    def head(self, now: int) -> dict:
        body = {
            'ns': self.ns,
            'count': len(self.log),
            'tip': DIGEST if self.log else '',
            'issued': now,
        }
        return {'body': body, 'signature': SIGNATURE}


def fold_status(log: list[dict], key: str, count: int | None = None) -> dict:
    prefix = log if count is None else log[:count]
    manifests = [
        event['body']['data']['manifest']
        for event in prefix
        if event['body']['kind'] == 'publish'
        and event['body']['data']['manifest']['key'] == key
    ]
    manifest = manifests[0] if manifests else None
    valid = bool(manifests) and all(other == manifest for other in manifests)
    for event in prefix:
        body = event['body']
        if body['kind'] == 'revoke' and body['data']['target'] == key:
            valid = False
        if (manifest is not None and body['kind'] == 'revoke_cap'
                and body['data']['target'] == manifest['cap']):
            valid = False
    return {'key': key, 'manifest': manifest, 'valid': valid}


def full_status(ns: str, authority: ModelAuthority,
                keys: Iterable[str], now: int) -> dict:
    ordered = sorted(keys)
    body = {
        'ns': ns,
        'count': len(authority.log),
        'issued': now,
        'objects': [fold_status(authority.log, key) for key in ordered],
    }
    return {'body': body, 'signature': SIGNATURE}


def compact_status(ns: str, authority: ModelAuthority,
                   keys: Iterable[str], now: int) -> dict:
    ordered = sorted(keys)
    states = []
    for key in ordered:
        item = fold_status(authority.log, key)
        states.append({
            'manifest': DIGEST if item['manifest'] is not None else '',
            'valid': item['valid'],
        })
    body = {
        'ns': ns,
        'count': len(authority.log),
        'issued': now,
        'keys': DIGEST,
        'states': states,
    }
    return {'body': body, 'signature': SIGNATURE}


def scope_projection(authority: ModelAuthority, keys: Iterable[str],
                     start: int) -> dict[str, list[str]]:
    ordered = sorted(keys)
    old = {key: fold_status(authority.log, key, start) for key in ordered}
    current = {key: fold_status(authority.log, key) for key in ordered}
    conflicts: list[str] = []
    for key in ordered:
        before = old[key]
        after = current[key]
        if (before['manifest'] is not None and before['valid']
                and after['manifest'] is not None and not after['valid']
                and any(
                    event['body']['kind'] == 'publish'
                    and event['body']['data']['manifest']['key'] == key
                    and event['body']['data']['manifest'] != before['manifest']
                    for event in authority.log[start:]
                )):
            conflicts.append(key)
    keyset = set(ordered)
    caps = {
        item['manifest']['cap']
        for item in old.values()
        if item['manifest'] is not None and item['valid']
    }
    revoked_keys: list[str] = []
    revoked_caps: list[str] = []
    for event in authority.log[start:]:
        body = event['body']
        if body['kind'] == 'revoke' and body['data']['target'] in keyset:
            revoked_keys.append(body['data']['target'])
        elif body['kind'] == 'revoke_cap' and body['data']['target'] in caps:
            revoked_caps.append(body['data']['target'])
    return {
        'conflicts': sorted(set(conflicts)),
        'revoked_keys': sorted(set(revoked_keys)),
        'revoked_caps': sorted(set(revoked_caps)),
    }


def scope_register(ns: str, authority: ModelAuthority,
                   keys: Iterable[str], now: int) -> dict:
    ordered = sorted(keys)
    body = {
        'op': 'register', 'ns': ns, 'scope': SCOPE,
        'count': len(authority.log), 'issued': now,
        'objects': [fold_status(authority.log, key) for key in ordered],
    }
    return {'body': body, 'signature': SIGNATURE}


def scope_renew(ns: str, authority: ModelAuthority, keys: Iterable[str],
                start: int, now: int) -> dict:
    body = {
        'op': 'renew', 'ns': ns, 'scope': SCOPE,
        'from': start, 'count': len(authority.log), 'issued': now,
        **scope_projection(authority, keys, start),
    }
    return {'body': body, 'signature': SIGNATURE}


def scope_extend(ns: str, authority: ModelAuthority, old_keys: Iterable[str],
                 additions: Iterable[str], start: int, now: int) -> dict:
    body = {
        'op': 'extend', 'ns': ns, 'from_scope': SCOPE, 'scope': SCOPE,
        'from': start, 'count': len(authority.log), 'issued': now,
        **scope_projection(authority, old_keys, start),
        'objects': [fold_status(authority.log, key) for key in sorted(additions)],
    }
    return {'body': body, 'signature': SIGNATURE}


def build_model(family: str, span: int) -> tuple[dict[str, list[str]], str,
                                                  dict, dict[str, ModelAuthority]]:
    graph_map, root, dimensions = graph(family, span)
    authorities = {ns: ModelAuthority(ns) for ns in NAMESPACES}
    for ns, authority in authorities.items():
        authority.append('grant', {
            'cap': f'cap:{ns}:0', 'publisher': f'publisher:{ns}:0',
            'epoch': 0, 'rights': ['publish'],
        }, 0)
    for key, deps in sorted(graph_map.items()):
        ns, name = key.split('/', 1)
        authorities[ns].append('publish', manifest_data(ns, name, deps), 0)
    return graph_map, root, dimensions, authorities


def snapshot_transaction(authority: ModelAuthority, start: int,
                         now: int) -> tuple[dict[str, int], int, int]:
    total = {'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0}
    cursor = start
    events = 0
    while True:
        request = {
            'op': 'snapshot', 'ns': authority.ns, 'start': cursor,
            'now': now, 'batch': BATCH,
        }
        batch = authority.log[cursor:cursor + BATCH]
        response = {'events': batch, 'heads': [authority.head(now)]}
        add_cost(total, tx(request, response))
        cursor += len(batch)
        events += len(batch)
        if cursor >= len(authority.log):
            return total, cursor, events


def head_transaction(authority: ModelAuthority, now: int) -> dict[str, int]:
    request = {
        'op': 'snapshot', 'ns': authority.ns,
        'start': len(authority.log), 'now': now, 'batch': BATCH,
    }
    response = {'events': [], 'heads': [authority.head(now)]}
    return tx(request, response)


@dataclass
class PrefixClient:
    counts: dict[str, int] = field(default_factory=dict)

    def refresh(self, authority: ModelAuthority, now: int) -> tuple[dict[str, int], str]:
        cost, count, events = snapshot_transaction(
            authority, self.counts.get(authority.ns, 0), now)
        self.counts[authority.ns] = count
        return cost, f'prefix:{events}' if events else 'head'

    def state_bytes(self, authorities: dict[str, ModelAuthority]) -> int:
        value = {
            ns: authorities[ns].log[:count]
            for ns, count in sorted(self.counts.items())
        }
        return len(encode({'prefixes': value}))


@dataclass
class StatusClient:
    objects: dict[str, dict] = field(default_factory=dict)
    head_count: dict[str, int] = field(default_factory=dict)
    head_issued: dict[str, int] = field(default_factory=dict)

    def _full_tx(self, authority: ModelAuthority, keys: list[str], now: int) -> tuple[dict[str, int], dict]:
        request = {'op': 'status', 'ns': authority.ns, 'keys': keys, 'now': now}
        response = full_status(authority.ns, authority, keys, now)
        return tx(request, response), response

    def _compact_tx(self, authority: ModelAuthority, keys: list[str], now: int) -> tuple[dict[str, int], dict]:
        request = {'op': 'compact-status', 'ns': authority.ns,
                   'keys': keys, 'now': now}
        response = compact_status(authority.ns, authority, keys, now)
        return tx(request, response), response

    def _apply_full(self, report: dict) -> None:
        body = report['body']
        for item in body['objects']:
            self.objects[item['key']] = {
                'manifest': item['manifest'], 'valid': item['valid'],
                'count': body['count'], 'issued': body['issued'],
            }
        self.head_count[body['ns']] = body['count']
        self.head_issued[body['ns']] = body['issued']

    def _apply_compact(self, report: dict, keys: list[str]) -> None:
        body = report['body']
        for key, state in zip(keys, body['states']):
            item = self.objects[key]
            item['valid'] = state['valid']
            item['count'] = body['count']
            item['issued'] = body['issued']
        self.head_count[body['ns']] = body['count']
        self.head_issued[body['ns']] = body['issued']

    def refresh(self, authority: ModelAuthority, needed: set[str],
                now: int) -> tuple[dict[str, int], str]:
        ns = authority.ns
        current = len(authority.log)
        ordered = sorted(needed)
        missing = [key for key in ordered if key not in self.objects]
        stale = [key for key in ordered
                 if key in self.objects and self.objects[key]['count'] != current]

        if not missing and not stale:
            cost = head_transaction(authority, now)
            self.head_count[ns] = current
            self.head_issued[ns] = now
            return cost, 'head'

        # Two legal cache-aware plans have the same postcondition: refresh the
        # complete needed set at the current frontier.  Choose the smaller
        # encoded transaction set, strengthening rather than handicapping this
        # baseline.
        split_cost = {'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0}
        split_reports: list[tuple[str, list[str], dict]] = []
        if stale:
            cost, report = self._compact_tx(authority, stale, now)
            add_cost(split_cost, cost)
            split_reports.append(('compact', stale, report))
        if missing:
            cost, report = self._full_tx(authority, missing, now)
            add_cost(split_cost, cost)
            split_reports.append(('full', missing, report))

        full_cost, full_report = self._full_tx(authority, ordered, now)
        use_full = ((full_cost['wire_bytes'], full_cost['reply_bytes'], full_cost['messages'])
                    < (split_cost['wire_bytes'], split_cost['reply_bytes'], split_cost['messages']))
        if use_full:
            self._apply_full(full_report)
            return full_cost, f'full:{len(ordered)}'

        actions: list[str] = []
        for kind, keys, report in split_reports:
            if kind == 'compact':
                self._apply_compact(report, keys)
            else:
                self._apply_full(report)
            actions.append(f'{kind}:{len(keys)}')
        return split_cost, '+'.join(actions)

    def state_bytes(self) -> int:
        return len(encode({
            'objects': {key: self.objects[key] for key in sorted(self.objects)},
            'heads': {
                ns: {'count': self.head_count[ns], 'issued': self.head_issued[ns]}
                for ns in sorted(self.head_count)
            },
        }))


@dataclass
class ScopeClient:
    keys: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    counts: dict[str, int] = field(default_factory=dict)
    issued: dict[str, int] = field(default_factory=dict)
    objects: dict[str, dict] = field(default_factory=dict)

    def refresh(self, authority: ModelAuthority, needed: set[str],
                now: int) -> tuple[dict[str, int], str]:
        ns = authority.ns
        existing = self.keys[ns]
        additions = sorted(needed - existing)
        if ns not in self.counts:
            request = {'op': 'scope-register', 'ns': ns,
                       'keys': sorted(needed), 'now': now}
            response = scope_register(ns, authority, needed, now)
            for item in response['body']['objects']:
                self.objects[item['key']] = {
                    'manifest': item['manifest'], 'valid': item['valid']}
            self.keys[ns] = set(needed)
            self.counts[ns] = len(authority.log)
            self.issued[ns] = now
            return tx(request, response), f'register:{len(needed)}'

        if additions:
            request = {
                'op': 'scope-extend', 'ns': ns, 'scope': SCOPE,
                'from': self.counts[ns], 'add': additions, 'now': now,
            }
            response = scope_extend(ns, authority, existing, additions,
                                    self.counts[ns], now)
            for item in response['body']['objects']:
                self.objects[item['key']] = {
                    'manifest': item['manifest'], 'valid': item['valid']}
            self.keys[ns].update(additions)
            self.counts[ns] = len(authority.log)
            self.issued[ns] = now
            projected = sum(len(response['body'][field]) for field in
                            ('conflicts', 'revoked_keys', 'revoked_caps'))
            return tx(request, response), f'extend:{len(additions)}+causes:{projected}'

        if self.counts[ns] != len(authority.log):
            request = {
                'op': 'scope-renew', 'ns': ns, 'scope': SCOPE,
                'from': self.counts[ns], 'now': now,
            }
            response = scope_renew(ns, authority, existing, self.counts[ns], now)
            self.counts[ns] = len(authority.log)
            self.issued[ns] = now
            projected = sum(len(response['body'][field]) for field in
                            ('conflicts', 'revoked_keys', 'revoked_caps'))
            return tx(request, response), f'renew:causes:{projected}'

        cost = head_transaction(authority, now)
        self.issued[ns] = now
        return cost, 'head'

    def client_state_bytes(self) -> int:
        return len(encode({
            'objects': {key: self.objects[key] for key in sorted(self.objects)},
            'scopes': {
                ns: {'scope': SCOPE, 'count': self.counts[ns],
                     'issued': self.issued[ns], 'keys': sorted(self.keys[ns])}
                for ns in sorted(self.counts)
            },
        }))

    def authority_state_bytes(self) -> int:
        return len(encode({
            'scopes': {
                ns: {SCOPE: sorted(self.keys[ns])}
                for ns in sorted(self.keys) if self.keys[ns]
            }
        }))


def roots_for_order(graph_map: dict[str, list[str]], bundle_root: str,
                    order: str, family: str, span: int) -> list[str]:
    roots = [key for key in graph_map if not key.endswith('/unrelated')]
    closures = {key: closure(graph_map, key) for key in roots}
    if order == 'increasing':
        roots.sort(key=lambda key: (len(closures[key]), key))
    elif order == 'decreasing':
        roots.sort(key=lambda key: (-len(closures[key]), key))
    elif order == 'random':
        roots.sort()
        random.Random(SEED + span + (0 if family == 'public-lock' else 100)).shuffle(roots)
    elif order == 'hot':
        roots = [bundle_root]
    else:
        raise ValueError(order)
    return [roots[index % len(roots)] for index in range(QUERIES)]


def add_unrelated_churn(authorities: dict[str, ModelAuthority], support: set[str],
                        step: int, count: int, now: int) -> None:
    for ns in sorted(support):
        for index in range(count):
            name = f'churn-{step:03d}-{index:03d}'
            authorities[ns].append('publish', manifest_data(ns, name, []), now)


def run_trace(family: str, span: int, order: str, churn: int) -> dict:
    graph_map, bundle_root, dimensions, authorities = build_model(family, span)
    trace = roots_for_order(graph_map, bundle_root, order, family, span)
    closures = {root: closure(graph_map, root) for root in set(trace)}
    clients = {
        'prefix': PrefixClient(),
        'cached-status': StatusClient(),
        'scope-delta': ScopeClient(),
    }
    totals = {
        name: {'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0}
        for name in STRATEGIES
    }
    peak_client = {name: 0 for name in STRATEGIES}
    peak_scope_authority = 0
    rows = []

    for step, root in enumerate(trace):
        now = 1 + step * DELTA
        reached = closures[root]
        support = {ns_of(key) for key in reached}
        needed: dict[str, set[str]] = defaultdict(set)
        for key in reached:
            needed[ns_of(key)].add(key)
        if step and churn:
            add_unrelated_churn(authorities, support, step, churn, now)

        row = {
            'step': step, 'root': root, 'closure_nodes': len(reached),
            'support_namespaces': len(support), 'now': now,
            'strategies': {},
        }
        for ns in sorted(support):
            cost, action = clients['prefix'].refresh(authorities[ns], now)
            add_cost(totals['prefix'], cost)
            row['strategies'].setdefault('prefix', {
                'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0, 'actions': []})
            add_cost(row['strategies']['prefix'], cost)
            row['strategies']['prefix']['actions'].append(f'{ns}:{action}')

            cost, action = clients['cached-status'].refresh(
                authorities[ns], needed[ns], now)
            add_cost(totals['cached-status'], cost)
            row['strategies'].setdefault('cached-status', {
                'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0, 'actions': []})
            add_cost(row['strategies']['cached-status'], cost)
            row['strategies']['cached-status']['actions'].append(f'{ns}:{action}')

            cost, action = clients['scope-delta'].refresh(
                authorities[ns], needed[ns], now)
            add_cost(totals['scope-delta'], cost)
            row['strategies'].setdefault('scope-delta', {
                'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0, 'actions': []})
            add_cost(row['strategies']['scope-delta'], cost)
            row['strategies']['scope-delta']['actions'].append(f'{ns}:{action}')

        peak_client['prefix'] = max(
            peak_client['prefix'], clients['prefix'].state_bytes(authorities))
        peak_client['cached-status'] = max(
            peak_client['cached-status'], clients['cached-status'].state_bytes())
        peak_client['scope-delta'] = max(
            peak_client['scope-delta'], clients['scope-delta'].client_state_bytes())
        peak_scope_authority = max(
            peak_scope_authority, clients['scope-delta'].authority_state_bytes())
        rows.append(row)

    ranking = sorted(STRATEGIES, key=lambda name: (
        totals[name]['wire_bytes'], totals[name]['reply_bytes'], name))
    winner_bytes = totals[ranking[0]]['wire_bytes']
    winners = [name for name in STRATEGIES
               if totals[name]['wire_bytes'] == winner_bytes]
    return {
        'family': family, 'span': span, 'order': order,
        'unrelated_events_per_support_namespace_per_renewal': churn,
        'queries': QUERIES,
        'dimensions': dimensions,
        'totals': totals,
        'winners': winners,
        'peak_client_state_bytes': peak_client,
        'peak_scope_authority_state_bytes': peak_scope_authority,
        'rows': rows,
    }


def run_fault(family: str, span: int, update: str) -> dict:
    graph_map, root, dimensions, authorities = build_model(family, span)
    reached = closure(graph_map, root)
    needed: dict[str, set[str]] = defaultdict(set)
    for key in reached:
        needed[ns_of(key)].add(key)
    target = dimensions['target']
    target_ns = ns_of(target)

    prefix = PrefixClient()
    status = StatusClient()
    scope = ScopeClient()
    for ns in sorted(needed):
        prefix.refresh(authorities[ns], 1)
        status.refresh(authorities[ns], needed[ns], 1)
        scope.refresh(authorities[ns], needed[ns], 1)

    authority = authorities[target_ns]
    if update == 'unrelated-publication':
        authority.append('publish', manifest_data(target_ns, 'fault-unrelated', []), 2)
        expected_serve = True
    elif update == 'artifact-revocation':
        authority.append('revoke', {'target': target}, 2)
        expected_serve = False
    elif update == 'capability-revocation':
        authority.append('revoke_cap', {'target': f'cap:{target_ns}:0'}, 2)
        expected_serve = False
    elif update == 'conflicting-publication':
        _, name = target.split('/', 1)
        authority.append('publish', manifest_data(
            target_ns, name, graph_map[target], blob='conflicting-object'), 2)
        expected_serve = False
    else:
        raise ValueError(update)

    old_scope_count = scope.counts[target_ns]
    costs = {}
    actions = {}
    costs['prefix'], actions['prefix'] = prefix.refresh(authority, 2)
    costs['cached-status'], actions['cached-status'] = status.refresh(
        authority, needed[target_ns], 2)
    costs['scope-delta'], actions['scope-delta'] = scope.refresh(
        authority, needed[target_ns], 2)
    projection = scope_projection(authority, needed[target_ns],
                                  old_scope_count)
    return {
        'family': family, 'span': span, 'update': update,
        'target_namespace_keys': len(needed[target_ns]),
        'expected_serve_after_update': expected_serve,
        'costs': costs, 'actions': actions,
        'scope_projection': projection,
    }


def build_actual_world(family: str, span: int):
    from codec import manifest as actual_manifest
    from fixtures import grant
    from model import Authority

    graph_map, root, dimensions = graph(family, span)
    authorities = {ns: Authority(ns) for ns in NAMESPACES}
    for ns, authority in authorities.items():
        authority.append('grant', grant(ns), 0)
    for key, deps in sorted(graph_map.items()):
        ns, name = key.split('/', 1)
        authority = authorities[ns]
        authority.append('publish', actual_manifest(ns, name, deps), 0)
    return graph_map, root, dimensions, authorities


def actual_protocol_checks() -> dict:
    from cached_status import CachedStatus, check_cached, produce_compact
    from codec import manifest as actual_manifest
    from scope_delta import ScopeCache, ScopeService, check_scopes
    from status_reference import produce

    checks = []
    for family in FAMILIES:
        for span in SPANS:
            for update in ('unrelated-publication', 'artifact-revocation',
                           'capability-revocation', 'conflicting-publication'):
                graph_map, root, dimensions, authorities = build_actual_world(family, span)
                reached = closure(graph_map, root)
                needed: dict[str, set[str]] = defaultdict(set)
                for key in reached:
                    needed[ns_of(key)].add(key)
                services = {ns: ScopeService(authorities[ns]) for ns in needed}
                scopes: dict[str, ScopeCache] = {}
                statuses: dict[str, CachedStatus] = {}
                for ns in sorted(needed):
                    scopes[ns] = ScopeCache(ns)
                    scopes[ns].apply_register(
                        services[ns].register(sorted(needed[ns]), 1), 1)
                    statuses[ns] = CachedStatus(ns)
                    statuses[ns].apply_full(
                        produce(ns, authorities[ns].log, sorted(needed[ns]), 1), 1)
                before_scope = check_scopes(scopes, root, 1)
                before_status = check_cached(statuses, root, 1)
                if not before_scope['serve'] or not before_status['serve']:
                    raise AssertionError('actual registration failed')

                target = dimensions['target']
                target_ns = ns_of(target)
                authority = authorities[target_ns]
                if update == 'unrelated-publication':
                    authority.append('publish', actual_manifest(
                        target_ns, 'actual-unrelated', []), 2)
                    expected = True
                elif update == 'artifact-revocation':
                    authority.append('revoke', {'target': target}, 2)
                    expected = False
                elif update == 'capability-revocation':
                    authority.append('revoke_cap', {
                        'target': f'cap:{target_ns}:0'}, 2)
                    expected = False
                else:
                    _, name = target.split('/', 1)
                    authority.append('publish', actual_manifest(
                        target_ns, name, graph_map[target],
                        blob='actual-conflict'), 2)
                    expected = False

                report = services[target_ns].renew(
                    scopes[target_ns].scope, scopes[target_ns].count, 2)
                scopes[target_ns].apply_renew(report, 2)
                statuses[target_ns].apply_compact(
                    produce_compact(target_ns, authority.log,
                                    sorted(needed[target_ns]), 2),
                    sorted(needed[target_ns]), 2)
                after_scope = check_scopes(scopes, root, 2)
                after_status = check_cached(statuses, root, 2)
                passed = (after_scope['serve'] == expected
                          and after_status['serve'] == expected)
                if not passed:
                    raise AssertionError((family, span, update,
                                          after_scope, after_status))
                checks.append({
                    'kind': 'update', 'family': family, 'span': span,
                    'update': update, 'expected_serve': expected,
                    'scope_reason': after_scope['reason'],
                    'status_reason': after_status['reason'],
                    'passed': True,
                })

            # Extension check: start from the smallest valid root and grow to
            # the complete bundle closure at one unchanged frontier.
            graph_map, root, _, authorities = build_actual_world(family, span)
            bundle = closure(graph_map, root)
            candidates = [key for key in graph_map
                          if not key.endswith('/unrelated') and key != root]
            small = min(candidates, key=lambda key: (len(closure(graph_map, key)), key))
            first = closure(graph_map, small)
            services = {ns: ScopeService(authorities[ns])
                        for ns in {ns_of(key) for key in bundle}}
            scopes: dict[str, ScopeCache] = {}
            by_ns_first: dict[str, set[str]] = defaultdict(set)
            by_ns_bundle: dict[str, set[str]] = defaultdict(set)
            for key in first:
                by_ns_first[ns_of(key)].add(key)
            for key in bundle:
                by_ns_bundle[ns_of(key)].add(key)
            for ns in sorted(by_ns_first):
                cache = ScopeCache(ns)
                cache.apply_register(services[ns].register(
                    sorted(by_ns_first[ns]), 1), 1)
                scopes[ns] = cache
            for ns in sorted(by_ns_bundle):
                if ns not in scopes:
                    cache = ScopeCache(ns)
                    cache.apply_register(services[ns].register(
                        sorted(by_ns_bundle[ns]), 2), 2)
                    scopes[ns] = cache
                else:
                    additions = sorted(by_ns_bundle[ns] - set(scopes[ns].objects))
                    if additions:
                        scopes[ns].apply_extend(services[ns].extend(
                            scopes[ns].scope, scopes[ns].count, additions, 2), 2)
                    else:
                        scopes[ns].apply_head(authorities[ns].head(2), 2)
            verdict = check_scopes(scopes, root, 2)
            if not verdict['serve']:
                raise AssertionError((family, span, 'extension', verdict))
            checks.append({
                'kind': 'extension', 'family': family, 'span': span,
                'from_closure': len(first), 'to_closure': len(bundle),
                'passed': True,
            })
    update_count = sum(check['kind'] == 'update' for check in checks)
    extension_count = sum(check['kind'] == 'extension' for check in checks)
    return {'checks': checks, 'count': len(checks),
            'passed': sum(check['passed'] for check in checks),
            'update_count': update_count,
            'extension_count': extension_count}


def fixed_length_parity() -> dict:
    """Compare independent fixed-token builders with actual signed objects."""
    from cached_status import produce_compact as actual_compact
    from scope_delta import ScopeService
    from status_reference import produce as actual_full

    graph_map, root, _, actual = build_actual_world('public-lock', 1)
    _, _, _, model = build_model('public-lock', 1)
    reached = closure(graph_map, root)
    keys = sorted(key for key in reached if ns_of(key) == 'n1')[:5]
    ns = 'n1'
    service = ScopeService(actual[ns])
    actual_register = service.register(keys, 1)
    model_register = scope_register(ns, model[ns], keys, 1)
    actual[ns].append('publish', __import__('codec').manifest(
        ns, 'parity-unrelated', []), 2)
    model[ns].append('publish', manifest_data(ns, 'parity-unrelated', []), 2)
    actual_renew = service.renew(actual_register['body']['scope'],
                                 actual_register['body']['count'], 2)
    model_renew = scope_renew(ns, model[ns], keys,
                              model_register['body']['count'], 2)

    pairs = {
        'grant-receipt': (actual[ns].log[0], model[ns].log[0]),
        'publish-receipt': (actual[ns].log[1], model[ns].log[1]),
        'head': (actual[ns].head(2), model[ns].head(2)),
        'full-status': (actual_full(ns, actual[ns].log, keys, 2),
                        full_status(ns, model[ns], keys, 2)),
        'compact-status': (actual_compact(ns, actual[ns].log, keys, 2),
                           compact_status(ns, model[ns], keys, 2)),
        'scope-register': (actual_register, model_register),
        'scope-renew': (actual_renew, model_renew),
        'snapshot-response': (
            {'events': actual[ns].log[-2:], 'heads': [actual[ns].head(2)]},
            {'events': model[ns].log[-2:], 'heads': [model[ns].head(2)]}),
    }
    rows = []
    for name, (actual_object, model_object) in pairs.items():
        actual_bytes = wire_bytes(actual_object)
        model_bytes = wire_bytes(model_object)
        if actual_bytes != model_bytes:
            raise AssertionError((name, actual_bytes, model_bytes))
        rows.append({'object': name, 'actual_bytes': actual_bytes,
                     'model_bytes': model_bytes, 'equal': True})
    return {'objects': rows, 'count': len(rows),
            'all_equal': all(row['equal'] for row in rows)}


def median(values: Iterable[int | float]) -> float:
    return float(statistics.median(list(values)))


def percentile(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError('empty percentile')
    index = round((len(ordered) - 1) * fraction)
    return float(ordered[index])


def summarize(traces: list[dict], faults: list[dict], parity: dict,
              actual_checks: dict) -> dict:
    winners = Counter()
    for trace in traces:
        for winner in trace['winners']:
            winners[winner] += 1 / len(trace['winners'])
    scope_ratios = []
    scope_prefix_ratios = []
    status_prefix_ratios = []
    scope_no_worse = 0
    for trace in traces:
        scope = trace['totals']['scope-delta']['wire_bytes']
        prefix = trace['totals']['prefix']['wire_bytes']
        status = trace['totals']['cached-status']['wire_bytes']
        best_other = min(prefix, status)
        ratio = scope / best_other
        scope_ratios.append(ratio)
        scope_prefix_ratios.append(scope / prefix)
        status_prefix_ratios.append(status / prefix)
        scope_no_worse += ratio <= 1.0

    by_churn = []
    for churn in CHURN_LEVELS:
        subset = [trace for trace in traces
                  if trace['unrelated_events_per_support_namespace_per_renewal'] == churn]
        row = {'churn': churn, 'traces': len(subset)}
        for strategy in STRATEGIES:
            values = [trace['totals'][strategy]['wire_bytes'] for trace in subset]
            row[strategy] = {
                'median_wire_bytes': median(values),
                'min_wire_bytes': min(values),
                'max_wire_bytes': max(values),
            }
        row['scope_wins'] = sum('scope-delta' in trace['winners'] for trace in subset)
        by_churn.append(row)

    fault_summary = []
    updates = ('unrelated-publication', 'artifact-revocation',
               'capability-revocation', 'conflicting-publication')
    for update in updates:
        subset = [row for row in faults if row['update'] == update]
        item = {'update': update, 'conditions': len(subset)}
        for strategy in STRATEGIES:
            values = [row['costs'][strategy]['wire_bytes'] for row in subset]
            item[strategy] = {
                'median_wire_bytes': median(values),
                'min_wire_bytes': min(values),
                'max_wire_bytes': max(values),
            }
        fault_summary.append(item)

    return {
        'study': {
            'traces': len(traces), 'queries_per_trace': QUERIES,
            'total_queries': len(traces) * QUERIES,
            'families': list(FAMILIES), 'spans': list(SPANS),
            'orders': list(ORDERS), 'churn_levels': list(CHURN_LEVELS),
            'delta_ticks': DELTA,
            'wire_definition': 'canonical JSON request plus newline and response plus newline',
            'timing_claim': False,
        },
        'winner_equivalents': dict(sorted(winners.items())),
        'scope_delta_vs_best_other': {
            'no_worse_traces': scope_no_worse,
            'traces': len(traces),
            'median_ratio': median(scope_ratios),
            'p90_ratio': percentile(scope_ratios, 0.90),
            'max_ratio': max(scope_ratios),
            'min_ratio': min(scope_ratios),
        },
        'scope_delta_vs_prefix': {
            'no_worse_traces': sum(value <= 1.0 for value in scope_prefix_ratios),
            'strictly_smaller_traces': sum(value < 1.0 for value in scope_prefix_ratios),
            'traces': len(traces),
            'median_ratio': median(scope_prefix_ratios),
            'max_ratio': max(scope_prefix_ratios),
            'min_ratio': min(scope_prefix_ratios),
        },
        'cached_status_vs_prefix': {
            'no_worse_traces': sum(value <= 1.0 for value in status_prefix_ratios),
            'strictly_smaller_traces': sum(value < 1.0 for value in status_prefix_ratios),
            'traces': len(traces),
            'median_ratio': median(status_prefix_ratios),
            'max_ratio': max(status_prefix_ratios),
            'min_ratio': min(status_prefix_ratios),
        },
        'by_churn': by_churn,
        'fault_updates': fault_summary,
        'state_tradeoff': {
            'median_peak_scope_authority_state_bytes': median(
                trace['peak_scope_authority_state_bytes'] for trace in traces),
            'max_peak_scope_authority_state_bytes': max(
                trace['peak_scope_authority_state_bytes'] for trace in traces),
            'median_peak_client_state_bytes': {
                strategy: median(trace['peak_client_state_bytes'][strategy]
                                 for trace in traces)
                for strategy in STRATEGIES
            },
        },
        'fixed_length_parity': parity,
        'actual_protocol_checks': {
            'count': actual_checks['count'],
            'passed': actual_checks['passed'],
            'update_count': actual_checks.get('update_count', 0),
            'extension_count': actual_checks.get('extension_count', 0),
        },
    }


def write_csvs(output: Path, traces: list[dict], faults: list[dict]) -> None:
    with (output / 'traces.csv').open('w', newline='') as handle:
        fields = ['family', 'span', 'order', 'churn', 'queries', 'winner',
                  'prefix_wire_bytes', 'cached_status_wire_bytes',
                  'scope_delta_wire_bytes', 'prefix_reply_bytes',
                  'cached_status_reply_bytes', 'scope_delta_reply_bytes',
                  'prefix_messages', 'cached_status_messages',
                  'scope_delta_messages', 'prefix_peak_client_state_bytes',
                  'cached_status_peak_client_state_bytes',
                  'scope_delta_peak_client_state_bytes',
                  'scope_authority_state_bytes']
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trace in traces:
            writer.writerow({
                'family': trace['family'], 'span': trace['span'],
                'order': trace['order'],
                'churn': trace['unrelated_events_per_support_namespace_per_renewal'],
                'queries': trace['queries'],
                'winner': '+'.join(trace['winners']),
                'prefix_wire_bytes': trace['totals']['prefix']['wire_bytes'],
                'cached_status_wire_bytes': trace['totals']['cached-status']['wire_bytes'],
                'scope_delta_wire_bytes': trace['totals']['scope-delta']['wire_bytes'],
                'prefix_reply_bytes': trace['totals']['prefix']['reply_bytes'],
                'cached_status_reply_bytes': trace['totals']['cached-status']['reply_bytes'],
                'scope_delta_reply_bytes': trace['totals']['scope-delta']['reply_bytes'],
                'prefix_messages': trace['totals']['prefix']['messages'],
                'cached_status_messages': trace['totals']['cached-status']['messages'],
                'scope_delta_messages': trace['totals']['scope-delta']['messages'],
                'prefix_peak_client_state_bytes': trace['peak_client_state_bytes']['prefix'],
                'cached_status_peak_client_state_bytes': trace['peak_client_state_bytes']['cached-status'],
                'scope_delta_peak_client_state_bytes': trace['peak_client_state_bytes']['scope-delta'],
                'scope_authority_state_bytes': trace['peak_scope_authority_state_bytes'],
            })

    with (output / 'faults.csv').open('w', newline='') as handle:
        fields = ['family', 'span', 'update', 'target_namespace_keys',
                  'expected_serve_after_update', 'prefix_wire_bytes',
                  'cached_status_wire_bytes', 'scope_delta_wire_bytes',
                  'prefix_reply_bytes', 'cached_status_reply_bytes',
                  'scope_delta_reply_bytes', 'prefix_action',
                  'cached_status_action', 'scope_delta_action',
                  'scope_conflicts', 'scope_revoked_keys', 'scope_revoked_caps']
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in faults:
            writer.writerow({
                'family': row['family'], 'span': row['span'],
                'update': row['update'],
                'target_namespace_keys': row['target_namespace_keys'],
                'expected_serve_after_update': row['expected_serve_after_update'],
                'prefix_wire_bytes': row['costs']['prefix']['wire_bytes'],
                'cached_status_wire_bytes': row['costs']['cached-status']['wire_bytes'],
                'scope_delta_wire_bytes': row['costs']['scope-delta']['wire_bytes'],
                'prefix_reply_bytes': row['costs']['prefix']['reply_bytes'],
                'cached_status_reply_bytes': row['costs']['cached-status']['reply_bytes'],
                'scope_delta_reply_bytes': row['costs']['scope-delta']['reply_bytes'],
                'prefix_action': row['actions']['prefix'],
                'cached_status_action': row['actions']['cached-status'],
                'scope_delta_action': row['actions']['scope-delta'],
                'scope_conflicts': len(row['scope_projection']['conflicts']),
                'scope_revoked_keys': len(row['scope_projection']['revoked_keys']),
                'scope_revoked_caps': len(row['scope_projection']['revoked_caps']),
            })


def tex_number(value: float, digits: int = 1) -> str:
    return f'{value:.{digits}f}'


def write_tex(generated: Path, summary: dict) -> None:
    generated.mkdir(parents=True, exist_ok=True)
    comparison = summary['scope_delta_vs_best_other']
    prefix_comparison = summary['scope_delta_vs_prefix']
    state = summary['state_tradeoff']
    macros = [
        '% Generated by artifact/src/renewal_study.py; do not edit.',
        f"\\newcommand{{\\RenewalTraceCount}}{{{summary['study']['traces']}\\xspace}}",
        f"\\newcommand{{\\RenewalQueryCount}}{{{summary['study']['total_queries']:,}\\xspace}}",
        f"\\newcommand{{\\ScopeNoWorseCount}}{{{comparison['no_worse_traces']}\\xspace}}",
        f"\\newcommand{{\\ScopeBeatsPrefixCount}}{{{prefix_comparison['strictly_smaller_traces']}\\xspace}}",
        f"\\newcommand{{\\ScopePrefixMedianRatio}}{{{prefix_comparison['median_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\ScopePrefixMaxRatio}}{{{prefix_comparison['max_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\ScopeMedianRatio}}{{{comparison['median_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\ScopeMaxRatio}}{{{comparison['max_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\ScopeActualChecks}}{{{summary['actual_protocol_checks']['passed']}\\xspace}}",
        f"\\newcommand{{\\ScopeActualUpdateChecks}}{{{summary['actual_protocol_checks']['update_count']}\\xspace}}",
        f"\\newcommand{{\\ScopeActualExtensionChecks}}{{{summary['actual_protocol_checks']['extension_count']}\\xspace}}",
        f"\\newcommand{{\\ScopeParityObjects}}{{{summary['fixed_length_parity']['count']}\\xspace}}",
        f"\\newcommand{{\\ScopeMedianAuthorityState}}{{{int(round(state['median_peak_scope_authority_state_bytes'])):,}\\xspace}}",
        f"\\newcommand{{\\ScopeMaxAuthorityState}}{{{int(round(state['max_peak_scope_authority_state_bytes'])):,}\\xspace}}",
        '',
    ]
    (generated / 'renewal-macros.tex').write_text('\n'.join(macros))

    lines = [
        '% Generated by artifact/src/renewal_study.py; do not edit.',
        '\\begin{tabular}{@{}rrrrr@{}}',
        '\\toprule',
        'Unrelated events & Prefix & Cached status & Scope delta & Scope wins \\\\',
        'per namespace & (KiB) & (KiB) & (KiB) & /24 \\\\',
        '\\midrule',
    ]
    for row in summary['by_churn']:
        lines.append(
            f"{row['churn']} & "
            f"{tex_number(row['prefix']['median_wire_bytes'] / 1024)} & "
            f"{tex_number(row['cached-status']['median_wire_bytes'] / 1024)} & "
            f"{tex_number(row['scope-delta']['median_wire_bytes'] / 1024)} & "
            f"{row['scope_wins']} \\\\"
        )
    lines += ['\\bottomrule', '\\end{tabular}', '']
    (generated / 'renewal-table.tex').write_text('\n'.join(lines))

    labels = {
        'unrelated-publication': 'Unrelated publish',
        'artifact-revocation': 'Artifact revoke',
        'capability-revocation': 'Capability revoke',
        'conflicting-publication': 'Conflicting publish',
    }
    lines = [
        '% Generated by artifact/src/renewal_study.py; do not edit.',
        '\\begin{tabular}{@{}lrrr@{}}',
        '\\toprule',
        'One changed-namespace update & Prefix & Cached status & Scope delta \\\\',
        ' & (bytes) & (bytes) & (bytes) \\\\',
        '\\midrule',
    ]
    for row in summary['fault_updates']:
        lines.append(
            f"{labels[row['update']]} & "
            f"{int(round(row['prefix']['median_wire_bytes'])):,} & "
            f"{int(round(row['cached-status']['median_wire_bytes'])):,} & "
            f"{int(round(row['scope-delta']['median_wire_bytes'])):,} \\\\"
        )
    lines += ['\\bottomrule', '\\end{tabular}', '']
    (generated / 'renewal-fault-table.tex').write_text('\n'.join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument('--output', type=Path, default=root / 'results' / 'renewal')
    parser.add_argument('--generated', type=Path,
                        default=root.parent / 'paper' / 'generated')
    parser.add_argument('--skip-actual', action='store_true',
                        help='skip cryptographic directed checks (size study still runs)')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    parity = fixed_length_parity()
    actual = ({'checks': [], 'count': 0, 'passed': 0,
               'update_count': 0, 'extension_count': 0}
              if args.skip_actual else actual_protocol_checks())
    traces = [
        run_trace(family, span, order, churn)
        for family in FAMILIES
        for span in SPANS
        for order in ORDERS
        for churn in CHURN_LEVELS
    ]
    faults = [
        run_fault(family, span, update)
        for family in FAMILIES
        for span in SPANS
        for update in ('unrelated-publication', 'artifact-revocation',
                       'capability-revocation', 'conflicting-publication')
    ]
    summary = summarize(traces, faults, parity, actual)

    with gzip.open(args.output / 'traces.json.gz', 'wt', encoding='utf-8',
                   compresslevel=9) as handle:
        json.dump(traces, handle, sort_keys=True, separators=(',', ':'))
        handle.write('\n')
    (args.output / 'faults.json').write_text(
        json.dumps(faults, indent=2, sort_keys=True) + '\n')
    (args.output / 'actual-checks.json').write_text(
        json.dumps(actual, indent=2, sort_keys=True) + '\n')
    (args.output / 'summary.json').write_text(
        json.dumps(summary, indent=2, sort_keys=True) + '\n')
    write_csvs(args.output, traces, faults)
    write_tex(args.generated, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
