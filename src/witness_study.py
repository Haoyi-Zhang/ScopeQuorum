#!/usr/bin/env python3
"""Deterministic size and fault study for 3-of-4 witnessed scope deltas.

The normal-workload matrix uses the same 96 traces as ``renewal_study``.  It
counts client-plane canonical JSON bytes separately from sequencer-to-witness
synchronization/certification bytes.  Witnesses receive each accepted suffix in
128-event batches and independently co-sign the exact checkpoint or scope body.
The size model uses fixed-length stand-ins for Ed25519 signatures and SHA-256
commitments; selected objects are checked against the actual implementation.

This is an encoded-object/network-accounting study, not a latency, WAN,
storage-engine, or production availability benchmark.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import statistics
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

from codec import commitment, encode, manifest
from fixtures import grant
from model import Authority
from renewal_study import (
    BATCH, CHURN_LEVELS, DELTA, DIGEST, FAMILIES, ORDERS, QUERIES, SIGNATURE,
    SPANS, SCOPE, ModelAuthority, add_cost, add_unrelated_churn, build_model,
    closure, fold_status, manifest_data, ns_of, roots_for_order,
    scope_projection, tx, wire_bytes,
)
from witness_delta import (
    QUORUM, WITNESS_IDS, QuorumUnavailable, WitnessCommittee,
    WitnessScopeCache, WitnessedScopeService, quorum_intersection_audit,
)

STRATEGIES = ('witnessed-prefix', 'witnessed-scope')


def zero_cost() -> dict[str, int]:
    return {'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0}


def tip(authority: ModelAuthority) -> str:
    return DIGEST if authority.log else ''


def witness_items(count: int = QUORUM) -> list[dict]:
    return [
        {'id': WITNESS_IDS[index], 'signature': SIGNATURE}
        for index in range(count)
    ]


def certificate(body: dict) -> dict:
    return {
        'body': deepcopy(body),
        'authority_signature': SIGNATURE,
        'witnesses': witness_items(),
    }


@dataclass
class WitnessPlane:
    """Four stateful witness replicas and exact certification-plane accounting."""
    counts: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: {wid: 0 for wid in WITNESS_IDS}))
    scopes: dict[str, dict[str, set[str]]] = field(
        default_factory=lambda: defaultdict(dict))

    def certify(self, authority: ModelAuthority, body: dict,
                scope_keys: set[str] | None = None) -> dict[str, int]:
        total = zero_cost()
        ns = authority.ns
        for wid in WITNESS_IDS:
            cursor = self.counts[ns][wid]
            while cursor < len(authority.log):
                batch = authority.log[cursor:cursor + BATCH]
                request = {
                    'op': 'witness-sync', 'ns': ns, 'start': cursor,
                    'events': batch,
                }
                response = {'id': wid, 'count': cursor + len(batch), 'tip': DIGEST}
                add_cost(total, tx(request, response))
                cursor += len(batch)
            request = {'op': 'witness-certify', 'ns': ns, 'body': body}
            response = {'id': wid, 'signature': SIGNATURE}
            add_cost(total, tx(request, response))
            self.counts[ns][wid] = len(authority.log)
        if scope_keys is not None:
            self.scopes[ns][body['scope']] = set(scope_keys)
        return total

    def state_bytes(self, authorities: dict[str, ModelAuthority]) -> int:
        state = {'witnesses': {}}
        for wid in WITNESS_IDS:
            state['witnesses'][wid] = {
                'logs': {
                    ns: authorities[ns].log[:self.counts[ns][wid]]
                    for ns in sorted(self.counts)
                },
                'scopes': {
                    ns: {scope: sorted(keys) for scope, keys in sorted(table.items())}
                    for ns, table in sorted(self.scopes.items()) if table
                },
            }
        return len(encode(state))


@dataclass
class WitnessedPrefixClient:
    counts: dict[str, int] = field(default_factory=dict)

    def refresh(self, authority: ModelAuthority, now: int,
                plane: WitnessPlane) -> tuple[dict[str, int], dict[str, int], str]:
        ns = authority.ns
        start = self.counts.get(ns, 0)
        body = {
            'op': 'checkpoint', 'ns': ns, 'count': len(authority.log),
            'tip': tip(authority), 'issued': now,
        }
        certification = plane.certify(authority, body)
        client = zero_cost()
        cursor = start
        events = 0
        while cursor < len(authority.log):
            request = {'op': 'prefix', 'ns': ns, 'start': cursor, 'batch': BATCH}
            batch = authority.log[cursor:cursor + BATCH]
            response = {'events': batch}
            add_cost(client, tx(request, response))
            cursor += len(batch); events += len(batch)
        request = {'op': 'checkpoint', 'ns': ns, 'from': cursor, 'now': now}
        add_cost(client, tx(request, certificate(body)))
        self.counts[ns] = len(authority.log)
        return client, certification, f'prefix:{events}' if events else 'checkpoint'

    def state_bytes(self, authorities: dict[str, ModelAuthority]) -> int:
        return len(encode({
            'prefixes': {
                ns: authorities[ns].log[:count]
                for ns, count in sorted(self.counts.items())
            }
        }))


@dataclass
class WitnessedScopeClient:
    keys: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    counts: dict[str, int] = field(default_factory=dict)
    issued: dict[str, int] = field(default_factory=dict)
    objects: dict[str, dict] = field(default_factory=dict)

    def _body(self, authority: ModelAuthority, needed: set[str], now: int) -> tuple[dict, str]:
        ns = authority.ns
        existing = self.keys[ns]
        additions = sorted(needed - existing)
        frontier = {'count': len(authority.log), 'tip': tip(authority), 'issued': now}
        if ns not in self.counts:
            body = {
                'op': 'register', 'ns': ns, 'scope': SCOPE, **frontier,
                'objects': [fold_status(authority.log, key) for key in sorted(needed)],
            }
            return body, f'register:{len(needed)}'
        if additions:
            body = {
                'op': 'extend', 'ns': ns, 'from_scope': SCOPE, 'scope': SCOPE,
                'from': self.counts[ns], **frontier,
                **scope_projection(authority, existing, self.counts[ns]),
                'objects': [fold_status(authority.log, key) for key in additions],
            }
            projected = sum(len(body[field]) for field in
                            ('conflicts', 'revoked_keys', 'revoked_caps'))
            return body, f'extend:{len(additions)}+causes:{projected}'
        if self.counts[ns] != len(authority.log):
            body = {
                'op': 'renew', 'ns': ns, 'scope': SCOPE,
                'from': self.counts[ns], **frontier,
                **scope_projection(authority, existing, self.counts[ns]),
            }
            projected = sum(len(body[field]) for field in
                            ('conflicts', 'revoked_keys', 'revoked_caps'))
            return body, f'renew:causes:{projected}'
        return {
            'op': 'head', 'ns': ns, 'scope': SCOPE, **frontier,
        }, 'head'

    def refresh(self, authority: ModelAuthority, needed: set[str], now: int,
                plane: WitnessPlane) -> tuple[dict[str, int], dict[str, int], str]:
        ns = authority.ns
        existing = set(self.keys[ns])
        body, action = self._body(authority, needed, now)
        resulting = set(needed) if ns not in self.counts else existing | set(needed)
        certification = plane.certify(
            authority, body, resulting if body['op'] in {'register', 'extend'} else None)
        request = {
            'op': 'witness-scope-' + body['op'], 'ns': ns, 'scope': body.get('scope', ''),
            'from': self.counts.get(ns, 0), 'keys': sorted(needed), 'now': now,
        }
        client = tx(request, certificate(body))

        if body['op'] == 'register':
            for item in body['objects']:
                self.objects[item['key']] = {
                    'manifest': item['manifest'], 'valid': item['valid']}
            self.keys[ns] = set(needed)
        elif body['op'] == 'extend':
            for item in body['objects']:
                self.objects[item['key']] = {
                    'manifest': item['manifest'], 'valid': item['valid']}
            self.keys[ns].update(needed)
        for key in body.get('conflicts', []) + body.get('revoked_keys', []):
            self.objects[key]['valid'] = False
        for cap in body.get('revoked_caps', []):
            for item in self.objects.values():
                if item['manifest'] is not None and item['manifest']['cap'] == cap:
                    item['valid'] = False
        self.counts[ns] = len(authority.log)
        self.issued[ns] = now
        return client, certification, action

    def state_bytes(self) -> int:
        return len(encode({
            'objects': {key: self.objects[key] for key in sorted(self.objects)},
            'scopes': {
                ns: {'scope': SCOPE, 'count': self.counts[ns],
                     'issued': self.issued[ns], 'keys': sorted(self.keys[ns])}
                for ns in sorted(self.counts)
            },
        }))


def run_trace(family: str, span: int, order: str, churn: int) -> dict:
    graph_map, bundle_root, dimensions, authorities = build_model(family, span)
    trace = roots_for_order(graph_map, bundle_root, order, family, span)
    closures = {root: closure(graph_map, root) for root in set(trace)}
    clients = {
        'witnessed-prefix': WitnessedPrefixClient(),
        'witnessed-scope': WitnessedScopeClient(),
    }
    planes = {name: WitnessPlane() for name in STRATEGIES}
    client_totals = {name: zero_cost() for name in STRATEGIES}
    certification_totals = {name: zero_cost() for name in STRATEGIES}
    peak_client = {name: 0 for name in STRATEGIES}
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
        row = {'step': step, 'root': root, 'strategies': {}}
        for ns in sorted(support):
            client, cert, action = clients['witnessed-prefix'].refresh(
                authorities[ns], now, planes['witnessed-prefix'])
            add_cost(client_totals['witnessed-prefix'], client)
            add_cost(certification_totals['witnessed-prefix'], cert)
            row['strategies'].setdefault('witnessed-prefix', {'actions': []})
            row['strategies']['witnessed-prefix']['actions'].append(f'{ns}:{action}')

            client, cert, action = clients['witnessed-scope'].refresh(
                authorities[ns], needed[ns], now, planes['witnessed-scope'])
            add_cost(client_totals['witnessed-scope'], client)
            add_cost(certification_totals['witnessed-scope'], cert)
            row['strategies'].setdefault('witnessed-scope', {'actions': []})
            row['strategies']['witnessed-scope']['actions'].append(f'{ns}:{action}')

        peak_client['witnessed-prefix'] = max(
            peak_client['witnessed-prefix'], clients['witnessed-prefix'].state_bytes(authorities))
        peak_client['witnessed-scope'] = max(
            peak_client['witnessed-scope'], clients['witnessed-scope'].state_bytes())
        rows.append(row)

    total = {}
    for name in STRATEGIES:
        total[name] = {
            key: client_totals[name][key] + certification_totals[name][key]
            for key in ('wire_bytes', 'reply_bytes', 'messages')
        }
    return {
        'family': family, 'span': span, 'order': order,
        'unrelated_events_per_support_namespace_per_renewal': churn,
        'queries': QUERIES, 'dimensions': dimensions,
        'client_totals': client_totals,
        'certification_totals': certification_totals,
        'total_plane': total,
        'peak_client_state_bytes': peak_client,
        'final_witness_state_bytes': {
            name: planes[name].state_bytes(authorities) for name in STRATEGIES
        },
        'rows': rows,
    }


def actual_world() -> Authority:
    authority = Authority('n1')
    authority.append('grant', grant('n1'), 0)
    authority.append('publish', manifest('n1', 'leaf', []), 0)
    authority.append('publish', manifest('n1', 'leaf2', []), 0)
    return authority


def actual_adversarial_checks() -> dict:
    checks = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({'name': name, 'passed': bool(passed), 'detail': detail})

    for update, data in (
        ('artifact-revocation', ('revoke', {'target': 'n1/leaf'})),
        ('capability-revocation', ('revoke_cap', {'target': 'cap:n1:0'})),
        ('conflicting-publication', ('publish', manifest('n1', 'leaf', [], blob='conflict'))),
    ):
        authority = actual_world()
        committee = WitnessCommittee('n1', faulty=('w0',))
        service = WitnessedScopeService(authority, committee)
        cache = WitnessScopeCache('n1')
        cache.apply_register(service.register(['n1/leaf'], 1), 1)
        authority.append(data[0], data[1], 2)
        committee.advance(2)
        body = {
            'op': 'renew', 'ns': 'n1', 'scope': cache.scope, 'from': cache.count,
            'count': len(authority.log), 'tip': commitment(authority.log[-1]),
            'issued': 2, 'conflicts': [], 'revoked_keys': [], 'revoked_caps': [],
        }
        signatures = committee.signatures(body, authority.log)
        record('omitted-' + update, len(signatures) < QUORUM,
               f'{len(signatures)} signatures')

    authority = actual_world(); committee = WitnessCommittee('n1')
    service = WitnessedScopeService(authority, committee)
    try:
        service.register(['n1/leaf'], 1, available=('w0', 'w1'))
        two_blocked = False
    except QuorumUnavailable:
        two_blocked = True
    record('two-responsive-blocked', two_blocked, '2/4 responsive')
    cert = service.register(['n1/leaf'], 1, available=('w0', 'w1', 'w2'))
    record('three-responsive-valid', len(cert['witnesses']) == 3, '3/4 responsive')

    base = actual_world(); left = deepcopy(base); right = deepcopy(base)
    left.append('revoke', {'target': 'n1/leaf'}, 2)
    right.append('publish', manifest('n1', 'leaf', [], blob='fork'), 2)
    committee = WitnessCommittee('n1', faulty=('w0',))
    committee.advance(2)
    left_body = {'op': 'checkpoint', 'ns': 'n1', 'count': len(left.log),
                 'tip': commitment(left.log[-1]), 'issued': 2}
    right_body = {'op': 'checkpoint', 'ns': 'n1', 'count': len(right.log),
                  'tip': commitment(right.log[-1]), 'issued': 2}
    committee.certify(left_body, left.log, available=('w0', 'w1', 'w2'))
    try:
        committee.certify(right_body, right.log, available=('w0', 'w2', 'w3'))
        fork_blocked = False
    except QuorumUnavailable:
        fork_blocked = True
    record('conflicting-quorum-blocked', fork_blocked, 'overlap includes honest witness')

    # A sequencer-only receipt is outside the effective frontier until a
    # witness quorum acknowledges it.  This negative control prevents the
    # study from silently claiming detection of events hidden from all honest
    # witnesses.
    authority = actual_world(); committee = WitnessCommittee('n1', faulty=('w0',))
    service = WitnessedScopeService(authority, committee); cache = WitnessScopeCache('n1')
    cache.apply_register(service.register(['n1/leaf'], 1), 1)
    old_log = deepcopy(authority.log)
    authority.append('revoke', {'target':'n1/leaf'}, 2)
    committee.advance(2)
    stale_body = {
        'op':'renew','ns':'n1','scope':cache.scope,'from':cache.count,
        'count':len(old_log),'tip':commitment(old_log[-1]),'issued':2,
        'conflicts':[],'revoked_keys':[],'revoked_caps':[],
    }
    pre_ack = committee.signatures(stale_body, old_log)
    record('unacknowledged-private-event-outside-contract', len(pre_ack) >= QUORUM,
           f'{len(pre_ack)} signatures before acknowledgement')
    checkpoint = {
        'op':'checkpoint','ns':'n1','count':len(authority.log),
        'tip':commitment(authority.log[-1]),'issued':2,
    }
    committee.certify(checkpoint, authority.log)
    committee.advance(3)
    stale_body['issued'] = 3
    post_ack = committee.signatures(stale_body, old_log)
    record('acknowledged-revocation-cannot-be-omitted', len(post_ack) < QUORUM,
           f'{len(post_ack)} signatures after acknowledgement')

    intersection = quorum_intersection_audit()
    record('quorum-intersection-enumeration',
           intersection['honest_intersection_failures'] == 0,
           f"{intersection['ordered_pairs']} ordered quorum pairs")
    return {
        'checks': checks,
        'count': len(checks),
        'passed': sum(item['passed'] for item in checks),
        'quorum_audit': intersection,
    }


def fixed_length_parity() -> dict:
    authority = actual_world(); committee = WitnessCommittee('n1')
    service = WitnessedScopeService(authority, committee)
    actual_register = service.register(['n1/leaf'], 1)
    model = ModelAuthority('n1')
    model.append('grant', {'cap':'cap:n1:0','publisher':'publisher:n1:0',
                           'epoch':0,'rights':['publish']}, 0)
    model.append('publish', manifest_data('n1', 'leaf', []), 0)
    model.append('publish', manifest_data('n1', 'leaf2', []), 0)
    register_body = {
        'op':'register','ns':'n1','scope':SCOPE,'count':len(model.log),
        'tip':DIGEST,'issued':1,
        'objects':[fold_status(model.log, 'n1/leaf')],
    }
    model_register = certificate(register_body)

    cache = WitnessScopeCache('n1'); cache.apply_register(actual_register, 1)
    authority.append('revoke', {'target':'n1/leaf'}, 2)
    actual_renew = service.renew(cache.scope, cache.count, 2)
    model.append('revoke', {'target':'n1/leaf'}, 2)
    renew_body = {
        'op':'renew','ns':'n1','scope':SCOPE,'from':3,'count':4,
        'tip':DIGEST,'issued':2,
        **scope_projection(model, {'n1/leaf'}, 3),
    }
    model_renew = certificate(renew_body)
    pairs = [
        ('register-certificate', actual_register, model_register),
        ('renew-certificate', actual_renew, model_renew),
    ]
    rows = [
        {'name': name, 'actual_bytes': wire_bytes(actual),
         'model_bytes': wire_bytes(modeled),
         'equal': wire_bytes(actual) == wire_bytes(modeled)}
        for name, actual, modeled in pairs
    ]
    return {'count': len(rows), 'all_equal': all(row['equal'] for row in rows),
            'objects': rows}


def median(values):
    return statistics.median(values)


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * q + 0.5)))
    return ordered[index]


def summarize(traces: list[dict], adversarial: dict, parity: dict) -> dict:
    client_ratios = [
        row['client_totals']['witnessed-scope']['wire_bytes'] /
        row['client_totals']['witnessed-prefix']['wire_bytes']
        for row in traces
    ]
    total_ratios = [
        row['total_plane']['witnessed-scope']['wire_bytes'] /
        row['total_plane']['witnessed-prefix']['wire_bytes']
        for row in traces
    ]
    cert_fraction = [
        row['certification_totals']['witnessed-scope']['wire_bytes'] /
        row['total_plane']['witnessed-scope']['wire_bytes']
        for row in traces
    ]
    scope_client_smaller = sum(
        row['client_totals']['witnessed-scope']['wire_bytes'] <
        row['client_totals']['witnessed-prefix']['wire_bytes'] for row in traces)
    scope_total_smaller = sum(
        row['total_plane']['witnessed-scope']['wire_bytes'] <
        row['total_plane']['witnessed-prefix']['wire_bytes'] for row in traces)
    by_churn = []
    for churn in CHURN_LEVELS:
        subset = [row for row in traces
                  if row['unrelated_events_per_support_namespace_per_renewal'] == churn]
        by_churn.append({
            'churn': churn, 'traces': len(subset),
            'prefix_client_median_wire_bytes': median(
                [row['client_totals']['witnessed-prefix']['wire_bytes'] for row in subset]),
            'scope_client_median_wire_bytes': median(
                [row['client_totals']['witnessed-scope']['wire_bytes'] for row in subset]),
            'prefix_total_median_wire_bytes': median(
                [row['total_plane']['witnessed-prefix']['wire_bytes'] for row in subset]),
            'scope_total_median_wire_bytes': median(
                [row['total_plane']['witnessed-scope']['wire_bytes'] for row in subset]),
        })
    return {
        'study': {
            'traces': len(traces), 'queries_per_trace': QUERIES,
            'total_queries': len(traces) * QUERIES,
            'families': list(FAMILIES), 'spans': list(SPANS),
            'orders': list(ORDERS), 'churn_levels': list(CHURN_LEVELS),
            'committee_size': len(WITNESS_IDS), 'quorum': QUORUM,
            'wire_definition': 'canonical JSON request plus newline and response plus newline',
            'client_and_certification_planes_separated': True,
            'timing_claim': False,
        },
        'client_plane': {
            'scope_strictly_smaller_traces': scope_client_smaller,
            'traces': len(traces),
            'median_scope_prefix_ratio': median(client_ratios),
            'p90_scope_prefix_ratio': percentile(client_ratios, 0.90),
            'max_scope_prefix_ratio': max(client_ratios),
            'min_scope_prefix_ratio': min(client_ratios),
        },
        'all_counted_planes': {
            'scope_strictly_smaller_traces': scope_total_smaller,
            'traces': len(traces),
            'median_scope_prefix_ratio': median(total_ratios),
            'p90_scope_prefix_ratio': percentile(total_ratios, 0.90),
            'max_scope_prefix_ratio': max(total_ratios),
            'min_scope_prefix_ratio': min(total_ratios),
            'median_scope_certification_fraction': median(cert_fraction),
        },
        'state': {
            'median_scope_client_bytes': median(
                [row['peak_client_state_bytes']['witnessed-scope'] for row in traces]),
            'median_prefix_client_bytes': median(
                [row['peak_client_state_bytes']['witnessed-prefix'] for row in traces]),
            'median_scope_witness_state_bytes': median(
                [row['final_witness_state_bytes']['witnessed-scope'] for row in traces]),
            'max_scope_witness_state_bytes': max(
                row['final_witness_state_bytes']['witnessed-scope'] for row in traces),
        },
        'by_churn': by_churn,
        'adversarial_checks': adversarial,
        'fixed_length_parity': parity,
    }


def write_csv(output: Path, traces: list[dict]) -> None:
    fields = [
        'family','span','order','churn','queries',
        'prefix_client_wire_bytes','scope_client_wire_bytes',
        'prefix_certification_wire_bytes','scope_certification_wire_bytes',
        'prefix_total_wire_bytes','scope_total_wire_bytes',
        'prefix_client_state_bytes','scope_client_state_bytes',
        'scope_witness_state_bytes',
    ]
    with (output / 'traces.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader()
        for row in traces:
            writer.writerow({
                'family': row['family'], 'span': row['span'], 'order': row['order'],
                'churn': row['unrelated_events_per_support_namespace_per_renewal'],
                'queries': row['queries'],
                'prefix_client_wire_bytes': row['client_totals']['witnessed-prefix']['wire_bytes'],
                'scope_client_wire_bytes': row['client_totals']['witnessed-scope']['wire_bytes'],
                'prefix_certification_wire_bytes': row['certification_totals']['witnessed-prefix']['wire_bytes'],
                'scope_certification_wire_bytes': row['certification_totals']['witnessed-scope']['wire_bytes'],
                'prefix_total_wire_bytes': row['total_plane']['witnessed-prefix']['wire_bytes'],
                'scope_total_wire_bytes': row['total_plane']['witnessed-scope']['wire_bytes'],
                'prefix_client_state_bytes': row['peak_client_state_bytes']['witnessed-prefix'],
                'scope_client_state_bytes': row['peak_client_state_bytes']['witnessed-scope'],
                'scope_witness_state_bytes': row['final_witness_state_bytes']['witnessed-scope'],
            })


def write_tex(generated: Path, summary: dict) -> None:
    generated.mkdir(parents=True, exist_ok=True)
    client = summary['client_plane']; total = summary['all_counted_planes']
    adversarial = summary['adversarial_checks']; state = summary['state']
    macros = [
        '% Generated by artifact/src/witness_study.py; do not edit.',
        f"\\newcommand{{\\WitnessTraceCount}}{{{summary['study']['traces']}\\xspace}}",
        f"\\newcommand{{\\WitnessQueryCount}}{{{summary['study']['total_queries']:,}\\xspace}}",
        f"\\newcommand{{\\WitnessClientWins}}{{{client['scope_strictly_smaller_traces']}\\xspace}}",
        f"\\newcommand{{\\WitnessClientMedianRatio}}{{{client['median_scope_prefix_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\WitnessClientMaxRatio}}{{{client['max_scope_prefix_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\WitnessTotalWins}}{{{total['scope_strictly_smaller_traces']}\\xspace}}",
        f"\\newcommand{{\\WitnessTotalMedianRatio}}{{{total['median_scope_prefix_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\WitnessTotalMaxRatio}}{{{total['max_scope_prefix_ratio']:.2f}\\xspace}}",
        f"\\newcommand{{\\WitnessCertFraction}}{{{100*total['median_scope_certification_fraction']:.1f}\\%\\xspace}}",
        f"\\newcommand{{\\WitnessAttackChecks}}{{{adversarial['passed']}\\xspace}}",
        f"\\newcommand{{\\WitnessParityObjects}}{{{summary['fixed_length_parity']['count']}\\xspace}}",
        f"\\newcommand{{\\WitnessMedianStateKiB}}{{{state['median_scope_witness_state_bytes']/1024:.1f}\\xspace}}",
        '',
    ]
    (generated / 'witness-macros.tex').write_text('\n'.join(macros))
    lines = [
        '% Generated by artifact/src/witness_study.py; do not edit.',
        '\\begin{tabular}{@{}rrrrr@{}}',
        '\\toprule',
        'Events/ns & \\multicolumn{2}{c}{Client KiB} & \\multicolumn{2}{c}{All-plane KiB} \\\\',
        '\\cmidrule(lr){2-3}\\cmidrule(l){4-5}',
        ' & Prefix & Scope & Prefix & Scope \\\\',
        '\\midrule',
    ]
    for row in summary['by_churn']:
        lines.append(
            f"{row['churn']} & {row['prefix_client_median_wire_bytes']/1024:.1f} & "
            f"{row['scope_client_median_wire_bytes']/1024:.1f} & "
            f"{row['prefix_total_median_wire_bytes']/1024:.1f} & "
            f"{row['scope_total_median_wire_bytes']/1024:.1f} \\\\"
        )
    lines.extend(['\\bottomrule', '\\end{tabular}', ''])
    (generated / 'witness-table.tex').write_text('\n'.join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--generated')
    args = parser.parse_args()
    output = Path(args.output); output.mkdir(parents=True, exist_ok=True)
    traces = [
        run_trace(family, span, order, churn)
        for family in FAMILIES for span in SPANS
        for order in ORDERS for churn in CHURN_LEVELS
    ]
    adversarial = actual_adversarial_checks()
    parity = fixed_length_parity()
    summary = summarize(traces, adversarial, parity)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    (output / 'adversarial.json').write_text(json.dumps(adversarial, indent=2, sort_keys=True) + '\n')
    with gzip.open(output / 'traces.json.gz', 'wt') as handle:
        json.dump(traces, handle, separators=(',', ':'), sort_keys=True)
    write_csv(output, traces)
    if args.generated:
        write_tex(Path(args.generated), summary)
    print(json.dumps({
        'traces': len(traces),
        'client_scope_wins': summary['client_plane']['scope_strictly_smaller_traces'],
        'total_scope_wins': summary['all_counted_planes']['scope_strictly_smaller_traces'],
        'attack_checks': f"{adversarial['passed']}/{adversarial['count']}",
        'parity': parity['all_equal'],
    }, sort_keys=True))


if __name__ == '__main__':
    main()
