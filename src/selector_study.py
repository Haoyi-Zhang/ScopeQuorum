#!/usr/bin/env python3
"""Causal one-way status-to-scope selector for the renewal traces.

The selector begins with cache-aware signed status.  Before each namespace
refresh while still in status mode it obtains a signed byte quote for registering
exactly the currently needed scope.  Once cumulative status-mode wire bytes for
that namespace reach the quoted registration transaction size, it registers the
scope and thereafter uses ScopeDelta.  The threshold and direction are fixed
before evaluation; there is no test-trace tuning or future knowledge.

The quote is a real modeled request/response and its bytes are charged.  CPU to
construct the quote is outside this encoded-wire study, as are TLS/TCP headers.
This is a diagnostic baseline, not a competitive-ratio theorem: registration
cost changes as the needed key set grows, and the two fixed strategies have
different server-state requirements.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from codec import encode
from renewal_study import (
    CHURN_LEVELS,
    DELTA,
    FAMILIES,
    ORDERS,
    QUERIES,
    SIGNATURE,
    SPANS,
    ScopeClient,
    StatusClient,
    add_cost,
    add_unrelated_churn,
    build_model,
    closure,
    ns_of,
    roots_for_order,
    scope_register,
    tx,
)


def quote_registration(authority, needed: set[str], now: int) -> tuple[dict[str, int], int]:
    ordered = sorted(needed)
    register_request = {
        'op': 'scope-register', 'ns': authority.ns,
        'keys': ordered, 'now': now,
    }
    registration = tx(
        register_request,
        scope_register(authority.ns, authority, ordered, now),
    )['wire_bytes']
    quote_request = {
        'op': 'scope-quote', 'ns': authority.ns,
        'keys': ordered, 'now': now,
    }
    quote_response = {
        'body': {
            'ns': authority.ns,
            'count': len(authority.log),
            'issued': now,
            'keys': 'D' * 44,
            'register_wire_bytes': registration,
        },
        'signature': SIGNATURE,
    }
    return tx(quote_request, quote_response), registration


@dataclass
class ThresholdSelector:
    status: StatusClient = field(default_factory=StatusClient)
    scope: ScopeClient = field(default_factory=ScopeClient)
    status_mode_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    scope_mode: set[str] = field(default_factory=set)
    switches: dict[str, int] = field(default_factory=dict)

    def refresh(self, authority, needed: set[str], now: int, step: int) -> tuple[dict[str, int], str]:
        ns = authority.ns
        if ns in self.scope_mode:
            cost, action = self.scope.refresh(authority, needed, now)
            return cost, f'scope:{action}'

        quote_cost, register_bytes = quote_registration(authority, needed, now)
        if self.status_mode_bytes[ns] >= register_bytes:
            scope_cost, action = self.scope.refresh(authority, needed, now)
            total = dict(quote_cost)
            add_cost(total, scope_cost)
            self.scope_mode.add(ns)
            self.switches[ns] = step
            return total, f'quote:{register_bytes}+switch:{action}'

        status_cost, action = self.status.refresh(authority, needed, now)
        total = dict(quote_cost)
        add_cost(total, status_cost)
        self.status_mode_bytes[ns] += total['wire_bytes']
        return total, f'quote:{register_bytes}+status:{action}'

    def client_state_bytes(self) -> int:
        return len(encode({
            'status': {
                'objects': {
                    key: self.status.objects[key]
                    for key in sorted(self.status.objects)
                },
                'heads': {
                    ns: {
                        'count': self.status.head_count[ns],
                        'issued': self.status.head_issued[ns],
                    }
                    for ns in sorted(self.status.head_count)
                },
            },
            'scope': {
                'objects': {
                    key: self.scope.objects[key]
                    for key in sorted(self.scope.objects)
                },
                'scopes': {
                    ns: {
                        'count': self.scope.counts[ns],
                        'issued': self.scope.issued[ns],
                        'keys': sorted(self.scope.keys[ns]),
                    }
                    for ns in sorted(self.scope.counts)
                },
            },
            'mode': sorted(self.scope_mode),
            'status_mode_bytes': dict(sorted(self.status_mode_bytes.items())),
        }))


def run_selector_trace(family: str, span: int, order: str, churn: int) -> dict:
    graph_map, bundle_root, dimensions, authorities = build_model(family, span)
    roots = roots_for_order(graph_map, bundle_root, order, family, span)
    closures = {root: closure(graph_map, root) for root in set(roots)}
    client = ThresholdSelector()
    total = {'wire_bytes': 0, 'reply_bytes': 0, 'messages': 0}
    peak_client = 0
    peak_authority = 0
    rows = []

    for step, root in enumerate(roots):
        now = 1 + step * DELTA
        reached = closures[root]
        support = {ns_of(key) for key in reached}
        needed: dict[str, set[str]] = defaultdict(set)
        for key in reached:
            needed[ns_of(key)].add(key)
        if step and churn:
            add_unrelated_churn(authorities, support, step, churn, now)

        row = {
            'step': step,
            'root': root,
            'wire_bytes': 0,
            'reply_bytes': 0,
            'messages': 0,
            'actions': [],
        }
        for ns in sorted(support):
            cost, action = client.refresh(authorities[ns], needed[ns], now, step)
            add_cost(total, cost)
            add_cost(row, cost)
            row['actions'].append(f'{ns}:{action}')
        peak_client = max(peak_client, client.client_state_bytes())
        peak_authority = max(peak_authority, client.scope.authority_state_bytes())
        rows.append(row)

    return {
        'family': family,
        'span': span,
        'order': order,
        'unrelated_events_per_support_namespace_per_renewal': churn,
        'queries': QUERIES,
        'dimensions': dimensions,
        'totals': total,
        'switches': dict(sorted(client.switches.items())),
        'peak_client_state_bytes': peak_client,
        'peak_scope_authority_state_bytes': peak_authority,
        'rows': rows,
    }


def median(values) -> float:
    return float(statistics.median(list(values)))


def percentile(values, fraction: float) -> float:
    ordered = sorted(values)
    return float(ordered[round((len(ordered) - 1) * fraction)])


def trace_key(row: dict) -> tuple:
    return (
        row['family'], row['span'], row['order'],
        row['unrelated_events_per_support_namespace_per_renewal'],
    )


def summarize(selector: list[dict], fixed: list[dict]) -> dict:
    fixed_by_key = {trace_key(row): row for row in fixed}
    ratios = []
    versus_status = []
    versus_scope = []
    switched = 0
    rows = []
    for row in selector:
        base = fixed_by_key[trace_key(row)]
        status = base['totals']['cached-status']['wire_bytes']
        scope = base['totals']['scope-delta']['wire_bytes']
        best = min(status, scope)
        cost = row['totals']['wire_bytes']
        ratios.append(cost / best)
        versus_status.append(cost / status)
        versus_scope.append(cost / scope)
        switched += bool(row['switches'])
        rows.append({
            'family': row['family'],
            'span': row['span'],
            'order': row['order'],
            'churn': row['unrelated_events_per_support_namespace_per_renewal'],
            'selector_wire_bytes': cost,
            'cached_status_wire_bytes': status,
            'scope_delta_wire_bytes': scope,
            'best_fixed_wire_bytes': best,
            'ratio_to_best_fixed': cost / best,
            'switched_namespaces': len(row['switches']),
        })

    by_churn = []
    for churn in CHURN_LEVELS:
        subset = [r for r in rows if r['churn'] == churn]
        by_churn.append({
            'churn': churn,
            'traces': len(subset),
            'switched_traces': sum(r['switched_namespaces'] > 0 for r in subset),
            'median_selector_wire_bytes': median(r['selector_wire_bytes'] for r in subset),
            'median_best_fixed_wire_bytes': median(r['best_fixed_wire_bytes'] for r in subset),
            'median_ratio_to_best_fixed': median(r['ratio_to_best_fixed'] for r in subset),
        })

    return {
        'study': {
            'traces': len(selector),
            'queries_per_trace': QUERIES,
            'policy': 'start cached status; charged signed quote each status-mode refresh; switch namespace once cumulative status-mode bytes >= current registration quote; never switch back',
            'future_knowledge': False,
            'tuned_on_traces': False,
            'timing_claim': False,
        },
        'switched_traces': switched,
        'ratio_to_best_fixed_status_or_scope': {
            'median': median(ratios),
            'p90': percentile(ratios, 0.90),
            'max': max(ratios),
            'min': min(ratios),
            'within_1_25': sum(r <= 1.25 for r in ratios),
            'within_1_50': sum(r <= 1.50 for r in ratios),
        },
        'ratio_to_cached_status': {
            'median': median(versus_status),
            'max': max(versus_status),
        },
        'ratio_to_scope_delta': {
            'median': median(versus_scope),
            'max': max(versus_scope),
        },
        'by_churn': by_churn,
        'worst_traces': sorted(rows, key=lambda r: r['ratio_to_best_fixed'], reverse=True)[:8],
    }


def write_csv(path: Path, rows: list[dict], fixed: list[dict]) -> None:
    fixed_by_key = {trace_key(row): row for row in fixed}
    with path.open('w', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow([
            'family', 'span', 'order', 'churn', 'selector_wire_bytes',
            'cached_status_wire_bytes', 'scope_delta_wire_bytes',
            'best_fixed_wire_bytes', 'ratio_to_best_fixed',
            'switched_namespaces', 'peak_client_state_bytes',
            'peak_scope_authority_state_bytes',
        ])
        for row in rows:
            base = fixed_by_key[trace_key(row)]
            status = base['totals']['cached-status']['wire_bytes']
            scope = base['totals']['scope-delta']['wire_bytes']
            best = min(status, scope)
            writer.writerow([
                row['family'], row['span'], row['order'],
                row['unrelated_events_per_support_namespace_per_renewal'],
                row['totals']['wire_bytes'], status, scope, best,
                f"{row['totals']['wire_bytes'] / best:.9f}",
                len(row['switches']), row['peak_client_state_bytes'],
                row['peak_scope_authority_state_bytes'],
            ])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--renewal-traces', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--paper-generated', type=Path)
    args = parser.parse_args()
    with gzip.open(args.renewal_traces, 'rt') as handle:
        fixed = json.load(handle)
    selector = [
        run_selector_trace(family, span, order, churn)
        for family in FAMILIES
        for span in SPANS
        for order in ORDERS
        for churn in CHURN_LEVELS
    ]
    summary = summarize(selector, fixed)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output_dir / 'selector-traces.json.gz', 'wt') as handle:
        json.dump(selector, handle, sort_keys=True, separators=(',', ':'))
    (args.output_dir / 'selector-summary.json').write_text(
        json.dumps(summary, indent=2, sort_keys=True) + '\n')
    write_csv(args.output_dir / 'selector.csv', selector, fixed)
    if args.paper_generated is not None:
        args.paper_generated.mkdir(parents=True, exist_ok=True)
        ratio = summary['ratio_to_best_fixed_status_or_scope']
        macros = [
            f"\\newcommand{{\\SelectorTraces}}{{{summary['study']['traces']}}}",
            f"\\newcommand{{\\SelectorSwitched}}{{{summary['switched_traces']}}}",
            f"\\newcommand{{\\SelectorMedianRatio}}{{{ratio['median']:.2f}}}",
            f"\\newcommand{{\\SelectorPninetyRatio}}{{{ratio['p90']:.2f}}}",
            f"\\newcommand{{\\SelectorMaxRatio}}{{{ratio['max']:.2f}}}",
            f"\\newcommand{{\\SelectorWithinQuarter}}{{{ratio['within_1_25']}}}",
        ]
        (args.paper_generated / 'selector-macros.tex').write_text('\n'.join(macros) + '\n')
        lines = [
            r'\begin{tabular}{@{}rrrr@{}}',
            r'\toprule',
            r'Churn & Best fixed & Selector & Ratio\\',
            r' & (KiB) & (KiB) & $\times$\\',
            r'\midrule',
        ]
        for row in summary['by_churn']:
            lines.append(
                f"{row['churn']} & {row['median_best_fixed_wire_bytes']/1024:.1f} & "
                f"{row['median_selector_wire_bytes']/1024:.1f} & "
                f"{row['median_ratio_to_best_fixed']:.2f}\\\\")
        lines.extend([r'\bottomrule', r'\end{tabular}'])
        (args.paper_generated / 'selector-table.tex').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
