"""Owned, finite two-plane TCP comparison under one witnessed read contract.

Both paths use actual Ed25519 and the existing incremental witness listeners.
The extra loopback listener transports client requests and replies; it is an
experiment adapter, not a deployed registry API. Prefix readers retain complete
signed histories and receive only suffixes plus witnessed checkpoints. Scope
readers retain exact-key status and receive register/extend/renew/head reports.
No durability, WAN, aggregate-signature, or native CoSi/CHAINIAC result is claimed.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import gc
import json
from pathlib import Path
import platform
from runtime_environment import current_environment
import statistics
import sys
import time
import tracemalloc

import cryptography
from codec import MAX_FRAME, encode, manifest, natural, ns_of, sign
from durable_witness import snapshot_wire, witness_payload
from fixtures import graph, grant
from model import Authority
from scope_delta import MAX_SCOPE_KEYS, MAX_SCOPES, _statuses
from witness_delta import (QUORUM, WITNESS_IDS, WitnessScopeCache,
                           _projection, _replay, _scope_id, _tip,
                           _validate_keys, check_witness_scopes)
from witness_network import WitnessTCPNetwork

DELTA = 10
CHURNS = (0, 1, 4)
FAULTS = ('artifact-revoke', 'capability-revoke', 'conflicting-publish')


def closure(g, root):
    seen, pending = set(), [root]
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(g[key])
    return seen


def world(family, span):
    g, root, dimensions = graph(family, span)
    authorities = {ns: Authority(ns) for ns in sorted({ns_of(k) for k in g})}
    for ns, authority in authorities.items():
        authority.append('grant', grant(ns), 0)
    for key, deps in sorted(g.items()):
        ns, name = key.split('/', 1)
        authorities[ns].append('publish', manifest(ns, name, deps), 0)
    return g, root, dimensions, authorities


@dataclass
class PrefixCache:
    """Checkpoint-bound, complete-prefix baseline with atomic suffix admission.

    Derived statuses reuse the closure checker, not witness projections. Every
    receipt and publication is replayed, and the checkpoint binds count and tip.
    The derived index is retained and charged as client state.
    """
    ns: str
    log: list = field(default_factory=list)
    certificate: dict | None = None
    view: WitnessScopeCache = field(init=False)

    def __post_init__(self):
        self.view = WitnessScopeCache(self.ns)

    def apply(self, reply, now, *, delta=DELTA, epsilon=0, floor=0):
        if (not isinstance(reply, dict)
                or set(reply) != {'start', 'previous', 'events', 'certificate'}
                or not natural(reply['start']) or reply['start'] != len(self.log)
                or reply['previous'] != _tip(self.log)
                or not isinstance(reply['events'], list)):
            raise ValueError('bad prefix suffix base')
        body = self.view._check_certificate(
            reply['certificate'], 'checkpoint', now, delta, epsilon,
            max(floor, len(self.log)))
        if set(body) != {'op', 'ns', 'count', 'tip', 'issued'}:
            raise ValueError('bad checkpoint fields')
        candidate = self.log + deepcopy(reply['events'])
        if len(candidate) != body['count'] or _tip(candidate) != body['tip']:
            raise ValueError('checkpoint does not bind suffix')
        _replay(candidate, self.ns)
        if candidate and candidate[-1]['body']['accepted'] > body['issued']:
            raise ValueError('issuance predates history')
        keys = tuple(sorted({e['body']['data']['manifest']['key']
                             for e in candidate if e['body']['kind'] == 'publish'}))
        statuses = _statuses(candidate, keys)
        view = WitnessScopeCache(self.ns, _scope_id(self.ns, keys), body['count'],
                                 body['tip'], body['issued'],
                                 {k: {'manifest': deepcopy(v['manifest']),
                                      'valid': v['valid']}
                                  for k, v in statuses.items()})
        self.log, self.certificate, self.view = candidate, deepcopy(reply['certificate']), view


class ReadEndpoint:
    """One owned sequencer listener; four independent witness state objects."""
    def __init__(self, authorities, network):
        self.authorities, self.network = authorities, network
        self.scopes = {ns: {} for ns in authorities}
        self.client_bytes = self.client_messages = 0
        self.client_history_events = 0
        self.snapshot_bytes = self.snapshot_serializations = 0
        self.snapshot_cpu_seconds = 0.0
        self.operations = Counter()

    async def certificate(self, ns, body):
        signatures = await self.network.signatures(ns, body, self.authorities[ns].log)
        # Serialize the existing durable schema once per signature actually
        # returned, including the fourth signature not sent to the client.
        # This is a byte/CPU diagnostic, NOT a disk commit or recovery test.
        started = time.process_time()
        for item in signatures:
            witness = self.network.states[item['id']][ns]
            self.snapshot_bytes += len(snapshot_wire(witness_payload(witness)))
            self.snapshot_serializations += 1
        self.snapshot_cpu_seconds += time.process_time() - started
        if len(signatures) < QUORUM:
            return None
        return {'body': deepcopy(body), 'authority_signature': sign('authority:' + ns, body),
                'witnesses': signatures[:QUORUM]}

    async def answer(self, request):
        ns, now, op = request['ns'], request['now'], request['op']
        authority = self.authorities[ns]
        if not natural(now) or (authority.log and now < authority.log[-1]['body']['accepted']):
            raise ValueError('bad read time')
        frontier = {'count': len(authority.log), 'tip': _tip(authority.log), 'issued': now}
        remember = None
        if op == 'prefix':
            if set(request) != {'op', 'ns', 'start', 'previous', 'now'}:
                raise ValueError('bad prefix request')
            start = request['start']
            if (not natural(start) or start > len(authority.log)
                    or request['previous'] != _tip(authority.log, start)):
                raise ValueError('wrong retained prefix')
            body = {'op': 'checkpoint', 'ns': ns, **frontier}
        elif op == 'register':
            if set(request) != {'op', 'ns', 'keys', 'now'}:
                raise ValueError('bad register request')
            keys = _validate_keys(ns, request['keys'])
            statuses = _statuses(authority.log, keys)
            objects = [statuses[k] for k in keys]
            if any(v['manifest'] is None or v['valid'] is not True for v in objects):
                raise ValueError('registration requires valid objects')
            scope = _scope_id(ns, keys)
            body = {'op': op, 'ns': ns, 'scope': scope, **frontier, 'objects': objects}
            remember = (scope, keys)
        elif op in {'extend', 'refresh'}:
            expected = {'op', 'ns', 'scope', 'from', 'now'} | ({'add'} if op == 'extend' else set())
            if set(request) != expected:
                raise ValueError('bad scope request')
            old = self.scopes[ns][request['scope']]
            start = request['from']
            if not natural(start) or start > len(authority.log):
                raise ValueError('bad scope base')
            if op == 'refresh' and start == len(authority.log):
                body = {'op': 'head', 'ns': ns, 'scope': request['scope'], **frontier}
            else:
                body = {'op': 'renew', 'ns': ns, 'scope': request['scope'],
                        'from': start, **frontier, **_projection(authority.log, old, start)}
                if op == 'extend':
                    add = _validate_keys(ns, request['add'])
                    keys = tuple(sorted(set(old) | set(add)))
                    if set(old) & set(add) or len(keys) > MAX_SCOPE_KEYS:
                        raise ValueError('bad extension keys')
                    statuses = _statuses(authority.log, add)
                    objects = [statuses[k] for k in add]
                    if any(v['manifest'] is None or v['valid'] is not True for v in objects):
                        raise ValueError('extension requires valid objects')
                    scope = _scope_id(ns, keys)
                    body.update(op='extend', from_scope=request['scope'], scope=scope, objects=objects)
                    remember = (scope, keys)
        else:
            raise ValueError('unknown read operation')
        if remember and remember[0] not in self.scopes[ns] and len(self.scopes[ns]) >= MAX_SCOPES:
            raise ValueError('scope table bound')
        cert = await self.certificate(ns, body)
        if cert is None:
            self.operations['unavailable'] += 1
            return {'unavailable': True}
        self.operations[body['op']] += 1
        if remember:
            self.scopes[ns][remember[0]] = remember[1]
        if op == 'prefix':
            events = deepcopy(authority.log[start:])
            self.client_history_events += len(events)
            return {'start': start, 'previous': request['previous'], 'events': events, 'certificate': cert}
        return cert

    async def __aenter__(self):
        async def handler(reader, writer):
            try:
                line = await asyncio.wait_for(reader.readline(), 10)
                if not line or len(line) > MAX_FRAME:
                    raise ValueError('frame bound')
                reply = await self.answer(json.loads(line))
            except (ValueError, KeyError, TypeError, asyncio.TimeoutError):
                reply = {'error': 'READ_REJECTED'}
            wire = encode(reply) + b'\n'
            if len(wire) > MAX_FRAME:
                wire = encode({'error': 'FRAME_BOUND'}) + b'\n'
            writer.write(wire)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        self.server = await asyncio.start_server(handler, '127.0.0.1', 0, limit=MAX_FRAME + 1)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *args):
        self.server.close()
        await self.server.wait_closed()

    async def exchange(self, request):
        wire = encode(request) + b'\n'
        if len(wire) > MAX_FRAME:
            raise ValueError('outbound frame bound')
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port, limit=MAX_FRAME + 1)
        try:
            writer.write(wire)
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), 30)
        finally:
            writer.close()
            await writer.wait_closed()
        self.client_bytes += len(wire) + len(reply)
        self.client_messages += 2
        value = json.loads(reply)
        if 'error' in value:
            raise AssertionError(value)
        return value


def heap_size(value, seen=None):
    """Alias-aware Python-owned protocol-state estimate, not process RSS."""
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(heap_size(k, seen) + heap_size(v, seen) for k, v in value.items())
    elif isinstance(value, (tuple, list, set)):
        size += sum(heap_size(v, seen) for v in value)
    elif hasattr(value, '__dict__'):
        size += heap_size(vars(value), seen)
    return size


def state_cost(endpoint, network, caches):
    started = time.process_time()
    authority_state = {ns: {'ns': a.ns, 'log': a.log, 'epoch': a.epoch,
                            'caps': a.caps, 'revoked_caps': sorted(a.revoked_caps)}
                       for ns, a in endpoint.authorities.items()}
    clients = {ns: asdict(c) for ns, c in caches.items()}
    accepted = sum(len(snapshot_wire(witness_payload(w)))
                   for states in network.states.values() for w in states.values())
    staged = {wid: {ns: session.candidate for ns, session in states.items()}
              for wid, states in network.sessions.items()}
    components = {
        'sequencer_bytes': len(encode({'authorities': authority_state, 'scopes': endpoint.scopes})),
        'client_bytes': len(encode(clients)), 'accepted_witness_bytes': accepted,
        'staging_bytes': len(encode(staged)),
    }
    components['aggregate_serialized_bytes'] = sum(components.values())
    live = {'authorities': endpoint.authorities, 'scopes': endpoint.scopes,
            'clients': caches, 'witnesses': network.states,
            'staging': {wid: {ns: s.candidate for ns, s in states.items()}
                        for wid, states in network.sessions.items()}}
    components['protocol_heap_estimate_bytes'] = heap_size(live)
    components['measurement_cpu_seconds'] = time.process_time() - started
    return components


def update(authorities, g, dimensions, fault, step, churn, now):
    target = dimensions['target']
    if step == 6:
        a = authorities[ns_of(target)]
        if fault == 'artifact-revoke':
            a.append('revoke', {'target': target}, now)
        elif fault == 'capability-revoke':
            a.append('revoke_cap', {'target': f'cap:{a.ns}:0'}, now)
            # Future benign churn is admitted by a new epoch; old artifacts
            # remain invalid. Transfer does not silently reauthorize them.
            a.append('transfer', {'epoch': 1}, now)
            a.append('grant', grant(a.ns, 1), now)
        elif fault == 'conflicting-publish':
            name = target.split('/', 1)[1]
            a.append('publish', manifest(a.ns, name, g[target], blob='other-owned-object'), now)
        else:
            raise ValueError('unknown finite update')
    if step:
        for ns in dimensions['support']:
            a = authorities[ns]
            for index in range(churn):
                a.append('publish', manifest(ns, f'read-churn-{step}-{index}', [], epoch=a.epoch), now)


async def run_mode(family, span, churn, fault, mode):
    gc.collect()
    tracemalloc.start()
    try:
        g, root, dimensions, authorities = world(family, span)
        reached = closure(g, root)
        ordered = sorted(reached, key=lambda k: (len(closure(g, k)), k))
        intermediate = ordered[len(ordered) // 2]
        roots = [dimensions['target'], intermediate] + [root] * 6 + ['n0/unrelated', root]
        caches, floors, rows = {}, {}, []
        peak_state = defaultdict(int)
        async with WitnessTCPNetwork() as network:
            for ns in authorities:
                network.configure(ns, ns)
            async with ReadEndpoint(authorities, network) as endpoint:
                for step, query_root in enumerate(roots):
                    now = 1 + step * DELTA
                    update(authorities, g, dimensions, fault, step, churn, now)
                    for ns in authorities:
                        network.advance(ns, now)
                    network.blocked = {'w2', 'w3'} if step == 4 else set()
                    # The finite catalog supplies both request plans. No hidden
                    # server-frontier oracle is used to choose renew vs head.
                    needed = defaultdict(set)
                    for key in closure(g, query_root):
                        needed[ns_of(key)].add(key)
                    start_cpu, start_wall = time.process_time(), time.perf_counter()
                    for ns, keys in sorted(needed.items()):
                        if mode == 'prefix':
                            cache = caches.setdefault(ns, PrefixCache(ns))
                            request = {'op': 'prefix', 'ns': ns, 'start': len(cache.log),
                                       'previous': _tip(cache.log), 'now': now}
                        else:
                            cache = caches.setdefault(ns, WitnessScopeCache(ns))
                            if cache.scope is None:
                                request = {'op': 'register', 'ns': ns, 'keys': sorted(keys), 'now': now}
                            else:
                                additions = sorted(keys - cache.objects.keys())
                                request = {'op': 'extend' if additions else 'refresh', 'ns': ns,
                                           'scope': cache.scope, 'from': cache.count, 'now': now}
                                if additions:
                                    request['add'] = additions
                        reply = await endpoint.exchange(request)
                        if reply.get('unavailable'):
                            continue
                        if mode == 'prefix':
                            cache.apply(reply, now, floor=floors.get(ns, 0))
                            count = cache.view.count
                        else:
                            getattr(cache, 'apply_' + reply['body']['op'])(
                                reply, now, floor=floors.get(ns, 0))
                            count = cache.count
                        floors[ns] = max(floors.get(ns, 0), count)
                    views = {ns: c.view if mode == 'prefix' else c for ns, c in caches.items()}
                    verdict = check_witness_scopes(views, query_root, now, floors=floors)
                    cpu, wall = time.process_time() - start_cpu, time.perf_counter() - start_wall
                    expected = step in {0, 1, 2, 3, 5, 8}
                    if verdict['serve'] != expected:
                        raise AssertionError((family, span, churn, fault, mode, step, verdict))
                    state = state_cost(endpoint, network, caches)
                    for name, value in state.items():
                        if name != 'measurement_cpu_seconds':
                            peak_state[name] = max(peak_state[name], value)
                    rows.append({'step': step, 'root': query_root, 'now': now, 'verdict': verdict,
                                 'expected_serve': expected, 'cpu_seconds': cpu, 'wall_seconds': wall,
                                 'client_wire_bytes': endpoint.client_bytes,
                                 'witness_counters': asdict(network.counters), 'state': state,
                                 'views': {ns: asdict(v) for ns, v in views.items()}})
                _, traced_peak = tracemalloc.get_traced_memory()
                return {'family': family, 'span': span, 'churn': churn, 'fault': fault, 'mode': mode,
                        'dimensions': dimensions, 'rows': rows, 'peak_state': dict(peak_state),
                        'tracemalloc_peak_bytes': traced_peak,
                        'client_wire_bytes': endpoint.client_bytes,
                        'client_messages': endpoint.client_messages,
                        'client_history_events': endpoint.client_history_events,
                        'witness_counters': asdict(network.counters),
                        'total_wire_bytes': endpoint.client_bytes + network.counters.wire_bytes,
                        'snapshot_serializations': endpoint.snapshot_serializations,
                        'snapshot_serialized_bytes': endpoint.snapshot_bytes,
                        'snapshot_cpu_seconds': endpoint.snapshot_cpu_seconds,
                        'read_cpu_seconds': sum(r['cpu_seconds'] for r in rows),
                        'read_wall_seconds': sum(r['wall_seconds'] for r in rows),
                        'operations': dict(endpoint.operations)}
    finally:
        tracemalloc.stop()


def compare(prefix, scope):
    for field in ('family', 'span', 'churn', 'fault'):
        if encode(prefix[field]) != encode(scope[field]):
            raise AssertionError(('different read workloads', field))
    if prefix['mode'] != 'prefix' or scope['mode'] != 'scope':
        raise AssertionError('read comparison mode mismatch')
    for p, s in zip(prefix['rows'], scope['rows'], strict=True):
        for field in ('step', 'root', 'now', 'expected_serve'):
            if encode(p[field]) != encode(s[field]):
                raise AssertionError(('different read query', field))
        if encode(p['verdict']) != encode(s['verdict']):
            raise AssertionError(('closure-decision mismatch', p['step']))
        for ns, sv in s['views'].items():
            pv = p['views'][ns]
            for name in ('count', 'tip', 'issued'):
                if encode(pv[name]) != encode(sv[name]):
                    raise AssertionError(('frontier mismatch', ns, name, p['step']))
            for key, status in sv['objects'].items():
                if encode(status) != encode(pv['objects'][key]):
                    raise AssertionError(('same-information status mismatch', key, p['step']))
    return {'family': prefix['family'], 'span': prefix['span'], 'churn': prefix['churn'],
            'fault': prefix['fault'], 'read_pairs': len(prefix['rows']),
            'client_ratio': scope['client_wire_bytes'] / prefix['client_wire_bytes'],
            'total_ratio': scope['total_wire_bytes'] / prefix['total_wire_bytes'],
            'prefix_total_bytes': prefix['total_wire_bytes'], 'scope_total_bytes': scope['total_wire_bytes'],
            'prefix_client_bytes': prefix['client_wire_bytes'], 'scope_client_bytes': scope['client_wire_bytes'],
            'prefix_witness_bytes': prefix['witness_counters']['wire_bytes'],
            'scope_witness_bytes': scope['witness_counters']['wire_bytes']}


async def campaign(output):
    output.mkdir(parents=True, exist_ok=False)
    traces, comparisons = [], []
    for family in ('public-lock', 'generated'):
        for span in (1, 3):
            for index, churn in enumerate(CHURNS):
                fault = FAULTS[index]
                pair = []
                for mode in ('prefix', 'scope'):
                    result = await run_mode(family, span, churn, fault, mode)
                    name = f'{family}-{span}-{churn}-{mode}.json'
                    (output / name).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
                    pair.append(result)
                    traces.append(result)
                row = compare(*pair)
                comparisons.append(row)
                print(json.dumps(row), flush=True)
    ratios = [r['total_ratio'] for r in comparisons]
    summary = {
        'environment': current_environment(),
        'contract': {'committee': 4, 'quorum': 3, 'fault_bound': 1, 'delta': DELTA, 'epsilon': 0,
                     'witness_transport': 'incremental TCP', 'client_transport': 'loopback TCP',
                     'faulty_witnesses_in_campaign': 0, 'disk_durability_exercised': False},
        'traces': len(comparisons), 'modes': 2, 'read_pairs': sum(r['read_pairs'] for r in comparisons),
        'matched_decisions_and_cached_statuses': True,
        'served_per_mode': sum(r['verdict']['serve'] for t in traces if t['mode'] == 'prefix' for r in t['rows']),
        'denied_per_mode': sum(not r['verdict']['serve'] for t in traces if t['mode'] == 'prefix' for r in t['rows']),
        'scope_client_wins': sum(r['client_ratio'] < 1 for r in comparisons),
        'scope_total_wins': sum(r < 1 for r in ratios),
        'total_ratio_median': statistics.median(ratios), 'total_ratio_min': min(ratios),
        'total_ratio_max': max(ratios), 'comparisons': comparisons,
        'totals_by_mode': {mode: {name: sum(t[name] for t in traces if t['mode'] == mode)
                                  for name in ('client_wire_bytes', 'total_wire_bytes', 'client_messages',
                                               'snapshot_serializations', 'snapshot_serialized_bytes',
                                               'snapshot_cpu_seconds', 'read_cpu_seconds', 'read_wall_seconds')}
                           for mode in ('prefix', 'scope')},
        'measurement_limits': [
            'Canonical JSON plus newlines; excludes TCP/IP, TLS and socket setup bytes.',
            'One process, actual five loopback listeners, independently owned witness state; no machine independence.',
            'CPU and wall time are instrumented single runs, include tracemalloc and snapshot diagnostics; not throughput.',
            'Serialized state includes authority admission state, all retained scopes/slots, client indexes and witness staging.',
            'Alias-aware protocol heap excludes diagnostics; whole-mode tracemalloc peak includes retained raw rows and serialization temporaries. Neither is native crypto, interpreter or kernel RSS.',
            'Snapshot byte/CPU accounting is not fsync I/O, durable TCP recovery or malicious-storage validation.',
            'Common finite catalog supplies query plans; manifest evidence still travels on the client plane.',
            'Unrelated churn and invalidator type are paired; no independent invalidator effect estimate.'],
    }
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True, help='fresh private or candidate output, must not exist')
    args = parser.parse_args()
    summary = asyncio.run(campaign(args.output))
    print(json.dumps({k: v for k, v in summary.items() if k != 'comparisons'}, indent=2))


if __name__ == '__main__':
    main()
