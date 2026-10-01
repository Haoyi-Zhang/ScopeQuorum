"""Cache-aware batched status evidence under the honest-issuer reference model.

A full report supplies an immutable manifest and status for requested keys.  A
later compact report repeats only each cached manifest commitment and validity
bit at a new namespace frontier.  Per-key frontiers are retained explicitly:
advancing one subset never makes an unrefreshed cached key appear current.  A
fresh signed namespace head can renew every cached status already at the same
unchanged count.

This is an honest-issuer reference, not a Byzantine completeness proof.  Count
uniqueness relies on one non-forking namespace sequencer.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from codec import (MAX_EVENTS, commitment, issuance_covers, natural, ns_of,
                   sign, verify)

MAX_STATUS_KEYS = 256


def _fold(log: list[dict], key: str) -> tuple[dict | None, bool]:
    manifests = [
        event['body']['data']['manifest']
        for event in log
        if event['body']['kind'] == 'publish'
        and event['body']['data']['manifest']['key'] == key
    ]
    manifest = manifests[0] if manifests else None
    valid = bool(manifests) and all(other == manifest for other in manifests)
    for event in log:
        body = event['body']
        if body['kind'] == 'revoke' and body['data']['target'] == key:
            valid = False
        if (manifest is not None and body['kind'] == 'revoke_cap'
                and body['data']['target'] == manifest['cap']):
            valid = False
    return manifest, valid


def _keys(ns: str, keys: list[str]) -> tuple[str, ...]:
    ordered = tuple(keys)
    if (not ordered or len(ordered) > MAX_STATUS_KEYS
            or len(ordered) != len(set(ordered))
            or any(ns_of(key) != ns for key in ordered)):
        raise ValueError('status request bound')
    return ordered


def produce_compact(ns: str, log: list[dict], keys: list[str], now: int) -> dict:
    ordered = _keys(ns, keys)
    if not issuance_covers(log, now):
        raise ValueError('status time precedes accepted frontier')
    states = []
    for key in ordered:
        manifest, valid = _fold(log, key)
        states.append({
            'manifest': commitment(manifest) if manifest is not None else '',
            'valid': valid,
        })
    body = {
        'ns': ns, 'count': len(log), 'issued': now,
        'keys': commitment(list(ordered)), 'states': states,
    }
    return {'body': body, 'signature': sign('authority:' + ns, body)}


def _fresh(issued: object, now: object, delta: object, epsilon: object = 0) -> bool:
    return (natural(issued) and natural(now) and natural(delta) and natural(epsilon)
            and issued <= now + 2 * epsilon
            and now - issued + 2 * epsilon < delta)


@dataclass
class CachedStatus:
    ns: str
    head_count: int = 0
    head_issued: int = 0
    objects: dict[str, dict] = field(default_factory=dict)

    def _advance_head(self, count: int, issued: int) -> None:
        if count > self.head_count or (count == self.head_count and issued >= self.head_issued):
            self.head_count = count
            self.head_issued = issued

    def apply_full(self, report: dict, now: int, *, delta: int = 10,
                   epsilon: int = 0, floor: int = 0) -> None:
        """Add or replace exactly the reported keys at the report frontier.

        Other cached objects remain available but retain their own older
        frontier and cannot be used as if this report had refreshed them.
        """
        try:
            if set(report) != {'body', 'signature'}:
                raise ValueError
            body = report['body']
            if (set(body) != {'ns', 'count', 'issued', 'objects'}
                    or body['ns'] != self.ns
                    or not natural(body['count']) or body['count'] > MAX_EVENTS
                    or body['count'] < floor
                    or not _fresh(body['issued'], now, delta, epsilon)
                    or not verify('authority:' + self.ns, body, report['signature'])
                    or not isinstance(body['objects'], list)
                    or not body['objects'] or len(body['objects']) > MAX_STATUS_KEYS):
                raise ValueError
            updates: dict[str, dict] = {}
            for item in body['objects']:
                if (set(item) != {'key', 'manifest', 'valid'}
                        or ns_of(item['key']) != self.ns
                        or type(item['valid']) is not bool
                        or item['key'] in updates
                        or (item['key'] in self.objects
                            and body['count'] < self.objects[item['key']]['count'])
                        or (item['manifest'] is not None
                            and item['manifest'].get('key') != item['key'])):
                    raise ValueError
                updates[item['key']] = {
                    'manifest': item['manifest'], 'valid': item['valid'],
                    'count': body['count'], 'issued': body['issued'],
                }
            self.objects.update(updates)
            self._advance_head(body['count'], body['issued'])
        except (KeyError, TypeError, ValueError):
            raise ValueError('bad full status report') from None

    def apply_compact(self, report: dict, keys: list[str], now: int, *,
                      delta: int = 10, epsilon: int = 0, floor: int = 0) -> None:
        try:
            ordered = _keys(self.ns, keys)
            if set(report) != {'body', 'signature'}:
                raise ValueError
            body = report['body']
            if (set(body) != {'ns', 'count', 'issued', 'keys', 'states'}
                    or body['ns'] != self.ns
                    or not natural(body['count']) or body['count'] > MAX_EVENTS
                    or body['count'] < floor
                    or not _fresh(body['issued'], now, delta, epsilon)
                    or body['keys'] != commitment(list(ordered))
                    or not isinstance(body['states'], list)
                    or len(body['states']) != len(ordered)
                    or not verify('authority:' + self.ns, body, report['signature'])):
                raise ValueError
            for key, state in zip(ordered, body['states']):
                if (key not in self.objects or set(state) != {'manifest', 'valid'}
                        or type(state['valid']) is not bool
                        or body['count'] < self.objects[key]['count']):
                    raise ValueError
                manifest = self.objects[key]['manifest']
                expected = commitment(manifest) if manifest is not None else ''
                if state['manifest'] != expected:
                    raise ValueError
            for key, state in zip(ordered, body['states']):
                item = self.objects[key]
                item['valid'] = state['valid']
                item['count'] = body['count']
                item['issued'] = body['issued']
            self._advance_head(body['count'], body['issued'])
        except (KeyError, TypeError, ValueError):
            raise ValueError('bad compact status report') from None

    def apply_head(self, head: dict, now: int, *, delta: int = 10,
                   epsilon: int = 0, floor: int = 0) -> None:
        try:
            if set(head) != {'body', 'signature'}:
                raise ValueError
            body = head['body']
            if (set(body) != {'ns', 'count', 'tip', 'issued'}
                    or body['ns'] != self.ns
                    or not natural(body['count']) or body['count'] > MAX_EVENTS
                    or body['count'] < max(floor, self.head_count)
                    or not _fresh(body['issued'], now, delta, epsilon)
                    or not verify('authority:' + self.ns, body, head['signature'])):
                raise ValueError
            self._advance_head(body['count'], body['issued'])
        except (KeyError, TypeError, ValueError):
            raise ValueError('bad renewal head') from None

    def effective_issued(self, item: dict) -> int:
        if item['count'] == self.head_count:
            return max(item['issued'], self.head_issued)
        return item['issued']


def check_cached(caches: dict[str, CachedStatus], root: str, now: int, *,
                 delta: int = 10, epsilon: int = 0,
                 floors: dict[str, int] | None = None) -> dict:
    observed: dict[str, int] = {}
    support: set[str] = set()
    reached: list[str] = []

    def result(reason: str) -> dict:
        return {'serve': reason == 'SERVE', 'reason': reason,
                'observed': observed, 'support': sorted(support),
                'closure': sorted(reached), 'witness': {}}

    try:
        ns_of(root)
        if not natural(now) or not natural(delta) or not natural(epsilon):
            return result('BAD_POLICY')
        graph: dict[str, list[str]] = {}
        pending = [root]
        seen: set[str] = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            reached.append(key)
            if len(seen) > 4096:
                return result('CLOSURE_BOUND')
            ns = ns_of(key)
            support.add(ns)
            cache = caches.get(ns)
            if cache is None or key not in cache.objects:
                return result('MISSING_STATUS')
            item = cache.objects[key]
            if item['count'] < (floors or {}).get(ns, 0):
                return result('ROLLBACK')
            prior = observed.get(ns)
            if prior is not None and prior != item['count']:
                return result('MIXED_FRONTIER')
            observed[ns] = item['count']
            if not _fresh(cache.effective_issued(item), now, delta, epsilon):
                return result('EXPIRED')
            if item['valid'] is not True or item['manifest'] is None:
                return result('INVALID_OR_MISSING_STATUS')
            graph[key] = item['manifest']['deps']
            pending.extend(graph[key])
        remaining = set(seen)
        depth: dict[str, int] = {}
        for _ in range(34):
            ready = {key for key in remaining if set(graph[key]) <= depth.keys()}
            if not ready:
                break
            update = {key: max((depth[dep] + 1 for dep in graph[key]), default=0)
                      for key in ready}
            remaining -= ready
            depth.update(update)
        return result('SERVE' if not remaining and depth[root] <= 32
                      else 'CYCLE_OR_DEPTH')
    except (KeyError, TypeError, ValueError, IndexError):
        return result('MALFORMED')
