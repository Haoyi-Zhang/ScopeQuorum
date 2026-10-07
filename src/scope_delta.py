"""Stateful, scoped status-delta evidence under an honest namespace issuer.

The full-prefix verifier can independently replay every accepted receipt.  This
module deliberately explores the strongest alternative allowed by the same
honest-issuer assumption: an authority remembers a bounded key scope and signs
that it returned every *status-changing* cause between two authenticated
frontiers.  The client caches immutable manifests and applies only those
changes.  Completeness of the projection is an issuer assertion; this is not a
Byzantine-transparency or non-equivocation construction.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from codec import (MAX_EVENTS, commitment, issuance_covers, natural, ns_of,
                   sign, verify)

MAX_SCOPE_KEYS = 256
MAX_SCOPES = 256


def _status(log: list[dict], key: str, count: int | None = None) -> dict:
    """Fold one key at a prefix.  ``log`` is an already-admitted authority log."""
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


def _statuses(log: list[dict], keys: Iterable[str],
              count: int | None = None) -> dict[str, dict]:
    """Batch the scalar fold over one admitted prefix; no retained cache.

    Two passes preserve revocations before first publication as well as the
    first manifest, exact duplicates and permanent conflicting-publication
    invalidity. Temporary key/capability maps are bounded by the caller's scope.
    """
    prefix = log if count is None else log[:count]
    states = {key: {'key': key, 'manifest': None, 'valid': False} for key in keys}
    for event in prefix:
        body = event['body']
        if body['kind'] == 'publish':
            manifest = body['data']['manifest']
            key = manifest['key']
            if key in states:
                item = states[key]
                if item['manifest'] is None:
                    item['manifest'] = manifest
                    item['valid'] = True
                elif manifest != item['manifest']:
                    item['valid'] = False
    by_cap: dict[str, list[dict]] = {}
    for item in states.values():
        if item['manifest'] is not None:
            by_cap.setdefault(item['manifest']['cap'], []).append(item)
    for event in prefix:
        body = event['body']
        if body['kind'] == 'revoke':
            target = body['data']['target']
            if target in states:
                states[target]['valid'] = False
        elif body['kind'] == 'revoke_cap':
            for item in by_cap.pop(body['data']['target'], ()):
                item['valid'] = False
    return states


def _validate_keys(ns: str, keys: Iterable[str]) -> tuple[str, ...]:
    ordered = tuple(sorted(keys))
    if (not ordered or len(ordered) > MAX_SCOPE_KEYS
            or len(ordered) != len(set(ordered))
            or any(ns_of(key) != ns for key in ordered)):
        raise ValueError('scope key bound')
    return ordered


def _fresh(issued: object, now: object, delta: object, epsilon: object = 0) -> bool:
    return (natural(issued) and natural(now) and natural(delta) and natural(epsilon)
            and issued <= now + 2 * epsilon
            and now - issued + 2 * epsilon < delta)


class ScopeService:
    """Bounded in-memory scope table at one honest namespace authority.

    Scope state is intentionally not crash durable.  A forgotten handle forces
    registration again; no availability or durable-session claim is made.
    """

    def __init__(self, authority):
        self.authority = authority
        self.ns = authority.ns
        self.scopes: dict[str, tuple[str, ...]] = {}

    def _scope_id(self, keys: tuple[str, ...]) -> str:
        # Handles are content-addressed rather than session secrets.  This makes
        # register/extend retries idempotent and lets the client verify that a
        # signed handle names exactly the cached key set.
        return commitment({'ns': self.ns, 'keys': list(keys)})

    def _remember(self, scope: str, keys: tuple[str, ...]) -> None:
        prior = self.scopes.get(scope)
        if prior is not None:
            if prior != keys:
                raise ValueError('scope commitment collision')
            return
        if len(self.scopes) >= MAX_SCOPES:
            raise ValueError('scope table bound')
        self.scopes[scope] = keys

    def register(self, keys: Iterable[str], now: int) -> dict:
        ordered = _validate_keys(self.ns, keys)
        if not issuance_covers(self.authority.log, now):
            raise ValueError('invalid time or stale issuance frontier')
        objects = [_status(self.authority.log, key) for key in ordered]
        if any(item['manifest'] is None or item['valid'] is not True for item in objects):
            raise ValueError('scope registration requires valid objects')
        scope = self._scope_id(ordered)
        self._remember(scope, ordered)
        body = {
            'op': 'register', 'ns': self.ns, 'scope': scope,
            'count': len(self.authority.log), 'issued': now,
            'objects': objects,
        }
        return {'body': body, 'signature': sign('authority:' + self.ns, body)}

    def _projection(self, keys: tuple[str, ...], start: int) -> dict:
        if not natural(start) or start > len(self.authority.log):
            raise ValueError('invalid frontier')
        old = {key: _status(self.authority.log, key, start) for key in keys}
        current = {key: _status(self.authority.log, key) for key in keys}
        conflicts = []
        revoked_keys = []
        revoked_caps = []

        # A first publication after a missing state needs the immutable manifest.
        # A different publication for an existing immutable key only needs a
        # conflict marker for the serving predicate.  Exact duplicates are
        # status-neutral and are omitted.
        for key in keys:
            before = old[key]
            after = current[key]
            if before['manifest'] is None:
                raise ValueError('scope frontier predates valid registration')
            if (before['manifest'] is not None and before['valid']
                    and after['manifest'] is not None and not after['valid']):
                if any(
                    event['body']['kind'] == 'publish'
                    and event['body']['data']['manifest']['key'] == key
                    and event['body']['data']['manifest'] != before['manifest']
                    for event in self.authority.log[start:]
                ):
                    conflicts.append(key)

        keyset = set(keys)
        caps = {
            item['manifest']['cap']
            for item in old.values()
            if item['manifest'] is not None and item['valid']
        }
        for event in self.authority.log[start:]:
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

    def renew(self, scope: str, start: int, now: int) -> dict:
        if scope not in self.scopes or not issuance_covers(self.authority.log, now):
            raise ValueError('unknown scope or invalid time')
        body = {
            'op': 'renew', 'ns': self.ns, 'scope': scope,
            'from': start, 'count': len(self.authority.log), 'issued': now,
            **self._projection(self.scopes[scope], start),
        }
        return {'body': body, 'signature': sign('authority:' + self.ns, body)}

    def extend(self, scope: str, start: int, add: Iterable[str], now: int) -> dict:
        if scope not in self.scopes or not issuance_covers(self.authority.log, now):
            raise ValueError('unknown scope or invalid time')
        additions = _validate_keys(self.ns, add)
        old_keys = self.scopes[scope]
        if set(additions) & set(old_keys):
            raise ValueError('scope extension repeats a key')
        combined = tuple(sorted(old_keys + additions))
        if len(combined) > MAX_SCOPE_KEYS:
            raise ValueError('scope key bound')
        projection = self._projection(old_keys, start)
        objects = [_status(self.authority.log, key) for key in additions]
        if any(item['manifest'] is None or item['valid'] is not True for item in objects):
            raise ValueError('scope extension requires valid objects')
        new_scope = self._scope_id(combined)
        body = {
            'op': 'extend', 'ns': self.ns,
            'from_scope': scope, 'scope': new_scope,
            'from': start, 'count': len(self.authority.log), 'issued': now,
            **projection,
            'objects': objects,
        }
        report = {'body': body, 'signature': sign('authority:' + self.ns, body)}
        # Retain the old immutable scope so a lost response does not strand the
        # client.  Repeating the same extension returns the same content handle.
        self._remember(new_scope, combined)
        return report


@dataclass
class ScopeCache:
    ns: str
    scope: str | None = None
    count: int = 0
    issued: int = 0
    objects: dict[str, dict] = field(default_factory=dict)

    def _check_common(self, report: dict, op: str, now: int, delta: int,
                      epsilon: int, floor: int) -> dict:
        if not isinstance(report, dict) or set(report) != {'body', 'signature'}:
            raise ValueError('bad scoped report')
        body = report['body']
        if (not isinstance(body, dict) or not natural(floor)
                or body.get('op') != op or body.get('ns') != self.ns
                or not verify('authority:' + self.ns, body, report['signature'])
                or not natural(body.get('count')) or body['count'] > MAX_EVENTS
                or body['count'] < floor
                or not _fresh(body.get('issued'), now, delta, epsilon)):
            raise ValueError('bad scoped report')
        return body

    def apply_register(self, report: dict, now: int, *, delta: int = 10,
                       epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_common(report, 'register', now, delta, epsilon, floor)
        if (set(body) != {'op','ns','scope','count','issued','objects'}
                or self.scope is not None or not isinstance(body['scope'], str)
                or len(body['scope']) != 44 or not isinstance(body['objects'], list)
                or not body['objects'] or len(body['objects']) > MAX_SCOPE_KEYS):
            raise ValueError('bad registration')
        objects: dict[str, dict] = {}
        for item in body['objects']:
            if (set(item) != {'key','manifest','valid'} or ns_of(item['key']) != self.ns
                    or item['valid'] is not True or item['key'] in objects
                    or not isinstance(item['manifest'], dict)):
                raise ValueError('bad registered object')
            manifest = item['manifest']
            if (manifest.get('key') != item['key']
                    or not isinstance(manifest.get('deps'), list)
                    or not isinstance(manifest.get('cap'), str)):
                raise ValueError('bad registered manifest')
            objects[item['key']] = {'manifest': manifest, 'valid': item['valid']}
        ordered = tuple(sorted(objects))
        if body['scope'] != commitment({'ns': self.ns, 'keys': list(ordered)}):
            raise ValueError('scope does not bind registered keys')
        self.scope = body['scope']; self.count = body['count']
        self.issued = body['issued']; self.objects = objects

    def _projected_copy(self, body: dict) -> dict[str, dict]:
        conflicts = body['conflicts']
        revoked_keys = body['revoked_keys']; revoked_caps = body['revoked_caps']
        if not all(isinstance(value, list) for value in
                   (conflicts, revoked_keys, revoked_caps)):
            raise ValueError('bad projection')
        if (conflicts != sorted(conflicts) or revoked_keys != sorted(revoked_keys)
                or revoked_caps != sorted(revoked_caps)):
            raise ValueError('noncanonical projection')
        if len(conflicts) != len(set(conflicts)) or any(key not in self.objects for key in conflicts):
            raise ValueError('bad conflict list')
        updated = {
            key: {'manifest': item['manifest'], 'valid': item['valid']}
            for key, item in self.objects.items()
        }
        for key in conflicts:
            updated[key]['valid'] = False
        if len(revoked_keys) != len(set(revoked_keys)) or any(key not in self.objects for key in revoked_keys):
            raise ValueError('bad revocation list')
        for key in revoked_keys:
            updated[key]['valid'] = False
        if len(revoked_caps) != len(set(revoked_caps)) or any(not isinstance(cap, str) for cap in revoked_caps):
            raise ValueError('bad capability list')
        for item in updated.values():
            manifest = item['manifest']
            if manifest is not None and manifest['cap'] in revoked_caps:
                item['valid'] = False
        return updated

    def apply_renew(self, report: dict, now: int, *, delta: int = 10,
                    epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_common(report, 'renew', now, delta, epsilon, floor)
        expected = {'op','ns','scope','from','count','issued',
                    'conflicts','revoked_keys','revoked_caps'}
        if (set(body) != expected or self.scope is None or body['scope'] != self.scope
                or body['from'] != self.count or body['count'] < body['from']):
            raise ValueError('bad renewal frontier')
        updated = self._projected_copy(body)
        self.objects = updated
        self.count = body['count']; self.issued = body['issued']

    def apply_extend(self, report: dict, now: int, *, delta: int = 10,
                     epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_common(report, 'extend', now, delta, epsilon, floor)
        expected = {'op','ns','from_scope','scope','from','count','issued',
                    'conflicts','revoked_keys','revoked_caps','objects'}
        if (set(body) != expected or self.scope is None
                or body['from_scope'] != self.scope
                or not isinstance(body['scope'], str) or len(body['scope']) != 44
                or body['from'] != self.count or body['count'] < body['from']
                or not isinstance(body['objects'], list)):
            raise ValueError('bad scope extension')
        updated = self._projected_copy(body)
        for item in body['objects']:
            if (set(item) != {'key','manifest','valid'} or item['key'] in updated
                    or ns_of(item['key']) != self.ns or item['valid'] is not True
                    or not isinstance(item['manifest'], dict)
                    or item['manifest'].get('key') != item['key']
                    or not isinstance(item['manifest'].get('deps'), list)
                    or not isinstance(item['manifest'].get('cap'), str)):
                raise ValueError('bad extension object')
            updated[item['key']] = {'manifest': item['manifest'], 'valid': item['valid']}
        if len(updated) > MAX_SCOPE_KEYS:
            raise ValueError('scope key bound')
        expected_scope = commitment({'ns': self.ns, 'keys': sorted(updated)})
        if body['scope'] != expected_scope:
            raise ValueError('scope does not bind extended keys')
        self.objects = updated; self.scope = body['scope']
        self.count = body['count']; self.issued = body['issued']

    def apply_head(self, head: dict, now: int, *, delta: int = 10,
                   epsilon: int = 0, floor: int = 0) -> None:
        """Renew an unchanged scope frontier with the namespace head."""
        try:
            if set(head) != {'body', 'signature'}:
                raise ValueError
            body = head['body']
            if (set(body) != {'ns', 'count', 'tip', 'issued'}
                    or body['ns'] != self.ns or body['count'] != self.count
                    or body['count'] < floor
                    or not _fresh(body['issued'], now, delta, epsilon)
                    or not verify('authority:' + self.ns, body, head['signature'])):
                raise ValueError
            self.issued = body['issued']
        except (KeyError, TypeError, ValueError):
            raise ValueError('bad scope renewal head') from None


def _check_scopes_with_freshness(caches: dict[str, ScopeCache], root: str,
                                 now: int, *, delta: int, epsilon: int,
                                 floors: dict[str, int] | None,
                                 freshness) -> dict:
    """Shared closure checker with an explicitly supplied clock policy."""
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
        pending = [root]; seen: set[str] = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key); reached.append(key)
            if len(seen) > 4096:
                return result('CLOSURE_BOUND')
            ns = ns_of(key); support.add(ns)
            cache = caches.get(ns)
            if cache is None or cache.scope is None or key not in cache.objects:
                return result('MISSING_STATUS')
            if cache.count < (floors or {}).get(ns, 0):
                return result('ROLLBACK')
            if not freshness(cache.issued, now, delta, epsilon):
                return result('EXPIRED')
            observed[ns] = cache.count
            item = cache.objects[key]
            if item['valid'] is not True or item['manifest'] is None:
                return result('INVALID_OR_MISSING_STATUS')
            graph[key] = item['manifest']['deps']
            pending.extend(graph[key])
        remaining = set(seen); depth: dict[str, int] = {}
        for _ in range(34):
            ready = {key for key in remaining if set(graph[key]) <= depth.keys()}
            if not ready:
                break
            updates = {key: max((depth[dep] + 1 for dep in graph[key]), default=0)
                       for key in ready}
            remaining -= ready; depth.update(updates)
        if remaining or depth[root] > 32:
            return result('CYCLE_OR_DEPTH')
        return result('SERVE')
    except (KeyError, TypeError, ValueError, IndexError):
        return result('MALFORMED')


def check_scopes(caches: dict[str, ScopeCache], root: str, now: int, *,
                 delta: int = 10, epsilon: int = 0,
                 floors: dict[str, int] | None = None) -> dict:
    """Check honest-issuer scope caches with the two-clock-error margin."""
    return _check_scopes_with_freshness(
        caches, root, now, delta=delta, epsilon=epsilon, floors=floors,
        freshness=_fresh)
