"""Quorum-witnessed exact-scope status deltas.

This module strengthens ``scope_delta`` against one Byzantine sequencer and at
most one Byzantine witness in a four-witness committee.  A client accepts a
report only after three distinct witnesses co-sign the exact report body.  An
honest witness first validates a contiguous authority history, replays event
admission rules, recomputes the requested exact-scope projection, and refuses a
conflicting state for the same certified slot.

The construction is deliberately bounded and simple.  This core module holds
witness state in memory; ``durable_witness`` wraps it with persist-before-sign
stable-state recovery.  Neither layer is general consensus, dynamic committee
reconfiguration, malicious-storage protection, or an aggregate-signature
implementation.  Independent Ed25519 signatures make byte cost explicit.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from itertools import combinations
from typing import Iterable

from codec import (MAX_EVENTS, authenticated, commitment, natural, ns_of, sign,
                   verify)
from scope_delta import (MAX_SCOPE_KEYS, MAX_SCOPES,
                         _check_scopes_with_freshness, _status, _statuses)

WITNESS_IDS = tuple(f'w{i}' for i in range(4))
FAULT_BOUND = 1
QUORUM = 3
MAX_SIGNED_SLOTS = 65_536


class QuorumUnavailable(RuntimeError):
    """Fewer than QUORUM witnesses certified a report."""


def _scope_id(ns: str, keys: tuple[str, ...]) -> str:
    return commitment({'ns': ns, 'keys': list(keys)})


def _tip(log: list[dict], count: int | None = None) -> str:
    limit = len(log) if count is None else count
    return commitment(log[limit - 1]) if limit else ''


def _validate_keys(ns: str, keys: Iterable[str]) -> tuple[str, ...]:
    ordered = tuple(sorted(keys))
    if (not ordered or len(ordered) > MAX_SCOPE_KEYS
            or len(ordered) != len(set(ordered))
            or any(ns_of(key) != ns for key in ordered)):
        raise ValueError('scope key bound')
    return ordered


def _projection(log: list[dict], keys: tuple[str, ...], start: int,
                count: int | None = None) -> dict[str, list[str]]:
    end = len(log) if count is None else count
    if not natural(start) or not natural(end) or start > end or end > len(log):
        raise ValueError('invalid projection frontier')
    old = _statuses(log, keys, start)
    current = _statuses(log, keys, end)
    conflicts: list[str] = []
    for key in keys:
        before = old[key]
        after = current[key]
        if before['manifest'] is None:
            raise ValueError('scope frontier predates registration')
        if (before['valid'] and after['manifest'] is not None
                and not after['valid'] and any(
                    event['body']['kind'] == 'publish'
                    and event['body']['data']['manifest']['key'] == key
                    and event['body']['data']['manifest'] != before['manifest']
                    for event in log[start:end]
                )):
            conflicts.append(key)
    keyset = set(keys)
    caps = {
        item['manifest']['cap']
        for item in old.values()
        if item['manifest'] is not None and item['valid']
    }
    revoked_keys: list[str] = []
    revoked_caps: list[str] = []
    for event in log[start:end]:
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


def _replay(log: list[dict], ns: str) -> None:
    """Validate one complete signed authority history independently."""
    previous = ''
    epoch = 0
    caps: dict[str, dict] = {}
    revoked_caps: set[str] = set()
    last_time = 0
    for expected, event in enumerate(log, start=1):
        if not authenticated(event):
            raise ValueError('unauthenticated receipt')
        body = event['body']
        if (body['ns'] != ns or body['seq'] != expected
                or body['previous'] != previous or body['accepted'] < last_time):
            raise ValueError('non-contiguous authority history')
        kind = body['kind']; data = body['data']
        if kind == 'grant':
            if (set(data) != {'cap', 'publisher', 'epoch', 'rights'}
                    or not natural(data['epoch']) or data['epoch'] != epoch
                    or data['cap'] != f'cap:{ns}:{epoch}'
                    or data['publisher'] != f'publisher:{ns}:{epoch}'
                    or data['rights'] != ['publish'] or data['cap'] in caps):
                raise ValueError('invalid replayed capability')
            caps[data['cap']] = deepcopy(data)
        elif kind == 'publish':
            if set(data) != {'manifest', 'signature'}:
                raise ValueError('invalid publication fields')
            manifest = data['manifest']
            if (set(manifest) != {'ns','key','deps','epoch','publisher','cap','blob'}
                    or manifest['ns'] != ns or ns_of(manifest['key']) != ns
                    or not natural(manifest['epoch']) or manifest['epoch'] != epoch
                    or not isinstance(manifest['deps'], list)
                    or len(manifest['deps']) > 256
                    or any(not isinstance(dep, str) for dep in manifest['deps'])
                    or manifest['deps'] != sorted(manifest['deps'])
                    or len(manifest['deps']) != len(set(manifest['deps']))
                    or not isinstance(manifest['blob'], str)
                    or len(manifest['blob']) > 256
                    or manifest['cap'] not in caps
                    or manifest['cap'] in revoked_caps
                    or caps[manifest['cap']]['publisher'] != manifest['publisher']
                    or caps[manifest['cap']]['epoch'] != manifest['epoch']
                    or not verify(manifest['publisher'], manifest, data['signature'])):
                raise ValueError('invalid replayed publication')
            for dep in manifest['deps']:
                ns_of(dep)
        elif kind == 'transfer':
            if set(data) != {'epoch'} or type(data['epoch']) is not int or data['epoch'] != epoch + 1:
                raise ValueError('invalid replayed transfer')
            epoch = data['epoch']
        elif kind == 'revoke':
            if set(data) != {'target'} or ns_of(data['target']) != ns:
                raise ValueError('invalid replayed revocation')
        elif kind == 'revoke_cap':
            if set(data) != {'target'} or data['target'] not in caps:
                raise ValueError('invalid replayed capability revocation')
            revoked_caps.add(data['target'])
        else:
            raise ValueError('unknown replayed event')
        previous = commitment(event)
        last_time = body['accepted']


def _state_digest(body: dict) -> str:
    """Digest state fields while allowing a later fresh issuance timestamp."""
    stable = {key: value for key, value in body.items() if key != 'issued'}
    return commitment(stable)


@dataclass
class Witness:
    ns: str
    witness_id: str
    faulty: bool = False
    log: list[dict] = field(default_factory=list)
    scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    signed_slots: dict[tuple, str] = field(default_factory=dict)
    clock: int = 0
    clock_epsilon: int = 0

    def advance(self, now: int) -> None:
        """Trusted local-emulator clock advance; not an RPC operation."""
        if not natural(now) or now < self.clock:
            raise ValueError('witness clock moved backwards')
        self.clock = now

    @property
    def signer(self) -> str:
        return f'witness:{self.ns}:{self.witness_id}'

    def _check_candidate(self, candidate: list[dict]) -> None:
        """Validate without mutating witness state.

        A malformed projection must not pin an honest witness to an otherwise
        valid but uncertified history.  The candidate history is committed only
        after the complete response body and slot checks succeed.
        """
        if len(candidate) > MAX_EVENTS:
            raise ValueError('history bound')
        _replay(candidate, self.ns)
        if len(candidate) < len(self.log) or candidate[:len(self.log)] != self.log:
            raise ValueError('rollback or fork')

    def _slot(self, body: dict) -> tuple:
        op = body['op']
        if op == 'register':
            return (op, body['scope'], body['count'], body['tip'])
        if op == 'extend':
            return (op, body['from_scope'], body['scope'], body['from'], body['count'], body['tip'])
        if op == 'renew':
            return (op, body['scope'], body['from'], body['count'], body['tip'])
        if op == 'head':
            return (op, body['scope'], body['count'], body['tip'])
        if op == 'checkpoint':
            return (op, body['count'])
        raise ValueError('unknown witnessed operation')

    def _validate_common(self, body: dict, candidate: list[dict]) -> None:
        if (not isinstance(body, dict) or body.get('ns') != self.ns
                or not natural(body.get('count')) or body['count'] != len(candidate)
                or body['tip'] != _tip(candidate)
                or not natural(body.get('issued'))
                or abs(body['issued'] - self.clock) > self.clock_epsilon
                or (candidate and candidate[-1]['body']['accepted'] > body['issued'])):
            raise ValueError('bad witnessed frontier or clock')
        self._check_candidate(candidate)

    def _validate_body(self, body: dict, candidate: list[dict]) -> tuple[str | None, tuple[str, ...] | None]:
        self._validate_common(body, candidate)
        op = body['op']
        if op == 'checkpoint':
            if set(body) != {'op','ns','count','tip','issued'}:
                raise ValueError('bad checkpoint')
            return None, None
        if op == 'register':
            if set(body) != {'op','ns','scope','count','tip','issued','objects'}:
                raise ValueError('bad registration body')
            if not isinstance(body['objects'], list):
                raise ValueError('bad registration objects')
            keys = tuple(sorted(item.get('key') for item in body['objects'] if isinstance(item, dict)))
            keys = _validate_keys(self.ns, keys)
            if body['scope'] != _scope_id(self.ns, keys):
                raise ValueError('scope binding mismatch')
            expected = [_status(candidate, key) for key in keys]
            if body['objects'] != expected or any(item['manifest'] is None or item['valid'] is not True for item in expected):
                raise ValueError('incorrect registration projection')
            return body['scope'], keys
        if op == 'renew':
            expected_keys = {'op','ns','scope','from','count','tip','issued',
                             'conflicts','revoked_keys','revoked_caps'}
            if set(body) != expected_keys or body['scope'] not in self.scopes:
                raise ValueError('unknown renewal scope')
            if not natural(body['from']) or body['from'] > body['count']:
                raise ValueError('bad renewal frontier')
            projected = _projection(candidate, self.scopes[body['scope']], body['from'], body['count'])
            if any(body[name] != projected[name] for name in projected):
                raise ValueError('incomplete or incorrect renewal projection')
            return None, None
        if op == 'extend':
            expected_keys = {'op','ns','from_scope','scope','from','count','tip','issued',
                             'conflicts','revoked_keys','revoked_caps','objects'}
            if set(body) != expected_keys or body['from_scope'] not in self.scopes:
                raise ValueError('unknown extension scope')
            if not natural(body['from']) or body['from'] > body['count'] or not isinstance(body['objects'], list):
                raise ValueError('bad extension frontier')
            old = self.scopes[body['from_scope']]
            additions = tuple(sorted(item.get('key') for item in body['objects'] if isinstance(item, dict)))
            if not additions:
                raise ValueError('empty extension')
            additions = _validate_keys(self.ns, additions)
            combined = tuple(sorted(set(old) | set(additions)))
            if (len(combined) > MAX_SCOPE_KEYS or set(additions) & set(old)
                    or body['scope'] != _scope_id(self.ns, combined)):
                raise ValueError('bad extension binding')
            projected = _projection(candidate, old, body['from'], body['count'])
            if any(body[name] != projected[name] for name in projected):
                raise ValueError('incomplete extension projection')
            expected_objects = [_status(candidate, key) for key in additions]
            if body['objects'] != expected_objects or any(item['manifest'] is None or item['valid'] is not True for item in expected_objects):
                raise ValueError('bad extension objects')
            return body['scope'], combined
        if op == 'head':
            if set(body) != {'op','ns','scope','count','tip','issued'} or body['scope'] not in self.scopes:
                raise ValueError('bad scope head')
            return None, None
        raise ValueError('unknown witnessed operation')

    def certify(self, body: dict, candidate: list[dict]) -> str | None:
        if self.faulty:
            return sign(self.signer, body)
        try:
            new_scope, new_keys = self._validate_body(body, candidate)
            slot = self._slot(body)
            digest = _state_digest(body)
            previous = self.signed_slots.get(slot)
            if previous is not None and previous != digest:
                return None
            if previous is None and len(self.signed_slots) >= MAX_SIGNED_SLOTS:
                return None
            if new_scope is not None and new_keys is not None:
                prior = self.scopes.get(new_scope)
                if prior is not None and prior != new_keys:
                    return None
                if prior is None and len(self.scopes) >= MAX_SCOPES:
                    return None
            # Commit only after every check has succeeded.
            self.log = deepcopy(candidate)
            if new_scope is not None and new_keys is not None:
                self.scopes.setdefault(new_scope, new_keys)
            self.signed_slots[slot] = digest
            return sign(self.signer, body)
        except (KeyError, TypeError, ValueError, IndexError):
            return None


class WitnessCommittee:
    def __init__(self, ns: str, faulty: Iterable[str] = (), *,
                 clock_epsilon: int = 0):
        faulty_set = set(faulty)
        if (not faulty_set <= set(WITNESS_IDS) or len(faulty_set) > FAULT_BOUND
                or not natural(clock_epsilon)):
            raise ValueError('fault bound')
        self.ns = ns
        self.witnesses = {
            witness_id: Witness(ns=ns, witness_id=witness_id,
                                faulty=witness_id in faulty_set,
                                clock_epsilon=clock_epsilon)
            for witness_id in WITNESS_IDS
        }

    def advance(self, now: int) -> None:
        for witness in self.witnesses.values():
            witness.advance(now)

    def signatures(self, body: dict, log: list[dict],
                   available: Iterable[str] | None = None) -> list[dict]:
        chosen = set(WITNESS_IDS if available is None else available)
        if not chosen <= set(WITNESS_IDS):
            raise ValueError('unknown witness')
        out = []
        for witness_id in WITNESS_IDS:
            if witness_id not in chosen:
                continue
            signature = self.witnesses[witness_id].certify(body, log)
            if signature is not None:
                out.append({'id': witness_id, 'signature': signature})
        return out

    def certify(self, body: dict, log: list[dict],
                available: Iterable[str] | None = None) -> dict:
        signatures = self.signatures(body, log, available)
        if len(signatures) < QUORUM:
            raise QuorumUnavailable(f'needed {QUORUM}, obtained {len(signatures)}')
        return {
            'body': deepcopy(body),
            'authority_signature': sign('authority:' + self.ns, body),
            'witnesses': signatures[:QUORUM],
        }


class WitnessedScopeService:
    """Content-bound scope service whose exact responses are witness-certified."""
    def __init__(self, authority, committee: WitnessCommittee):
        if authority.ns != committee.ns:
            raise ValueError('namespace mismatch')
        self.authority = authority
        self.committee = committee
        self.ns = authority.ns
        self.scopes: dict[str, tuple[str, ...]] = {}

    def _remember(self, scope: str, keys: tuple[str, ...]) -> None:
        prior = self.scopes.get(scope)
        if prior is not None:
            if prior != keys:
                raise ValueError('scope collision')
            return
        if len(self.scopes) >= MAX_SCOPES:
            raise ValueError('scope table bound')
        self.scopes[scope] = keys

    def _frontier(self, now: int, witness_now: int | None = None) -> dict:
        if not natural(now):
            raise ValueError('invalid time')
        local_now = now if witness_now is None else witness_now
        if not natural(local_now):
            raise ValueError('invalid witness time')
        # In the executable fixture this is a trusted harness action.  A
        # deployment obtains each witness clock locally rather than from the
        # sequencer request.
        self.committee.advance(local_now)
        return {'count': len(self.authority.log), 'tip': _tip(self.authority.log), 'issued': now}

    def checkpoint(self, now: int, available: Iterable[str] | None = None, *,
                   witness_now: int | None = None) -> dict:
        body = {'op': 'checkpoint', 'ns': self.ns,
                **self._frontier(now, witness_now)}
        return self.committee.certify(body, self.authority.log, available)

    def register(self, keys: Iterable[str], now: int,
                 available: Iterable[str] | None = None, *,
                 witness_now: int | None = None) -> dict:
        ordered = _validate_keys(self.ns, keys)
        objects = [_status(self.authority.log, key) for key in ordered]
        if any(item['manifest'] is None or item['valid'] is not True for item in objects):
            raise ValueError('registration requires valid objects')
        scope = _scope_id(self.ns, ordered)
        body = {'op': 'register', 'ns': self.ns, 'scope': scope,
                **self._frontier(now, witness_now), 'objects': objects}
        cert = self.committee.certify(body, self.authority.log, available)
        self._remember(scope, ordered)
        return cert

    def renew(self, scope: str, start: int, now: int,
              available: Iterable[str] | None = None, *,
              witness_now: int | None = None) -> dict:
        if scope not in self.scopes:
            raise ValueError('unknown scope')
        body = {'op': 'renew', 'ns': self.ns, 'scope': scope, 'from': start,
                **self._frontier(now, witness_now),
                **_projection(self.authority.log, self.scopes[scope], start)}
        return self.committee.certify(body, self.authority.log, available)

    def extend(self, scope: str, start: int, additions: Iterable[str], now: int,
               available: Iterable[str] | None = None, *,
               witness_now: int | None = None) -> dict:
        if scope not in self.scopes:
            raise ValueError('unknown scope')
        add = _validate_keys(self.ns, additions)
        old = self.scopes[scope]
        if set(add) & set(old):
            raise ValueError('extension must add new keys')
        combined = tuple(sorted(set(old) | set(add)))
        if len(combined) > MAX_SCOPE_KEYS:
            raise ValueError('scope key bound')
        objects = [_status(self.authority.log, key) for key in add]
        if any(item['manifest'] is None or item['valid'] is not True for item in objects):
            raise ValueError('extension requires valid objects')
        new_scope = _scope_id(self.ns, combined)
        body = {'op': 'extend', 'ns': self.ns, 'from_scope': scope,
                'scope': new_scope, 'from': start,
                **self._frontier(now, witness_now),
                **_projection(self.authority.log, old, start), 'objects': objects}
        cert = self.committee.certify(body, self.authority.log, available)
        self._remember(new_scope, combined)
        return cert

    def head(self, scope: str, now: int,
             available: Iterable[str] | None = None, *,
             witness_now: int | None = None) -> dict:
        if scope not in self.scopes:
            raise ValueError('unknown scope')
        body = {'op': 'head', 'ns': self.ns, 'scope': scope,
                **self._frontier(now, witness_now)}
        return self.committee.certify(body, self.authority.log, available)


def _witness_fresh(issued: object, now: object, delta: object, epsilon: object = 0) -> bool:
    """Freshness when an honest witness validates the proposed timestamp.

    Witness and client clocks each have error at most epsilon, and a witness
    accepts a common report timestamp within epsilon of its own reading.  The
    resulting conservative end-to-end margin is three epsilon.
    """
    return (natural(issued) and natural(now) and natural(delta) and natural(epsilon)
            and issued <= now + 3 * epsilon
            and now - issued + 3 * epsilon < delta)


@dataclass
class WitnessScopeCache:
    ns: str
    scope: str | None = None
    count: int = 0
    tip: str = ''
    issued: int = 0
    objects: dict[str, dict] = field(default_factory=dict)

    def _check_certificate(self, certificate: dict, op: str, now: int,
                           delta: int, epsilon: int, floor: int) -> dict:
        if (not isinstance(certificate, dict)
                or set(certificate) != {'body','authority_signature','witnesses'}):
            raise ValueError('bad witness certificate')
        body = certificate['body']; signatures = certificate['witnesses']
        if (not isinstance(body, dict) or body.get('op') != op
                or body.get('ns') != self.ns or not natural(floor)
                or not natural(body.get('count')) or body['count'] > MAX_EVENTS
                or body['count'] < floor or not isinstance(body.get('tip'), str)
                or len(body['tip']) > 44
                or not _witness_fresh(body.get('issued'), now, delta, epsilon)
                or not verify('authority:' + self.ns, body, certificate['authority_signature'])
                or not isinstance(signatures, list) or len(signatures) < QUORUM
                or len(signatures) > len(WITNESS_IDS)):
            raise ValueError('bad witness certificate')
        seen: set[str] = set()
        valid = 0
        for item in signatures:
            if (not isinstance(item, dict) or set(item) != {'id','signature'}
                    or item['id'] not in WITNESS_IDS or item['id'] in seen):
                raise ValueError('bad witness signer set')
            seen.add(item['id'])
            if verify(f'witness:{self.ns}:{item["id"]}', body, item['signature']):
                valid += 1
        if valid < QUORUM:
            raise ValueError('insufficient valid witness signatures')
        return body

    def _projected_copy(self, body: dict) -> dict[str, dict]:
        conflicts = body['conflicts']; revoked_keys = body['revoked_keys']; revoked_caps = body['revoked_caps']
        if not all(isinstance(value, list) for value in (conflicts, revoked_keys, revoked_caps)):
            raise ValueError('bad projection')
        if (conflicts != sorted(conflicts) or revoked_keys != sorted(revoked_keys)
                or revoked_caps != sorted(revoked_caps)
                or len(conflicts) != len(set(conflicts))
                or len(revoked_keys) != len(set(revoked_keys))
                or len(revoked_caps) != len(set(revoked_caps))):
            raise ValueError('noncanonical projection')
        if any(key not in self.objects for key in conflicts + revoked_keys):
            raise ValueError('projection outside scope')
        updated = deepcopy(self.objects)
        for key in conflicts + revoked_keys:
            updated[key]['valid'] = False
        for cap in revoked_caps:
            if not isinstance(cap, str):
                raise ValueError('bad capability')
            for item in updated.values():
                if item['manifest'] is not None and item['manifest']['cap'] == cap:
                    item['valid'] = False
        return updated

    def apply_register(self, certificate: dict, now: int, *, delta: int = 10,
                       epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_certificate(certificate, 'register', now, delta, epsilon, floor)
        if (set(body) != {'op','ns','scope','count','tip','issued','objects'}
                or self.scope is not None or not isinstance(body['scope'], str)
                or len(body['scope']) != 44 or not isinstance(body['objects'], list)
                or not body['objects'] or len(body['objects']) > MAX_SCOPE_KEYS):
            raise ValueError('bad witnessed registration')
        objects: dict[str, dict] = {}
        for item in body['objects']:
            if (not isinstance(item, dict) or set(item) != {'key','manifest','valid'}
                    or ns_of(item['key']) != self.ns or item['valid'] is not True
                    or item['key'] in objects or not isinstance(item['manifest'], dict)
                    or item['manifest'].get('key') != item['key']
                    or not isinstance(item['manifest'].get('deps'), list)
                    or not isinstance(item['manifest'].get('cap'), str)):
                raise ValueError('bad witnessed object')
            objects[item['key']] = {'manifest': deepcopy(item['manifest']), 'valid': True}
        ordered = tuple(sorted(objects))
        if body['scope'] != _scope_id(self.ns, ordered):
            raise ValueError('scope binding mismatch')
        self.scope = body['scope']; self.count = body['count']; self.tip = body['tip']
        self.issued = body['issued']; self.objects = objects

    def apply_renew(self, certificate: dict, now: int, *, delta: int = 10,
                    epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_certificate(certificate, 'renew', now, delta, epsilon, floor)
        expected = {'op','ns','scope','from','count','tip','issued',
                    'conflicts','revoked_keys','revoked_caps'}
        if (set(body) != expected or self.scope is None or body['scope'] != self.scope
                or body['from'] != self.count or body['count'] < body['from']):
            raise ValueError('bad witnessed renewal frontier')
        updated = self._projected_copy(body)
        self.objects = updated; self.count = body['count']; self.tip = body['tip']; self.issued = body['issued']

    def apply_extend(self, certificate: dict, now: int, *, delta: int = 10,
                     epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_certificate(certificate, 'extend', now, delta, epsilon, floor)
        expected = {'op','ns','from_scope','scope','from','count','tip','issued',
                    'conflicts','revoked_keys','revoked_caps','objects'}
        if (set(body) != expected or self.scope is None or body['from_scope'] != self.scope
                or body['from'] != self.count or body['count'] < body['from']
                or not isinstance(body['scope'], str) or len(body['scope']) != 44
                or not isinstance(body['objects'], list)):
            raise ValueError('bad witnessed extension')
        updated = self._projected_copy(body)
        for item in body['objects']:
            if (not isinstance(item, dict) or set(item) != {'key','manifest','valid'}
                    or item['key'] in updated or ns_of(item['key']) != self.ns
                    or item['valid'] is not True or not isinstance(item['manifest'], dict)
                    or item['manifest'].get('key') != item['key']
                    or not isinstance(item['manifest'].get('deps'), list)
                    or not isinstance(item['manifest'].get('cap'), str)):
                raise ValueError('bad witnessed extension object')
            updated[item['key']] = {'manifest': deepcopy(item['manifest']), 'valid': True}
        if len(updated) > MAX_SCOPE_KEYS or body['scope'] != _scope_id(self.ns, tuple(sorted(updated))):
            raise ValueError('bad extended scope binding')
        self.objects = updated; self.scope = body['scope']; self.count = body['count']
        self.tip = body['tip']; self.issued = body['issued']

    def apply_head(self, certificate: dict, now: int, *, delta: int = 10,
                   epsilon: int = 0, floor: int = 0) -> None:
        body = self._check_certificate(certificate, 'head', now, delta, epsilon, floor)
        if (set(body) != {'op','ns','scope','count','tip','issued'}
                or self.scope is None or body['scope'] != self.scope
                or body['count'] != self.count or body['tip'] != self.tip):
            raise ValueError('bad witnessed head')
        self.issued = body['issued']


def check_witness_scopes(caches: dict[str, WitnessScopeCache], root: str, now: int, **kwargs) -> dict:
    allowed = {'delta', 'epsilon', 'floors'}
    if set(kwargs) - allowed:
        raise TypeError('unexpected witness scope policy argument')
    return _check_scopes_with_freshness(
        caches, root, now,
        delta=kwargs.get('delta', 10), epsilon=kwargs.get('epsilon', 0),
        floors=kwargs.get('floors'), freshness=_witness_fresh)


def quorum_intersection_audit() -> dict:
    committees = [set(group) for group in combinations(WITNESS_IDS, QUORUM)]
    pairs = 0; minimum_intersection = len(WITNESS_IDS); honest_intersection_failures = 0
    for first in committees:
        for second in committees:
            pairs += 1
            overlap = first & second
            minimum_intersection = min(minimum_intersection, len(overlap))
            # For every allowed faulty identity, some overlapping signer is honest.
            for faulty in [set()] + [{item} for item in WITNESS_IDS]:
                if not (overlap - faulty):
                    honest_intersection_failures += 1
    return {
        'committee_size': len(WITNESS_IDS), 'fault_bound': FAULT_BOUND,
        'quorum': QUORUM, 'quorum_sets': len(committees), 'ordered_pairs': pairs,
        'minimum_intersection': minimum_intersection,
        'honest_intersection_failures': honest_intersection_failures,
    }
