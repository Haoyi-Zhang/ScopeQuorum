"""Reconstruct a witnessed client from its admitted certificate transcript.

The caller supplies trusted namespace membership, clock policy and independently
retained frontier floors. A saved transcript is evidence, not a trusted cache
image. Replay authenticates every transition and preserves its original issue
time; each subsequent read still applies current-time freshness. The caller owns
durable storage and protection of the independent floors.
"""
from __future__ import annotations

from copy import deepcopy
import json

from codec import MAX_FRAME, NAMESPACES, encode, natural
from witness_delta import WitnessScopeCache, check_witness_scopes

MAX_CERTIFICATES = 4096
OPERATIONS = {'register', 'renew', 'extend', 'head'}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate saved-client field')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('non-finite saved-client value')


class WitnessClient:
    """Bounded transcript-backed cache with atomic in-memory admission."""

    def __init__(self, namespaces, *, delta=10, epsilon=0):
        if (not isinstance(namespaces, (list, tuple)) or not namespaces
                or any(type(ns) is not str or ns not in NAMESPACES for ns in namespaces)
                or len(set(namespaces)) != len(namespaces)
                or not natural(delta) or not natural(epsilon)
                or delta <= 3 * epsilon):
            raise ValueError('bad witnessed client policy')
        self.namespaces = tuple(sorted(namespaces))
        self.delta, self.epsilon = delta, epsilon
        self._caches = {ns: WitnessScopeCache(ns) for ns in self.namespaces}
        self._certificates = {ns: [] for ns in self.namespaces}
        self._floors = {ns: 0 for ns in self.namespaces}

    @property
    def views(self):
        return deepcopy(self._caches)

    @property
    def floors(self):
        return dict(self._floors)

    def _envelope(self, certificates=None, floors=None):
        return {'namespaces': list(self.namespaces), 'delta': self.delta,
                'epsilon': self.epsilon,
                'certificates': self._certificates if certificates is None else certificates,
                'floors': self._floors if floors is None else floors}

    def apply(self, certificate, now):
        """Admit one fresh certificate or leave all client state unchanged."""
        try:
            body = certificate['body']
            ns, op = body['ns'], body['op']
            if ns not in self._caches or op not in OPERATIONS:
                raise ValueError('unsupported client transition')
            if sum(map(len, self._certificates.values())) >= MAX_CERTIFICATES:
                raise ValueError('client transcript bound')
            cache = deepcopy(self._caches[ns])
            getattr(cache, 'apply_' + op)(certificate, now, delta=self.delta,
                                        epsilon=self.epsilon, floor=self._floors[ns])
            histories = {**self._certificates,
                         ns: self._certificates[ns] + [deepcopy(certificate)]}
            floors = {**self._floors, ns: max(self._floors[ns], cache.count)}
            if len(encode(self._envelope(histories, floors))) > MAX_FRAME:
                raise ValueError('saved-client byte bound')
        except (KeyError, TypeError, IndexError, AttributeError, RecursionError) as error:
            raise ValueError('malformed client transition') from error
        self._caches[ns] = cache
        self._certificates, self._floors = histories, floors

    def check(self, root, now):
        return check_witness_scopes(self._caches, root, now, delta=self.delta,
                                    epsilon=self.epsilon, floors=self._floors)

    def snapshot(self):
        """Return canonical evidence bytes; this method performs no disk I/O."""
        return encode(self._envelope())

    @classmethod
    def restore(cls, payload, *, namespaces, delta=10, epsilon=0,
                minimum_floors):
        """Verify the entire saved client before publishing a reconstructed one.

        ``minimum_floors`` must come from independent retained state. Supplying
        floors read from the same rolled-back snapshot cannot detect rollback of
        that whole snapshot. Historical transitions are replayed at their signed
        issue times solely to reconstruct state, never to authorize a read now.
        """
        candidate = cls(namespaces, delta=delta, epsilon=epsilon)
        try:
            if type(payload) is not bytes or not payload or len(payload) > MAX_FRAME:
                raise ValueError('saved-client byte bound')
            saved = json.loads(payload.decode('ascii'), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
            if (type(saved) is not dict
                    or set(saved) != {'namespaces', 'delta', 'epsilon', 'certificates', 'floors'}
                    or type(saved['namespaces']) is not list
                    or saved['namespaces'] != list(candidate.namespaces)
                    or not natural(saved['delta']) or saved['delta'] != delta
                    or not natural(saved['epsilon']) or saved['epsilon'] != epsilon):
                raise ValueError('saved client does not match trusted policy')
            histories, floors = saved['certificates'], saved['floors']
            if (type(histories) is not dict or set(histories) != set(candidate.namespaces)
                    or any(type(rows) is not list for rows in histories.values())
                    or sum(map(len, histories.values())) > MAX_CERTIFICATES
                    or type(floors) is not dict or set(floors) != set(candidate.namespaces)
                    or any(not natural(floor) for floor in floors.values())
                    or type(minimum_floors) is not dict
                    or set(minimum_floors) != set(candidate.namespaces)
                    or any(not natural(floor) for floor in minimum_floors.values())):
                raise ValueError('bad saved history or independent floors')
            for ns in candidate.namespaces:
                for certificate in histories[ns]:
                    if certificate['body']['ns'] != ns:
                        raise ValueError('certificate stored under wrong namespace')
                    candidate.apply(certificate, certificate['body']['issued'])
            if candidate._floors != floors:
                raise ValueError('saved floors do not match authenticated replay')
            if any(candidate._floors[ns] < minimum_floors[ns]
                   for ns in candidate.namespaces):
                raise ValueError('saved client is below independently retained floor')
        except (KeyError, TypeError, IndexError, UnicodeError, RecursionError) as error:
            raise ValueError('malformed saved client') from error
        return candidate
