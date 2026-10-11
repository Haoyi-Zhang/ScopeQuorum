"""Bounded suffix staging, separate from a witness's accepted refusal state.

Prefix replies are transport hints, not certificates. Reset discards only the
uncommitted staging buffer; it never clears accepted history, scopes or slots.
Certification still runs the original complete-history/projection checks and,
for DurableWitness, persist-before-sign. All keys are public local fixtures.
"""
from __future__ import annotations

from copy import deepcopy

from codec import MAX_EVENTS, commitment, natural
from witness_delta import _replay

BATCH = 128


def prefix(log: list[dict], ns: str) -> dict:
    return {'ns': ns, 'count': len(log),
            'tip': commitment(log[-1]) if log else ''}


class HistorySession:
    def __init__(self, owner):
        self.owner = owner
        self.candidate = deepcopy(self.core.log)

    @property
    def core(self):
        # A poisoned durable owner must not expose a usable transport session.
        if hasattr(self.owner, '_ensure_available'):
            self.owner._ensure_available()
        return getattr(self.owner, 'witness', self.owner)

    def frontier(self) -> dict:
        return {'ok': True, **prefix(self.candidate, self.core.ns)}

    def reset(self, ns: str) -> dict:
        if ns != self.core.ns:
            raise ValueError('namespace mismatch')
        self.candidate = deepcopy(self.core.log)
        return self.frontier()

    def sync(self, ns: str, start: int, previous: str,
             events: list[dict]) -> dict:
        core = self.core
        current = prefix(self.candidate, core.ns)
        if (ns != core.ns or not natural(start) or start != current['count']
                or previous != current['tip'] or not isinstance(events, list)
                or not 1 <= len(events) <= BATCH
                or start + len(events) > MAX_EVENTS):
            raise ValueError('suffix base or batch mismatch')
        candidate = self.candidate + deepcopy(events)
        # Check signatures, predecessor links, sequence, time and admission.
        # No mutation occurs even if the last event is invalid.
        _replay(candidate, core.ns)
        if (not core.faulty and
                (len(candidate) < len(core.log)
                 or candidate[:len(core.log)] != core.log)):
            raise ValueError('candidate does not extend accepted branch')
        self.candidate = candidate
        return self.frontier()

    def certify(self, body: dict, *, log=None, **kwargs):
        candidate = self.candidate if log is None else log
        signature = self.owner.certify(body, candidate, **kwargs)
        if signature is not None and not self.core.faulty:
            self.candidate = deepcopy(self.core.log)
        return signature


def agrees(reply, ns: str, log: list[dict]) -> bool:
    if (not isinstance(reply, dict) or reply.get('ok') is not True
            or reply.get('ns') != ns or not natural(reply.get('count'))
            or reply['count'] > len(log)):
        return False
    count = reply['count']
    return reply.get('tip') == (commitment(log[count - 1]) if count else '')


async def incremental_certify(send, case_id: str, body: dict, log: list[dict],
                              **extra):
    if not isinstance(log, list) or len(log) > MAX_EVENTS:
        raise ValueError('history bound')
    ns = body['ns']
    reply = await send({'op': 'prefix', 'case': case_id})
    if reply is None:
        return None
    if not agrees(reply, ns, log):
        # Retry from the *accepted* branch, not from empty history. This can
        # recover stale staging but cannot unlock incompatible honest branches.
        reply = await send({'op': 'reset', 'case': case_id, 'ns': ns})
        if reply is None:
            return None
        if not agrees(reply, ns, log):
            return {'reject': True}
    cursor = reply['count']
    while cursor < len(log):
        events = log[cursor:cursor + BATCH]
        expected = cursor + len(events)
        reply = await send({
            'op': 'sync', 'case': case_id, 'ns': ns, 'start': cursor,
            'previous': commitment(log[cursor - 1]) if cursor else '',
            'events': events,
        })
        if reply is None:
            return None
        if not agrees(reply, ns, log) or reply['count'] != expected:
            return {'reject': True}
        cursor = expected
    return await send({'op': 'certify', 'case': case_id, 'body': body, **extra})
