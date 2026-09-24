"""Crash-durable state for a witnessed exact-scope signer.

An honest witness must not return a signature until the branch, scope table,
signed-slot digest, and logical clock that justify that signature are durable.
This module wraps :class:`witness_delta.Witness` with an atomic file snapshot:
write a new canonical state file, fsync it, atomically replace the prior file,
and fsync the containing directory before returning the signature.

The implementation is intentionally small and local.  It assumes the witness's
stable storage is not lost or maliciously rewritten.  Corrupt snapshots are
detected and make the witness unavailable rather than silently resetting it.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import Any

from codec import MAX_EVENTS, commitment, encode, natural, ns_of
from scope_delta import MAX_SCOPE_KEYS, MAX_SCOPES
from witness_delta import (MAX_SIGNED_SLOTS, WITNESS_IDS, Witness, _replay,
                           _scope_id)


class DurableStateError(RuntimeError):
    """The persistent witness state is missing, corrupt, or cannot be committed."""


class DurableCommitUncertain(DurableStateError):
    """The replacement occurred but directory durability could not be confirmed.

    No signature may escape from this state.  The in-process object is poisoned
    and must be reopened from disk before it can sign again.  On recovery the
    file may contain either the old or the new snapshot; both outcomes are safe
    because the failed operation returned no signature.
    """


class InjectedCrash(RuntimeError):
    """Deterministic crash point used only by the owned test harness."""

    def __init__(self, phase: str):
        super().__init__(phase)
        self.phase = phase


CRASH_PHASES = ('before-commit', 'after-temp-fsync', 'after-replace')


@dataclass(frozen=True)
class DurableSummary:
    ns: str
    witness_id: str
    faulty: bool
    count: int
    tip: str
    scopes: int
    signed_slots: int
    clock: int
    state_bytes: int


def _slot_value(value: Any) -> bool:
    return isinstance(value, str) or natural(value)


def _validate_case_state(payload: dict, expected_ns: str,
                         expected_id: str, expected_faulty: bool) -> Witness:
    expected = {
        'ns', 'witness_id', 'faulty', 'log', 'scopes', 'signed_slots',
        'clock', 'clock_epsilon',
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise DurableStateError('invalid durable state fields')
    if (payload['ns'] != expected_ns or payload['witness_id'] != expected_id
            or payload['faulty'] is not expected_faulty
            or expected_id not in WITNESS_IDS
            or not natural(payload['clock'])
            or not natural(payload['clock_epsilon'])
            or not isinstance(payload['log'], list)
            or len(payload['log']) > MAX_EVENTS
            or not isinstance(payload['scopes'], list)
            or len(payload['scopes']) > MAX_SCOPES
            or not isinstance(payload['signed_slots'], list)
            or len(payload['signed_slots']) > MAX_SIGNED_SLOTS):
        raise DurableStateError('invalid durable state values')

    log = deepcopy(payload['log'])
    try:
        _replay(log, expected_ns)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise DurableStateError('invalid durable authority history') from exc
    if (log and log[-1]['body']['accepted']
            > payload['clock'] + payload['clock_epsilon']):
        raise DurableStateError('durable history exceeds persisted witness clock')

    scopes: dict[str, tuple[str, ...]] = {}
    for item in payload['scopes']:
        if (not isinstance(item, dict) or set(item) != {'scope', 'keys'}
                or not isinstance(item['scope'], str)
                or len(item['scope']) != 44
                or not isinstance(item['keys'], list)
                or not item['keys']
                or len(item['keys']) > MAX_SCOPE_KEYS
                or any(not isinstance(key, str) for key in item['keys'])):
            raise DurableStateError('invalid durable scope')
        keys = tuple(item['keys'])
        try:
            wrong_namespace = any(ns_of(key) != expected_ns for key in keys)
        except (TypeError, ValueError):
            wrong_namespace = True
        if (tuple(sorted(keys)) != keys or len(keys) != len(set(keys))
                or wrong_namespace):
            raise DurableStateError('noncanonical durable scope')
        if _scope_id(expected_ns, keys) != item['scope'] or item['scope'] in scopes:
            raise DurableStateError('durable scope binding mismatch')
        scopes[item['scope']] = keys

    def expected_tip(count: int) -> str:
        return commitment(log[count - 1]) if count else ''

    def valid_slot(slot: tuple) -> bool:
        op = slot[0] if slot else None
        if op == 'checkpoint':
            return (len(slot) == 2 and natural(slot[1])
                    and slot[1] <= len(log))
        if op in {'register', 'head'}:
            if len(slot) != 4:
                return False
            _, scope, count, tip = slot
            return (isinstance(scope, str) and scope in scopes
                    and natural(count) and count <= len(log)
                    and isinstance(tip, str) and tip == expected_tip(count))
        if op == 'renew':
            if len(slot) != 5:
                return False
            _, scope, start, count, tip = slot
            return (isinstance(scope, str) and scope in scopes
                    and natural(start) and natural(count) and start <= count
                    and count <= len(log) and isinstance(tip, str)
                    and tip == expected_tip(count))
        if op == 'extend':
            if len(slot) != 6:
                return False
            _, old_scope, scope, start, count, tip = slot
            return (isinstance(old_scope, str) and old_scope in scopes
                    and isinstance(scope, str) and scope in scopes
                    and natural(start) and natural(count) and start <= count
                    and count <= len(log) and isinstance(tip, str)
                    and tip == expected_tip(count))
        return False

    signed_slots: dict[tuple, str] = {}
    for item in payload['signed_slots']:
        if (not isinstance(item, dict) or set(item) != {'slot', 'digest'}
                or not isinstance(item['slot'], list) or not item['slot']
                or not all(_slot_value(value) for value in item['slot'])
                or not isinstance(item['digest'], str)
                or len(item['digest']) != 44):
            raise DurableStateError('invalid durable signed slot')
        slot = tuple(item['slot'])
        if not valid_slot(slot):
            raise DurableStateError('invalid durable signed slot semantics')
        if slot in signed_slots:
            raise DurableStateError('duplicate durable signed slot')
        signed_slots[slot] = item['digest']

    return Witness(
        ns=expected_ns,
        witness_id=expected_id,
        faulty=expected_faulty,
        log=log,
        scopes=scopes,
        signed_slots=signed_slots,
        clock=payload['clock'],
        clock_epsilon=payload['clock_epsilon'],
    )


class DurableWitness:
    """A witness whose accepted state is persisted before its signature escapes."""

    def __init__(self, path: str | Path, ns: str, witness_id: str, *,
                 faulty: bool = False, clock_epsilon: int = 0):
        if witness_id not in WITNESS_IDS or not isinstance(ns, str) or not ns:
            raise ValueError('bad durable witness identity')
        if not natural(clock_epsilon):
            raise ValueError('bad witness clock epsilon')
        self.path = Path(path)
        self._unavailable_reason: str | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cleanup_temps()
        if self.path.exists():
            self.witness = self._load(ns, witness_id, faulty)
            if self.witness.clock_epsilon != clock_epsilon:
                raise DurableStateError('clock epsilon mismatch')
        else:
            self.witness = Witness(
                ns=ns, witness_id=witness_id, faulty=faulty,
                clock_epsilon=clock_epsilon,
            )
            self._persist()

    @property
    def ns(self) -> str:
        return self.witness.ns

    @property
    def witness_id(self) -> str:
        return self.witness.witness_id

    @property
    def faulty(self) -> bool:
        return self.witness.faulty

    def _cleanup_temps(self) -> None:
        pattern = f'.{self.path.name}.tmp-*'
        for candidate in self.path.parent.glob(pattern):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass

    def _ensure_available(self) -> None:
        if self._unavailable_reason is not None:
            raise DurableStateError(
                'durable witness requires restart: ' + self._unavailable_reason)

    def _poison(self, reason: str) -> None:
        self._unavailable_reason = reason

    def _payload(self) -> dict:
        return {
            'ns': self.witness.ns,
            'witness_id': self.witness.witness_id,
            'faulty': self.witness.faulty,
            'log': deepcopy(self.witness.log),
            'scopes': [
                {'scope': scope, 'keys': list(keys)}
                for scope, keys in sorted(self.witness.scopes.items())
            ],
            'signed_slots': [
                {'slot': list(slot), 'digest': digest}
                for slot, digest in sorted(
                    self.witness.signed_slots.items(),
                    key=lambda item: encode(list(item[0])),
                )
            ],
            'clock': self.witness.clock,
            'clock_epsilon': self.witness.clock_epsilon,
        }

    def _load(self, ns: str, witness_id: str, faulty: bool) -> Witness:
        try:
            raw = self.path.read_bytes()
            envelope = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DurableStateError('unreadable durable state') from exc
        if (not isinstance(envelope, dict)
                or set(envelope) != {'state', 'commitment'}
                or not isinstance(envelope['commitment'], str)
                or commitment(envelope['state']) != envelope['commitment']):
            raise DurableStateError('durable state commitment mismatch')
        return _validate_case_state(envelope['state'], ns, witness_id, faulty)

    def _persist(self, crash: str | None = None) -> None:
        if crash is not None and crash not in CRASH_PHASES:
            raise ValueError('unknown injected crash phase')
        payload = self._payload()
        envelope = {'state': payload, 'commitment': commitment(payload)}
        wire = encode(envelope) + b'\n'
        temp = self.path.parent / (
            f'.{self.path.name}.tmp-{os.getpid()}-{time.monotonic_ns()}'
        )
        replaced = False
        try:
            with temp.open('xb') as handle:
                handle.write(wire)
                handle.flush()
                os.fsync(handle.fileno())
            if crash == 'after-temp-fsync':
                raise InjectedCrash(crash)
            os.replace(temp, self.path)
            replaced = True
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            if crash == 'after-replace':
                raise InjectedCrash(crash)
        except InjectedCrash:
            raise
        except OSError as exc:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
            if replaced:
                raise DurableCommitUncertain(
                    'durable state replacement has uncertain directory commit') from exc
            raise DurableStateError('durable state commit failed') from exc

    def advance(self, now: int) -> None:
        self._ensure_available()
        before = deepcopy(self.witness)
        try:
            self.witness.advance(now)
            self._persist()
        except DurableCommitUncertain:
            self._poison('uncertain commit while advancing the logical clock')
            raise
        except InjectedCrash:
            self._poison('injected crash while advancing the logical clock')
            raise
        except Exception:
            self.witness = before
            raise

    def certify(self, body: dict, candidate: list[dict], *,
                crash: str | None = None) -> str | None:
        self._ensure_available()
        if crash is not None and crash not in CRASH_PHASES:
            raise ValueError('unknown injected crash phase')
        if crash == 'before-commit':
            self._poison('injected crash before durable commit')
            raise InjectedCrash(crash)
        before = deepcopy(self.witness)
        signature = self.witness.certify(body, candidate)
        if signature is None:
            return None
        try:
            self._persist(crash)
        except InjectedCrash:
            self._poison('injected crash during durable commit')
            raise
        except DurableCommitUncertain:
            self._poison('uncertain durable commit after replacement')
            raise
        except Exception:
            self.witness = before
            raise
        return signature

    def summary(self) -> DurableSummary:
        self._ensure_available()
        tip = commitment(self.witness.log[-1]) if self.witness.log else ''
        return DurableSummary(
            ns=self.witness.ns,
            witness_id=self.witness.witness_id,
            faulty=self.witness.faulty,
            count=len(self.witness.log),
            tip=tip,
            scopes=len(self.witness.scopes),
            signed_slots=len(self.witness.signed_slots),
            clock=self.witness.clock,
            state_bytes=self.path.stat().st_size,
        )
