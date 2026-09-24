"""Process-isolated TCP witnesses with crash-durable state.

Each witness runs in a separate spawned Python process, owns a distinct loopback
listener and state directory, and persists accepted state before returning a
signature.  The parent harness can inject three deterministic crash windows and
restart a witness from its retained file.  This is a bounded owned-machine
recovery test, not a WAN deployment or a storage-loss model.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
from typing import Iterable

from codec import MAX_FRAME, encode
from durable_witness import DurableStateError, DurableWitness, InjectedCrash
from witness_delta import WITNESS_IDS

_CASE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')


@dataclass
class DurableNetworkCounters:
    messages: int = 0
    wire_bytes: int = 0
    certify_messages: int = 0
    certify_wire_bytes: int = 0
    control_messages: int = 0
    control_wire_bytes: int = 0
    drops: int = 0
    injected_crashes: int = 0
    restarts: int = 0


def _case_path(root: Path, case_id: str) -> Path:
    if not isinstance(case_id, str) or _CASE_RE.fullmatch(case_id) is None:
        raise ValueError('bad case id')
    return root / f'{case_id}.json'


async def _worker_server(witness_id: str, root: Path, ready) -> None:
    states: dict[str, DurableWitness] = {}

    async def handler(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        answer: dict = {'error': 'MALFORMED_REQUEST'}
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line or len(line) > MAX_FRAME:
                answer = {'error': 'FRAME_BOUND'}
            else:
                request = json.loads(line)
                if not isinstance(request, dict) or not isinstance(request.get('op'), str):
                    answer = {'error': 'BAD_REQUEST'}
                elif request['op'] == 'configure':
                    if set(request) != {'op', 'case', 'ns', 'faulty'}:
                        answer = {'error': 'BAD_REQUEST'}
                    else:
                        case_id = request['case']
                        path = _case_path(root, case_id)
                        faulty = bool(request['faulty'])
                        if request['faulty'] is not faulty or not isinstance(request['ns'], str):
                            answer = {'error': 'BAD_REQUEST'}
                        elif case_id in states:
                            state = states[case_id]
                            if state.ns != request['ns'] or state.faulty is not faulty:
                                answer = {'error': 'CONFIG_MISMATCH'}
                            else:
                                answer = {'ok': True, 'summary': asdict(state.summary())}
                        else:
                            state = DurableWitness(
                                path, request['ns'], witness_id, faulty=faulty)
                            states[case_id] = state
                            answer = {'ok': True, 'summary': asdict(state.summary())}
                elif request['op'] == 'advance':
                    if set(request) != {'op', 'case', 'now'} or request['case'] not in states:
                        answer = {'error': 'BAD_REQUEST'}
                    else:
                        states[request['case']].advance(request['now'])
                        answer = {'ok': True, 'summary': asdict(states[request['case']].summary())}
                elif request['op'] == 'certify':
                    if (set(request) != {'op', 'case', 'body', 'log', 'crash'}
                            or request['case'] not in states
                            or not isinstance(request['log'], list)
                            or (request['crash'] is not None
                                and not isinstance(request['crash'], str))):
                        answer = {'error': 'BAD_REQUEST'}
                    else:
                        try:
                            signature = states[request['case']].certify(
                                request['body'], request['log'],
                                crash=request['crash'])
                        except InjectedCrash:
                            os._exit(73)
                        answer = ({'id': witness_id, 'signature': signature,
                                   'summary': asdict(states[request['case']].summary())}
                                  if signature is not None
                                  else {'id': witness_id, 'reject': True})
                elif request['op'] == 'status':
                    if set(request) != {'op', 'case'} or request['case'] not in states:
                        answer = {'error': 'BAD_REQUEST'}
                    else:
                        answer = {'ok': True, 'summary': asdict(states[request['case']].summary())}
                else:
                    answer = {'error': 'BAD_REQUEST'}
            wire = encode(answer) + b'\n'
            if len(wire) > MAX_FRAME:
                wire = encode({'error': 'FRAME_BOUND'}) + b'\n'
            writer.write(wire)
            await writer.drain()
        except (DurableStateError, ValueError, KeyError, TypeError,
                asyncio.TimeoutError, json.JSONDecodeError, RecursionError) as exc:
            try:
                wire = encode({'error': type(exc).__name__}) + b'\n'
                writer.write(wire)
                await writer.drain()
            except (ConnectionError, RuntimeError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, RuntimeError):
                pass

    server = await asyncio.start_server(
        handler, '127.0.0.1', 0, limit=MAX_FRAME + 1)
    port = server.sockets[0].getsockname()[1]
    ready.send({'port': port, 'pid': os.getpid()})
    ready.close()
    async with server:
        await server.serve_forever()


def _worker_main(witness_id: str, root: str, ready) -> None:
    try:
        asyncio.run(_worker_server(witness_id, Path(root), ready))
    finally:
        try:
            ready.close()
        except OSError:
            pass


class DurableWitnessProcessNetwork:
    """Four spawned witness processes and their bounded TCP control plane."""

    def __init__(self, state_root: str | Path):
        self.state_root = Path(state_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        method = 'forkserver' if 'forkserver' in mp.get_all_start_methods() else 'spawn'
        self.context = mp.get_context(method)
        self.start_method = method
        self.processes: dict[str, mp.Process] = {}
        self.ports: dict[str, int] = {}
        self.pids: dict[str, int] = {}
        self.blocked: set[str] = set()
        self.counters = DurableNetworkCounters()
        self.cases: dict[str, tuple[str, frozenset[str]]] = {}

    def state_path(self, witness_id: str, case_id: str) -> Path:
        if witness_id not in WITNESS_IDS:
            raise ValueError('unknown witness')
        return _case_path(self.state_root / witness_id, case_id)

    def _start(self, witness_id: str) -> None:
        if witness_id not in WITNESS_IDS or witness_id in self.processes:
            raise ValueError('bad witness start')
        root = self.state_root / witness_id
        root.mkdir(parents=True, exist_ok=True)
        parent, child = self.context.Pipe(duplex=False)
        process = self.context.Process(
            target=_worker_main,
            args=(witness_id, str(root), child),
            name=f'durable-{witness_id}',
        )
        process.start()
        child.close()
        try:
            if not parent.poll(10):
                raise RuntimeError('witness start timeout')
            ready = parent.recv()
        finally:
            parent.close()
        if (not isinstance(ready, dict) or set(ready) != {'port', 'pid'}
                or not isinstance(ready['port'], int)
                or not isinstance(ready['pid'], int)):
            process.terminate(); process.join(timeout=5)
            raise RuntimeError('bad witness ready message')
        self.processes[witness_id] = process
        self.ports[witness_id] = ready['port']
        self.pids[witness_id] = ready['pid']

    def _stop(self, witness_id: str) -> None:
        process = self.processes.pop(witness_id, None)
        self.ports.pop(witness_id, None)
        self.pids.pop(witness_id, None)
        if process is None:
            return
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            process.kill(); process.join(timeout=5)

    async def __aenter__(self):
        for witness_id in WITNESS_IDS:
            self._start(witness_id)
        if len(set(self.pids.values())) != len(WITNESS_IDS):
            raise RuntimeError('witness processes are not distinct')
        return self

    async def __aexit__(self, *args):
        for witness_id in tuple(WITNESS_IDS):
            self._stop(witness_id)

    async def rpc(self, witness_id: str, request: dict,
                  *, timeout: float = 8.0) -> dict | None:
        if witness_id in self.blocked:
            self.counters.drops += 1
            return None
        process = self.processes.get(witness_id)
        if process is None or not process.is_alive():
            self.counters.drops += 1
            return None
        wire = encode(request) + b'\n'
        if len(wire) > MAX_FRAME:
            raise ValueError('outbound frame too large')
        certify = request.get('op') == 'certify'
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    '127.0.0.1', self.ports[witness_id],
                    limit=MAX_FRAME + 1),
                timeout,
            )
            writer.write(wire)
            await writer.drain()
            self.counters.messages += 1
            self.counters.wire_bytes += len(wire)
            if certify:
                self.counters.certify_messages += 1
                self.counters.certify_wire_bytes += len(wire)
            else:
                self.counters.control_messages += 1
                self.counters.control_wire_bytes += len(wire)
            reply = await asyncio.wait_for(reader.readline(), timeout)
            if not reply:
                self.counters.injected_crashes += 1
                return None
            self.counters.messages += 1
            self.counters.wire_bytes += len(reply)
            if certify:
                self.counters.certify_messages += 1
                self.counters.certify_wire_bytes += len(reply)
            else:
                self.counters.control_messages += 1
                self.counters.control_wire_bytes += len(reply)
            return json.loads(reply)
        except (ConnectionError, OSError, asyncio.TimeoutError,
                json.JSONDecodeError):
            self.counters.drops += 1
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, RuntimeError):
                    pass

    async def configure(self, case_id: str, ns: str, *,
                        faulty: Iterable[str] = (), strict: bool = True) -> dict[str, dict | None]:
        faulty_set = frozenset(faulty)
        if len(faulty_set) > 1 or not faulty_set <= set(WITNESS_IDS):
            raise ValueError('fault bound')
        prior = self.cases.get(case_id)
        if prior is not None and prior != (ns, faulty_set):
            raise ValueError('case configuration mismatch')
        self.cases[case_id] = (ns, faulty_set)
        replies = {
            witness_id: reply
            for witness_id, reply in zip(
                WITNESS_IDS,
                await asyncio.gather(*(
                    self.rpc(witness_id, {
                        'op': 'configure', 'case': case_id, 'ns': ns,
                        'faulty': witness_id in faulty_set,
                    }) for witness_id in WITNESS_IDS
                )),
            )
        }
        if strict and any(reply is None or reply.get('ok') is not True
                          for reply in replies.values()):
            raise RuntimeError('durable witness configuration failed')
        return replies

    async def advance(self, case_id: str, now: int, *,
                      strict: bool = True) -> dict[str, dict | None]:
        replies = {
            witness_id: reply
            for witness_id, reply in zip(
                WITNESS_IDS,
                await asyncio.gather(*(
                    self.rpc(witness_id, {
                        'op': 'advance', 'case': case_id, 'now': now,
                    }) for witness_id in WITNESS_IDS
                )),
            )
        }
        if strict and any(reply is None or reply.get('ok') is not True
                          for reply in replies.values()):
            raise RuntimeError('durable witness clock advance failed')
        return replies

    async def signatures(self, case_id: str, body: dict, log: list[dict], *,
                         crash: dict[str, str] | None = None) -> list[dict]:
        crash = {} if crash is None else dict(crash)
        if not set(crash) <= set(WITNESS_IDS):
            raise ValueError('unknown crash witness')
        replies = await asyncio.gather(*(
            self.rpc(witness_id, {
                'op': 'certify', 'case': case_id, 'body': body,
                'log': log, 'crash': crash.get(witness_id),
            }) for witness_id in WITNESS_IDS
        ))
        return [
            {'id': reply['id'], 'signature': reply['signature']}
            for reply in replies
            if reply is not None and 'signature' in reply
        ]

    async def status(self, case_id: str) -> dict[str, dict | None]:
        replies = await asyncio.gather(*(
            self.rpc(witness_id, {'op': 'status', 'case': case_id})
            for witness_id in WITNESS_IDS
        ))
        return dict(zip(WITNESS_IDS, replies))

    def stop(self, witness_id: str) -> None:
        """Abruptly stop one witness process while retaining its state files."""
        if witness_id not in WITNESS_IDS:
            raise ValueError('unknown witness')
        self._stop(witness_id)

    async def restart(self, witness_id: str, *, strict: bool = True,
                      cases: Iterable[str] | None = None) -> bool:
        if witness_id not in WITNESS_IDS:
            raise ValueError('unknown witness')
        self._stop(witness_id)
        self._start(witness_id)
        self.counters.restarts += 1
        selected = tuple(self.cases) if cases is None else tuple(cases)
        if any(case_id not in self.cases for case_id in selected):
            raise ValueError('unknown recovery case')
        ok = True
        for case_id in selected:
            ns, faulty = self.cases[case_id]
            reply = await self.rpc(witness_id, {
                'op': 'configure', 'case': case_id, 'ns': ns,
                'faulty': witness_id in faulty,
            })
            if reply is None or reply.get('ok') is not True:
                ok = False
        if strict and not ok:
            raise RuntimeError('durable witness recovery failed')
        return ok

    async def restart_all(self, *, strict: bool = True,
                          cases: Iterable[str] | None = None) -> bool:
        selected = None if cases is None else tuple(cases)
        ok = True
        for witness_id in WITNESS_IDS:
            ok = await self.restart(
                witness_id, strict=strict, cases=selected) and ok
        return ok
