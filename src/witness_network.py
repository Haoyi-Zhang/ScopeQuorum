"""Four loopback TCP witness services for bounded protocol validation.

Each listener owns independent ``Witness`` state.  The implementation runs in
one Python process and therefore does not model machine failure independence or
WAN behavior.  It exists to exercise framing, distinct endpoints, partitions,
and exact signed report exchange with the same verifier used by the core model.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from codec import MAX_FRAME, encode
from witness_delta import WITNESS_IDS, Witness
from witness_sync import HistorySession, incremental_certify


@dataclass
class NetworkCounters:
    messages: int = 0
    wire_bytes: int = 0
    drops: int = 0
    history_events: int = 0
    prefix_wire_bytes: int = 0
    sync_wire_bytes: int = 0
    reset_wire_bytes: int = 0
    certify_wire_bytes: int = 0


class WitnessTCPNetwork:
    def __init__(self, *, incremental: bool = True):
        self.servers = []
        self.ports: dict[str, int] = {}
        self.states: dict[str, dict[str, Witness]] = {wid: {} for wid in WITNESS_IDS}
        self.blocked: set[str] = set()
        self.counters = NetworkCounters()
        self.incremental = incremental
        self.sessions: dict[str, dict[str, HistorySession]] = {wid: {} for wid in WITNESS_IDS}

    def configure(self, case_id: str, ns: str, *, faulty: tuple[str, ...] = ()) -> None:
        if not isinstance(case_id, str) or not case_id or len(case_id) > 128:
            raise ValueError('bad case id')
        faulty_set = set(faulty)
        if len(faulty_set) > 1 or not faulty_set <= set(WITNESS_IDS):
            raise ValueError('fault bound')
        for wid in WITNESS_IDS:
            if case_id in self.states[wid]:
                raise ValueError('duplicate case')
            self.states[wid][case_id] = Witness(ns, wid, wid in faulty_set)
            self.sessions[wid][case_id] = HistorySession(self.states[wid][case_id])

    def advance(self, case_id: str, now: int) -> None:
        """Advance each endpoint's local logical clock outside the RPC path."""
        for wid in WITNESS_IDS:
            if case_id not in self.states[wid]:
                raise ValueError('unknown case')
            self.states[wid][case_id].advance(now)

    async def __aenter__(self):
        for wid in WITNESS_IDS:
            async def handler(reader, writer, wid=wid):
                answer = {'error': 'MALFORMED_REQUEST'}
                try:
                    line = await asyncio.wait_for(reader.readline(), 3)
                    if not line or len(line) > MAX_FRAME:
                        answer = {'error': 'FRAME_BOUND'}
                    else:
                        request = json.loads(line)
                        if (not isinstance(request, dict)
                                or request.get('case') not in self.states[wid]):
                            answer = {'error': 'BAD_REQUEST'}
                        else:
                            session = self.sessions[wid][request['case']]
                            fields = set(request)
                            if request.get('op') == 'prefix' and fields == {'op', 'case'}:
                                answer = session.frontier()
                            elif request.get('op') == 'reset' and fields == {'op', 'case', 'ns'}:
                                answer = session.reset(request['ns'])
                            elif request.get('op') == 'sync' and fields == {'op', 'case', 'ns', 'start', 'previous', 'events'}:
                                answer = session.sync(request['ns'], request['start'], request['previous'], request['events'])
                            elif (request.get('op') == 'certify'
                                  and fields in ({'op', 'case', 'body'}, {'op', 'case', 'body', 'log'})
                                  and ('log' not in request or isinstance(request['log'], list))):
                                signature = session.certify(request['body'], log=request.get('log'))
                                answer = ({'id': wid, 'signature': signature}
                                          if signature is not None else {'id': wid, 'reject': True})
                            else:
                                answer = {'error': 'BAD_REQUEST'}
                    wire = encode(answer) + b'\n'
                    if len(wire) > MAX_FRAME:
                        wire = encode({'error': 'FRAME_BOUND'}) + b'\n'
                    writer.write(wire); await writer.drain()
                except (ValueError, KeyError, TypeError, asyncio.TimeoutError,
                        json.JSONDecodeError, RecursionError):
                    writer.write(encode(answer) + b'\n'); await writer.drain()
                finally:
                    writer.close(); await writer.wait_closed()
            server = await asyncio.start_server(
                handler, '127.0.0.1', 0, limit=MAX_FRAME + 1)
            self.servers.append(server)
            self.ports[wid] = server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *args):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))

    async def exchange(self, wid: str, request: dict) -> dict | None:
        if wid in self.blocked:
            self.counters.drops += 1
            return None
        wire = encode(request) + b'\n'
        if len(wire) > MAX_FRAME:
            raise ValueError('outbound frame too large')
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', self.ports[wid], limit=MAX_FRAME + 1), 3)
        try:
            writer.write(wire); await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), 3)
        finally:
            writer.close(); await writer.wait_closed()
        self.counters.messages += 2
        self.counters.wire_bytes += len(wire) + len(reply)
        op = request['op']
        field = op + '_wire_bytes'
        if hasattr(self.counters, field):
            setattr(self.counters, field, getattr(self.counters, field) + len(wire) + len(reply))
        self.counters.history_events += len(request.get('events', request.get('log', [])))
        return json.loads(reply)

    async def rpc(self, wid: str, case_id: str, body: dict, log: list[dict]) -> dict | None:
        if self.incremental:
            return await incremental_certify(
                lambda request: self.exchange(wid, request), case_id, body, log)
        return await self.exchange(wid, {
            'op': 'certify', 'case': case_id, 'body': body, 'log': log})

    async def signatures(self, case_id: str, body: dict, log: list[dict]) -> list[dict]:
        replies = await asyncio.gather(*(
            self.rpc(wid, case_id, body, log) for wid in WITNESS_IDS
        ))
        return [
            {'id': reply['id'], 'signature': reply['signature']}
            for reply in replies
            if reply is not None and 'signature' in reply
        ]
