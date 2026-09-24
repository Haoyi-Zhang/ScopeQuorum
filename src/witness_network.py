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


@dataclass
class NetworkCounters:
    messages: int = 0
    wire_bytes: int = 0
    drops: int = 0


class WitnessTCPNetwork:
    def __init__(self):
        self.servers = []
        self.ports: dict[str, int] = {}
        self.states: dict[str, dict[str, Witness]] = {wid: {} for wid in WITNESS_IDS}
        self.blocked: set[str] = set()
        self.counters = NetworkCounters()

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
                                or set(request) != {'op', 'case', 'body', 'log'}
                                or request['op'] != 'certify'
                                or request['case'] not in self.states[wid]
                                or not isinstance(request['log'], list)):
                            answer = {'error': 'BAD_REQUEST'}
                        else:
                            signature = self.states[wid][request['case']].certify(
                                request['body'], request['log'])
                            answer = ({'id': wid, 'signature': signature}
                                      if signature is not None else {'id': wid, 'reject': True})
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

    async def rpc(self, wid: str, case_id: str, body: dict, log: list[dict]) -> dict | None:
        if wid in self.blocked:
            self.counters.drops += 1
            return None
        request = {'op': 'certify', 'case': case_id, 'body': body, 'log': log}
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
        return json.loads(reply)

    async def signatures(self, case_id: str, body: dict, log: list[dict]) -> list[dict]:
        replies = await asyncio.gather(*(
            self.rpc(wid, case_id, body, log) for wid in WITNESS_IDS
        ))
        return [
            {'id': reply['id'], 'signature': reply['signature']}
            for reply in replies
            if reply is not None and 'signature' in reply
        ]
