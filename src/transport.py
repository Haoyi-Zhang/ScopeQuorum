"""Six loopback TCP services with a deterministic link-drop emulator.

A single asyncio worker hosts independent replica stores and TCP listeners.
This measures a localhost protocol, not six machine failure domains or WAN RTTs.
"""
from __future__ import annotations
import asyncio
import json
import time
from codec import NAMESPACES, MAX_FRAME, encode, natural
from model import Authority, Replica
from status_reference import produce

def owner(ns: str) -> int:
    return int(ns[1:]) % 6

class Node:
    def __init__(self, number: int):
        self.number=number
        self.clock=0
        self.replica=Replica()
        self.authorities={n:Authority(n) for n in NAMESPACES if owner(n)==number}

    def advance(self, now: int) -> None:
        # Trusted local emulator control, deliberately NOT an RPC operation.
        if not natural(now) or now < self.clock:
            raise ValueError('invalid local clock advance')
        self.clock=now

    def dispatch(self, request: dict) -> dict:
        op=request['op']
        if op in {'append','snapshot','status'}:
            if not natural(request.get('now')) or request['now'] != self.clock:
                return {'error':'CLOCK_MISMATCH'}
        if op=='append':
            ns=request['ns']
            if ns not in self.authorities: return {'error':'NOT_AUTHORITY'}
            try:
                e=self.authorities[ns].append(request['kind'],request['data'],self.clock)
                self.replica.ingest(e)
                self.replica.cache_head(self.authorities[ns].head(self.clock))
                return {'event':e}
            except (ValueError,TypeError,KeyError): return {'error':'REJECTED'}
        if op=='status':
            ns=request['ns']
            if ns not in self.authorities:return {'error':'NOT_AUTHORITY'}
            return produce(ns,self.authorities[ns].log,request['keys'],self.clock)
        if op=='snapshot':
            ns=request['ns']; start=request.get('start',0); batch=request.get('batch',128)
            if ns not in self.authorities: return {'error':'NOT_AUTHORITY'}
            if type(start) is not int or start<0 or type(batch) is not int or not 1<=batch<=256:
                return {'error':'BAD_RANGE'}
            a=self.authorities[ns]
            return {'events':a.log[start:start+batch],'heads':[a.head(self.clock)]}
        if op=='deliver':
            events=request.get('events',[]); heads=request.get('heads',[])
            if len(events)>256 or len(heads)>len(NAMESPACES): return {'error':'BATCH_BOUND'}
            admitted=sum(self.replica.ingest(e) for e in events)
            for h in heads: self.replica.cache_head(h)
            return {'admitted':admitted}
        if op=='inventory':
            return {'counts':{n:len(self.replica.prefix(n)) for n in NAMESPACES}}
        if op=='delta':
            batch=request.get('batch',128)
            if type(batch) is not int or not 1<=batch<=256: return {'error':'BATCH_BOUND'}
            result=[]
            for n in NAMESPACES:
                start=request['after'].get(n,0)
                if type(start) is not int or start<0: return {'error':'BAD_RANGE'}
                result.extend(self.replica.prefix(n)[start:][:batch-len(result)])
                if len(result)>=batch: break
            return {'events':result,'heads':list(self.replica.heads.values())}
        if op=='discover':
            closure,support=self.replica.discover(request['root'])
            return {'closure':closure,'support':sorted(support)}
        if op=='certificate': return self.replica.certificate(request['root'],request.get('full',False))
        if op=='rollback': self.replica.rollback(); return {'rolled_back':True}
        if op=='stats': return {'verified':self.replica.verified,'replayed':self.replica.replayed}
        return {'error':'UNKNOWN_OPERATION'}

class Network:
    def __init__(self):
        self.nodes=[Node(i) for i in range(6)]
        self.servers=[];self.ports=[];self.blocked=set()
        self.messages=0;self.bytes=0;self.drops=0;self.log=[]

    async def __aenter__(self):
        for node in self.nodes:
            async def handler(reader,writer,node=node):
                try:
                    line=await asyncio.wait_for(reader.readline(),timeout=3)
                    if len(line)>MAX_FRAME: answer={'error':'FRAME_BOUND'}
                    else: answer=node.dispatch(json.loads(line))
                    wire=encode(answer)+b'\n'
                    if len(wire)>MAX_FRAME:wire=encode({'error':'FRAME_BOUND'})+b'\n'
                    writer.write(wire);await writer.drain()
                except (ValueError,KeyError,TypeError,asyncio.TimeoutError,RecursionError):
                    writer.write(encode({'error':'MALFORMED_REQUEST'})+b'\n')
                    await writer.drain()
                finally:
                    writer.close();await writer.wait_closed()
            server=await asyncio.start_server(handler,'127.0.0.1',0,limit=MAX_FRAME+1)
            self.servers.append(server);self.ports.append(server.sockets[0].getsockname()[1])
        return self

    async def __aexit__(self,*args):
        for server in self.servers: server.close()
        await asyncio.gather(*(s.wait_closed() for s in self.servers))

    async def rpc(self, source: int, dest: int, request: dict) -> dict | None:
        if (source,dest) in self.blocked:
            self.drops+=1;self.log.append({'source':source,'dest':dest,'op':request['op'],'dropped':True})
            return None
        started=time.perf_counter()
        wire=encode(request)+b'\n'
        if len(wire)>MAX_FRAME: raise ValueError('outbound frame too large')
        reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',self.ports[dest],limit=MAX_FRAME+1),3)
        try:
            writer.write(wire);await writer.drain()
            reply=await asyncio.wait_for(reader.readline(),3)
        finally:
            writer.close();await writer.wait_closed()
        self.messages+=2;self.bytes+=len(wire)+len(reply)
        self.log.append({'source':source,'dest':dest,'op':request['op'],
                         'request_bytes':len(wire),'reply_bytes':len(reply),
                         'elapsed_ms':(time.perf_counter()-started)*1000,'dropped':False})
        return json.loads(reply)

    def advance(self, now: int) -> None:
        for node in self.nodes:node.advance(now)

    def isolate(self, node: int):
        self.blocked={(i,node) for i in range(6) if i!=node}|{(node,i) for i in range(6) if i!=node}

    async def gossip(self, batch: int = 128):
        # One directed ring round. Issuers remain sources of their own streams.
        for dest in range(6):
            source=(dest-1)%6
            if (source,dest) in self.blocked:
                self.drops+=1;continue
            inv=await self.rpc(dest,dest,{'op':'inventory'})
            delta=await self.rpc(dest,source,{'op':'delta','after':inv['counts'],'batch':batch})
            if delta is not None:
                await self.rpc(source,dest,{'op':'deliver',**delta})
