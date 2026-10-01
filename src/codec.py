"""Canonical wire encoding and a deliberately public, test-only signing fixture.

No fixture key may be used for a real service. Proofs assume unforgeability and
binding abstract interfaces; the fixture instantiates these with Ed25519/SHA256.
Only protocol objects carry commitments, never a toolchain/hash manifest.
"""
from __future__ import annotations
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from binascii import Error as Base64Error

NAMESPACES = tuple(f'n{i}' for i in range(12))
MAX_EVENTS = 4096
MAX_FRAME = 8 * 1024 * 1024

def encode(x: object) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')

def commitment(x: object) -> str:
    return base64.b64encode(hashlib.sha256(encode(x)).digest()).decode('ascii')

def key(name: str) -> Ed25519PrivateKey:
    # Public deterministic seed material, not a password or a production key.
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(('PUBLIC-TOY-KEY:' + name).encode()).digest())

def sign(who: str, body: dict) -> str:
    return base64.b64encode(key(who).sign(encode(body))).decode('ascii')

def verify(who: str, body: dict, signature: str) -> bool:
    try:
        if not isinstance(signature, str) or len(signature) != 88:
            return False
        key(who).public_key().verify(base64.b64decode(signature, validate=True), encode(body))
        return True
    except (ValueError, TypeError, InvalidSignature, Base64Error):
        return False

def ns_of(artifact: str) -> str:
    if not isinstance(artifact, str) or len(artifact) > 256 or '/' not in artifact:
        raise ValueError('invalid artifact key')
    ns, suffix = artifact.split('/', 1)
    if ns not in NAMESPACES or not suffix or '/' in suffix:
        raise ValueError('invalid artifact key')
    return ns

def natural(x: object) -> bool:
    return type(x) is int and 0 <= x < 2**63

def issuance_covers(log: object, issued: object) -> bool:
    """Return whether ``issued`` is a valid time at or after the log frontier.

    Producers use this before signing a status assertion or allocating state.
    The check is intentionally small: admission and replay validate the history;
    this guard prevents a report timestamp from preceding its latest accepted
    event.  Malformed inputs fail closed.
    """
    if not natural(issued) or not isinstance(log, list):
        return False
    if not log:
        return True
    try:
        accepted = log[-1]['body']['accepted']
    except (KeyError, TypeError, IndexError):
        return False
    return natural(accepted) and issued >= accepted

def signed_receipt(ns: str, seq: int, previous: str, now: int,
                   kind: str, data: dict) -> dict:
    body = dict(ns=ns, seq=seq, previous=previous, accepted=now, kind=kind, data=data)
    return dict(body=body, signature=sign('authority:' + ns, body))

def authenticated(receipt: dict) -> bool:
    try:
        b = receipt['body']
        return (set(receipt) == {'body', 'signature'} and
                set(b) == {'ns','seq','previous','accepted','kind','data'} and
                b['ns'] in NAMESPACES and natural(b['seq']) and b['seq'] > 0 and
                natural(b['accepted']) and isinstance(b['previous'],str) and
                len(b['previous']) <= 44 and isinstance(b['data'],dict) and
                verify('authority:' + b['ns'], b, receipt['signature']))
    except (KeyError, TypeError):
        return False

def make_head(ns: str, log: list[dict], now: int) -> dict:
    body = dict(ns=ns, count=len(log), tip=commitment(log[-1]) if log else '', issued=now)
    return dict(body=body, signature=sign('authority:' + ns, body))

def manifest(ns: str, name: str, deps: list[str], epoch: int = 0,
             blob: str | None = None) -> dict:
    m = dict(ns=ns, key=f'{ns}/{name}', deps=sorted(deps), epoch=epoch,
             publisher=f'publisher:{ns}:{epoch}', cap=f'cap:{ns}:{epoch}',
             blob=blob if blob is not None else 'object:' + name)
    return dict(manifest=m, signature=sign(m['publisher'],m))
