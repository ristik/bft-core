#!/usr/bin/env python3
"""Measurement only: the verifier's gas on evidence files with its runtime code replaced by eth_call state overrides (validator 1 directly).

    ovgas.py RPC VERIFIER GAMMA_HEX_FILE ORIG_ARTIFACT_JSON NEW_ARTIFACT_JSON EVIDENCE...

The new runtime gets the deployed verifier's immutables (read from its on-chain code at the positions the unmodified build names). The
unmodified build, filled the same way, must reproduce the on-chain code byte for byte (the fidelity check). One JSON line per file:
gas of verifyReturn as deployed, under the unmodified build, and under the new build, with each one's return or revert.
"""
import json, sys, urllib.request
rpc, verifier, gamma_file, orig_art, new_art, *files = sys.argv[1:]

def call(method, params):
    req = urllib.request.Request(rpc, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())

def art(p):
    d = json.load(open(p))
    db = d['deployedBytecode']
    return bytes.fromhex(db['object'].removeprefix('0x')), db.get('immutableReferences', {})

chain = bytes.fromhex(call('eth_getCode', [verifier, 'latest'])['result'][2:])
orig, oref = art(orig_art)
new, nref = art(new_art)
vals = {k: chain[v[0]['start']:v[0]['start'] + v[0]['length']] for k, v in oref.items()}
def fill(code, refs):
    c = bytearray(code)
    for k, v in refs.items():
        for r in v:
            c[r['start']:r['start'] + r['length']] = vals[k]
    return bytes(c)
fo = fill(orig, oref)
ok=sorted(oref,key=int); nk=sorted(nref,key=int); assert len(ok)==len(nk)
nref={ok[i]: nref[nk[i]] for i in range(len(ok))}  # the same immutables in declaration order
fn = fill(new, nref)
print(json.dumps({'fidelity': fo == chain, 'chainBytes': len(chain), 'newBytes': len(fn), 'immutables': {k: v.hex() for k, v in vals.items()}}))
gamma = bytes.fromhex(open(gamma_file).read().strip().removeprefix('0x'))

def abi2(sel, a, b):
    pad = lambda x: x + b'\0' * ((32 - len(x) % 32) % 32)
    u = lambda n: n.to_bytes(32, 'big')
    ta = u(len(a)) + pad(a)
    return sel + u(64) + u(64 + len(ta)) + ta + u(len(b)) + pad(b)

SELECTOR = bytes.fromhex('df447dca')  # cast sig 'verifyReturn(bytes,bytes)'
for f in files:
    ev = open(f, 'rb').read()
    data = '0x' + abi2(SELECTOR, gamma, ev).hex()
    tx = {'to': verifier, 'data': data, 'gas': hex(500_000_000)}
    row = {'file': f, 'bytes': len(ev)}
    for name, ov in (('deployed', None), ('orig', fo), ('new', fn)):
        params = [tx, 'latest'] + ([{verifier: {'code': '0x' + ov.hex()}}] if ov is not None else [])
        g = call('eth_estimateGas', params)
        r = call('eth_call', params)
        row[name] = {'gas': int(g['result'], 16) if 'result' in g else None, 'error': (g.get('error') or {}).get('message'),
                     'ret': (r.get('result') or '')[:66] + '..' if 'result' in r else None, 'callError': (r.get('error') or {}).get('message')}
    print(json.dumps(row))
