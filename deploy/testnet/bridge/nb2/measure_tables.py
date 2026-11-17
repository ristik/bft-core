#!/usr/bin/env python3
"""Measurement only: the tables of the consolidation report from a measure_consolidation run's evidence.

    measure_tables.py EVIDENCE_NB2_DIR [OVGAS_JSONL...]
"""
import glob
import json
import os
import statistics
import sys

d = sys.argv[1]
J = lambda name: json.load(open(os.path.join(d, name))) if os.path.exists(os.path.join(d, name)) else None   # noqa: E731
ov = {}
for f in sys.argv[2:]:
    for line in open(f):
        r = json.loads(line)
        if 'file' in r:
            ov[os.path.basename(r['file']).removesuffix('.cbor')] = r
M = lambda g: f'{int(g) / 1e6:.2f}' if isinstance(g, (int, str)) and str(g).isdigit() else (g or '-')   # noqa: E731


def judge(label):
    for f in glob.glob(os.path.join(d, 'm-judge-*.json')):
        j = json.load(open(f))
        if label in j:
            return j[label]
    return None


print('## Preflight (wallet gas model) and token anatomy, before the burn\n')
print('| token | transfers | certs | evidence B | B/transfer | UC B/proof | siblings/proof | model gas M | planReturn |')
print('|---|---|---|---|---|---|---|---|---|')
labels = sorted({os.path.basename(f)[len('m-mk-'):-5] for f in glob.glob(os.path.join(d, 'm-mk-*.json'))}, key=lambda x: (x[0], int(''.join(c for c in x if c.isdigit()) or 0)))
for l in labels:
    for t in (l, l + 'k'):
        j = judge(t)
        if j is None:
            continue
        a = j['anatomy']
        pr = j['planReturn']
        pr = 'passes' if pr == 'passes' else ('refused: ' + ('bytes' if 'fit' in pr else 'gas'))
        print(f"| {t} | {a['transfers']} | {a['distinctCertificates']} | {a['evidenceBytes']} | {a['bytesPerTransfer']} | {a['ucBytesPerProof']} | {a['siblingsPerProof']} | {M(j['modelGas'])} | {pr} |")

print('\n## The same burn four ways: real gas (M)\n')
print('| burn | variant | certs | evidence B | siblings/proof | sigs | verifier gas | redeem gas (estimate) | verifier gas, cached build | paid gasUsed |')
print('|---|---|---|---|---|---|---|---|---|---|')
for f in sorted(glob.glob(os.path.join(d, 'm-burn3-*.json')), key=lambda x: (os.path.basename(x)[8], int(''.join(c for c in os.path.basename(x) if c.isdigit()) or 0))):
    b = json.load(open(f))
    label = b['label']
    pay = J(f'm-pay-{label}.json')
    for v, x in b['variants'].items():
        a = x['anatomy']
        o = ov.get(f'{label}-{v}', {}).get('new', {}).get('gas')
        paid = pay['paid']['gasUsed'] if pay and pay.get('variant') == v and pay.get('paid') else ''
        print(f"| {label} | {v} | {a['distinctCertificates']} | {a['evidenceBytes']} | {a['siblingsPerProof']} | {list(a['signaturesPerProof'])} | {M(x['verifierGas'])} | {M(x['redeemGas'])} | {M(o)} | {M(paid) if paid else ''} |")

print('\n## Determinism: five fresh 200-transfer tokens\n')
rows = []
for i in range(1, 6):
    jr, jk = judge(f'd{i}'), judge(f'd{i}k')
    b = J(f'm-burn3-d{i}.json')
    rows.append((i, jr, jk, b))
print('| probe | certs raw | model gas raw | model gas consolidated | evidence B raw | evidence B consolidated | verifier gas raw | pre | post | trim |')
print('|---|---|---|---|---|---|---|---|---|---|')
for i, jr, jk, b in rows:
    if jr is None or jk is None:
        continue
    vg = {v: (b['variants'][v]['verifierGas'] if b else '-') for v in ('raw', 'pre', 'post', 'trim')}
    print(f"| d{i} | {jr['anatomy']['distinctCertificates']} | {M(jr['modelGas'])} | {M(jk['modelGas'])} | {jr['anatomy']['evidenceBytes']} | {jk['anatomy']['evidenceBytes']} | {M(vg['raw'])} | {M(vg['pre'])} | {M(vg['post'])} | {M(vg['trim'])} |")


def spread(xs):
    xs = [int(x) for x in xs if str(x).isdigit()]
    if len(xs) < 2:
        return '-'
    steps = [b - a for a, b in zip(xs, xs[1:])]
    return f'range {(max(xs) - min(xs)) / 1e3:.0f}k, sd {statistics.pstdev(xs) / 1e3:.0f}k, mean drift per probe {statistics.mean(steps) / 1e3:+.0f}k'


ok = [r for r in rows if r[1] and r[2]]
print()
print('- model gas, raw:', spread([r[1]['modelGas'] for r in ok]))
print('- model gas, consolidated before the burn:', spread([r[2]['modelGas'] for r in ok]))
for v in ('raw', 'pre', 'post', 'trim'):
    print(f'- verifier gas, {v}:', spread([r[3]['variants'][v]['verifierGas'] for r in ok if r[3]]))
print('- evidence bytes, raw:', spread([r[1]['anatomy']['evidenceBytes'] for r in ok]).replace('k', ' kB').replace('range', 'range'))

print('\n## Consolidation cost\n')
print('| token | how | outer proofs | requests | ms | plug-in verify ms |')
print('|---|---|---|---|---|---|')
for f in sorted(glob.glob(os.path.join(d, 'm-consolidate-*.json'))):
    c = json.load(open(f))
    print(f"| {c['to']} | {c['how']}{' (SDK: ' + c['unavailable']['reason'] + ')' if c.get('unavailable') else ''} | {c['before']['proofs']} | {c['requests']} | {c['ms']} | {c['pluginVerifyMs']} |")
for f in sorted(glob.glob(os.path.join(d, 'm-burn3-*.json'))):
    b = json.load(open(f))
    pc = b.get('postConsolidation', {})
    print(f"| {b['label']} burned (post) | {pc.get('how')} | | {pc.get('requests')} | {pc.get('ms')} | |")

print('\n## Verifier acceptance\n')
print('| burn | variant | plug-in (TS) | deployed verifier | Go nb2ref | Rust plug-in |')
print('|---|---|---|---|---|---|')
for f in sorted(glob.glob(os.path.join(d, 'm-burn3-*.json'))):
    b = json.load(open(f))
    label = b['label']
    x = J(f'm-xverdicts-{label}.json') or {}
    x = x.get(label, {})
    for v, r in b['variants'].items():
        g = x.get('go', {}).get(f'{label}-{v}.cbor', {})
        ru = x.get('rust', {}).get(f'{label}-{v}.cbor', {})
        verdict = r['ts'].get('verdict')
        same = lambda o: 'accepts' + ('' if o.get('verdict') == verdict else ' (different verdict!)') if o.get('verdict') else (o.get('rule') or '-')   # noqa: E731
        print(f"| {label} | {v} | {'accepts' if verdict else r['ts'].get('rule')} | {same(r['solidity'])} | {same(g)} | {same(ru)} |")
