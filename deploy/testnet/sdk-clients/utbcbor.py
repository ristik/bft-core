"""A minimal deterministic-CBOR codec and the negative-fixture builder of the public SDK acceptance clients (bft-core #430 row 2).

Only the shapes of the Unicity Trust Base are handled: the tag-39000 entry [version, network, epoch, epochStart, members, quorum, stateHash,
changeRecordHash, previousEntryId, signatures|null] and the tag-39015 response/bundle [1, network, status, fromEpoch, effectiveEnd, endEntryId|null,
[entry...], nextEpoch|null]. The fixtures are derived from REAL entries (a complete served history); the module never signs anything: a weakened entry
is the real entry with fewer signatures, a wrong-network genesis is the real genesis with another network id. The SDKs verify; this only prepares bytes.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ENTRY_TAG, RESPONSE_TAG = 39000, 39015


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class Raw(bytes):
    """Already-encoded CBOR, embedded verbatim."""


class Map:
    def __init__(self, pairs):
        self.pairs = list(pairs)


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for width, code in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | code]) + n.to_bytes(width, 'big')
    raise ValueError('integer too large')


def encode(v):
    if isinstance(v, Raw):
        return bytes(v)
    if v is None:
        return b'\xf6'
    if isinstance(v, bool):
        return b'\xf5' if v else b'\xf4'
    if isinstance(v, int):
        return _head(0, v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return _head(3, len(raw)) + raw
    if isinstance(v, list):
        return _head(4, len(v)) + b''.join(encode(x) for x in v)
    if isinstance(v, Map):
        return _head(5, len(v.pairs)) + b''.join(encode(k) + encode(x) for k, x in v.pairs)
    if isinstance(v, Tag):
        return _head(6, v.tag) + encode(v.value)
    raise TypeError(type(v))


def _arg(buf, pos, info):
    if info < 24:
        return info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
    return int.from_bytes(buf[pos:pos + width], 'big'), pos + width


def _decode(buf, pos):
    major, info = buf[pos] >> 5, buf[pos] & 31
    pos += 1
    if major == 7:
        return {20: False, 21: True, 22: None}[info], pos
    n, pos = _arg(buf, pos, info)
    if major == 0:
        return n, pos
    if major in (2, 3):
        raw = bytes(buf[pos:pos + n])
        return (raw if major == 2 else raw.decode()), pos + n
    if major == 4:
        out = []
        for _ in range(n):
            x, pos = _decode(buf, pos)
            out.append(x)
        return out, pos
    if major == 5:
        pairs = []
        for _ in range(n):
            k, pos = _decode(buf, pos)
            x, pos = _decode(buf, pos)
            pairs.append((k, x))
        return Map(pairs), pos
    if major == 6:
        x, pos = _decode(buf, pos)
        return Tag(n, x), pos
    raise ValueError(f'unsupported CBOR major type {major}')


def decode(buf):
    value, end = _decode(buf, 0)
    if end != len(buf):
        raise ValueError('trailing bytes')
    return value


def entry_fields(raw):
    t = decode(raw)
    assert isinstance(t, Tag) and t.tag == ENTRY_TAG and len(t.value) == 10, 'not a trust-base entry'
    assert encode(t) == raw, 'the entry is not in the deterministic form this tool re-encodes'
    return t.value


def entry_id(raw):
    """SHA-256 of the entry with its signature field null (what a successor links to and a pin names)."""
    f = list(entry_fields(raw))
    f[9] = None
    return hashlib.sha256(encode(Tag(ENTRY_TAG, f))).digest()


def response(network, status, from_epoch, end, end_id, entries, next_epoch):
    return encode(Tag(RESPONSE_TAG, [1, network, status, from_epoch, end, end_id, [Raw(e) for e in entries], next_epoch]))


def parse_response(raw):
    t = decode(raw)
    assert isinstance(t, Tag) and t.tag == RESPONSE_TAG and len(t.value) == 8, 'not a trust-base response'
    v = t.value
    return {'network': v[1], 'status': v[2], 'from': v[3], 'end': v[4], 'endId': v[5], 'entries': [encode(e) if not isinstance(e, bytes) else e for e in v[6]], 'next': v[7]}


def history(bundle):
    """The raw entries of a complete bundle (status OK, from the genesis epoch, no cursor), contiguous and linked by entry id."""
    r = parse_response(bundle)
    assert r['status'] == 0 and r['next'] is None, 'the bundle is not complete'
    entries = r['entries']
    for i, raw in enumerate(entries):
        f = entry_fields(raw)
        assert f[2] == entry_fields(entries[0])[2] + i, 'epochs are not contiguous'
        if i:
            assert f[8] == entry_id(entries[i - 1]), 'an entry does not link to its predecessor'
    return r['network'], entries


def bundle_of(network, entries):
    return response(network, 0, entry_fields(entries[0])[2], entry_fields(entries[-1])[2], entry_id(entries[-1]), entries, None)


def weaken(pred, entry):
    """The real ENTRY with signatures reduced to the greatest prefix whose weight stays below the predecessor's quorum floor(2W/3)+1."""
    members = {m[0]: m[2] for m in entry_fields(pred)[4]}
    total = sum(members.values())
    threshold = 2 * total // 3 + 1
    f = list(entry_fields(entry))
    kept, weight = [], 0
    for node, sig in f[9].pairs:
        if weight + members.get(node, 0) < threshold:
            kept.append((node, sig))
            weight += members.get(node, 0)
    assert len(kept) < len(f[9].pairs), 'the entry has no signature to drop'
    f[9] = Map(kept)
    return encode(Tag(ENTRY_TAG, f)), {'predecessorTotalWeight': total, 'quorum': threshold, 'signaturesKept': len(kept), 'signaturesOriginal': len(entry_fields(entry)[9].pairs), 'keptWeight': weight}


def other_network(genesis, network):
    """The real genesis entry of another network id (its entry id differs; it is a genesis of its own, which is all a session pins)."""
    f = list(entry_fields(genesis))
    other = network + 1 if network < 0xffff else network - 1
    f[1] = other
    return encode(Tag(ENTRY_TAG, f)), other


def build_negatives(bundle, out):
    """Write the fixture directory of the clients' --negatives from a complete history of at least three epochs: genesis.bundle.cbor, entry-2/3.cbor (the real
    entries after the genesis), entry-2.weak.cbor, genesis.othernet.bundle.cbor and negatives.json (the facts about them)."""
    network, entries = history(bundle)
    assert len(entries) >= 3, 'the negatives need a history of at least three epochs'
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    g = entry_fields(entries[0])[2]
    weak, facts = weaken(entries[0], entries[1])
    other_genesis, other = other_network(entries[0], network)
    (out / 'genesis.bundle.cbor').write_bytes(bundle_of(network, entries[:1]))
    (out / 'entry-2.cbor').write_bytes(entries[1])
    (out / 'entry-3.cbor').write_bytes(entries[2])
    (out / 'entry-2.weak.cbor').write_bytes(weak)
    (out / 'genesis.othernet.bundle.cbor').write_bytes(bundle_of(other, [other_genesis]))
    facts.update({'network': network, 'otherNetwork': other, 'genesisEpoch': g, 'weakEntryId': entry_id(weak).hex(), 'realEntryId': entry_id(entries[1]).hex()})
    (out / 'negatives.json').write_text(json.dumps(facts, indent=2) + '\n')
    return facts


if __name__ == '__main__':
    # utbcbor.py negatives BUNDLE OUTDIR | genesis BUNDLE OUT | info BUNDLE
    cmd = sys.argv[1]
    data = Path(sys.argv[2]).read_bytes()
    if cmd == 'negatives':
        print(json.dumps(build_negatives(data, sys.argv[3])))
    elif cmd == 'genesis':
        network, entries = history(data)
        Path(sys.argv[3]).write_bytes(bundle_of(network, entries[:1]))
        print(entry_id(entries[0]).hex())
    elif cmd == 'info':
        network, entries = history(data)
        print(json.dumps({'network': network, 'epochs': [entry_fields(e)[2] for e in entries], 'ids': [entry_id(e).hex() for e in entries]}))
