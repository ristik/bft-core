"""Root signing keys are specific to one root history (#1297, astra's review: D5 section 2.1).

Post-term evidence charges a quorum seal from its signed bytes alone. Those bytes bind the network N but not the root genesis, so a seal one root key
signed in another root history that shares N would be chargeable here. A validator must therefore sign every root history (every reset generation)
with a fresh consensus key, including when it joins later and when it rotates. This module holds the guard:

- a generation's manifest records its genesis root signing keys (`root_signing_keys`: node id, compressed key, key hash);
- the retired inventory is cumulative and comes from the prior generation's signed history: `ubft trust-base utb-verify --keys-out` writes every
  epoch's root signing keys of the verified UTB history (so the keys that joined or rotated after genesis are in it), and the prior generation's
  own published list carries everything retired before it;
- `generate.py` refuses to run without that history (`--prior-generation <keys file>`) unless `--first-generation` says there is none, and
  publishes the union as `network/retired-root-keys.json`;
- generation, joiner, enrollment and rotation tooling refuse a root key whose hash is in that list (`check_fresh`).

The key hash is keccak256 of the 33-byte compressed key: the root key hash custody and the validator registry store. Stdlib only.
"""
import json
from pathlib import Path
import re

from evm_keys import keccak256

FORMAT = 'unicity-retired-root-keys/1'
HISTORY_FORMAT = 'unicity-utb-root-keys/1'   # `ubft trust-base utb-verify --keys-out`
FILE = 'retired-root-keys.json'   # under the generation's network/ directory


class RetiredKeyError(Exception):
    pass


def key_bytes(key):
    """The 33-byte compressed key from hex (with or without 0x) or bytes."""
    raw = bytes.fromhex(key[2:] if key.startswith('0x') else key) if isinstance(key, str) else bytes(key)
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError(f'not a compressed secp256k1 key: {raw.hex()[:20]}...')
    return raw


def key_hash(key):
    return '0x' + keccak256(key_bytes(key)).hex()


def node_info_key(path):
    """The signing key a root node's node-info.json names."""
    return json.loads(Path(path).read_text())['sigKey']


def manifest_entries(node_ids, keys):
    """The manifest's `root_signing_keys`: one entry per genesis validator, in validator order."""
    return [{'validator': i, 'node_id': n, 'key': '0x' + key_bytes(k).hex(), 'key_hash': key_hash(k)} for i, (n, k) in enumerate(zip(node_ids, keys), 1)]


def read_list_text(text, name):
    doc = json.loads(text)
    if doc.get('format') != FORMAT or not isinstance(doc.get('keyHashes'), list):
        raise RetiredKeyError(f'{name}: not a {FORMAT} list')
    return {h.lower() for h in doc['keyHashes']}


def read_list(path):
    return read_list_text(Path(path).read_text(), path)


def is_history(source):
    """Whether `source` is a verified UTB history keys file (the authoritative inventory of the keys that signed for a root history)."""
    p = Path(source)
    if not p.is_file():
        return False
    try:
        return json.loads(p.read_text()).get('format') == HISTORY_FORMAT
    except (ValueError, AttributeError):
        return False


def history_of(path):
    """(genesisId, last epoch) of a verified UTB history keys file."""
    doc = json.loads(Path(path).read_text())
    epochs = [int(e['epoch']) for e in doc.get('epochs') or []]
    return (doc.get('genesisId') or '').lower(), max(epochs) if epochs else 0


def generation_epoch(generation):
    """The newest root epoch a generation directory holds a trust base for: network/trust-base.json is epoch 1, every installed handoff
    writes network/handoff/trust-base-epoch<N>.json."""
    net = Path(generation) / 'network'
    found = [int(m.group(1)) for f in (net / 'handoff').glob('trust-base-epoch*.json') if (m := re.fullmatch(r'trust-base-epoch(\d+)\.json', f.name))]
    return max(found + [1])


def generation_pin(generation):
    """The trusted root-genesis pin of a generation: its network/utb-genesis.id, else its manifest's utb.genesis_id; None when neither names one."""
    gen = Path(generation)
    pin_file = gen / 'network' / 'utb-genesis.id'
    pin = pin_file.read_text().strip().lower() if pin_file.is_file() else ''
    if not pin and (gen / 'manifest.json').is_file():
        pin = str((json.loads((gen / 'manifest.json').read_text()).get('utb') or {}).get('genesis_id') or '').strip().lower()
    return pin if re.fullmatch(r'0x[0-9a-f]{64}', pin) else None


def bind_to_generation(histories, generation):
    """Refuse an inventory that is not the generation's own complete history: no trusted root-genesis pin to bind it to, a history of another
    root genesis (a stale export of an earlier reset), or one that ends before the generation's newest installed epoch (a truncated
    `utb-verify --url` read). Returns the error text, or None."""
    gen = Path(generation)
    pin = generation_pin(gen)
    if pin is None:
        return (f'{gen.name} names no root-genesis pin (network/utb-genesis.id, or the manifest\'s utb.genesis_id): the history cannot be bound '
                f'to it; nothing is deleted')
    want = generation_epoch(gen)
    for h in histories:
        gid, last = history_of(h)
        if gid == pin and last >= want:
            return None
    return (f'no --prior-generation history is {gen.name}\'s own complete one: it needs genesisId {pin} and epochs through {want} '
            f'(the newest trust base the generation holds); export it again from the running generation')


def load(source):
    """The retired key hashes a prior source names: a verified UTB history keys file (every epoch's root signing keys), a generation directory
    (its manifest's root keys and its own published list), a manifest.json, or a published list file. A source that names no root key is refused:
    a guard fed an unreadable or keyless manifest would pass everything."""
    p = Path(source)
    if p.is_dir():
        out = load(p / 'manifest.json')
        if (p / 'network' / FILE).is_file():
            out |= read_list(p / 'network' / FILE)
        return out
    doc = json.loads(p.read_text())
    if doc.get('format') == FORMAT:
        return read_list(p)
    if doc.get('format') == HISTORY_FORMAT:
        keys = {key_hash(k) for e in doc.get('epochs') or [] for k in e.get('keys') or []}
        if not keys:
            raise RetiredKeyError(f'{source}: the UTB history names no root keys')
        return keys
    entries = doc.get('root_signing_keys')
    if not entries:
        raise RetiredKeyError(f'{source}: the manifest records no root signing keys (made before #1297): pass its retired-root-keys list or its keys instead')
    out = {key_hash(e['key']) for e in entries}
    lst = p.parent / 'network' / FILE
    if lst.is_file():
        out |= read_list(lst)
    return out


def write(network_dir, hashes):
    Path(network_dir, FILE).write_text(json.dumps({'format': FORMAT, 'keyHashes': sorted(hashes)}, indent=1) + '\n')


def published(generation):
    """The retired key hashes a generation publishes (empty for a generation made before the list existed)."""
    p = Path(generation) / 'network' / FILE
    return read_list(p) if p.is_file() else set()


def check_fresh(keys, retired, what):
    """Refuse any root key whose hash is in `retired`."""
    bad = sorted(key_hash(k) for k in keys if key_hash(k) in retired)
    if bad:
        raise RetiredKeyError(f'{what}: root signing key(s) {", ".join(bad)} belong to an earlier root history (retired-root-keys) or to '
                              'another validator; a root key is specific to one root history and one validator: make a fresh key (D5 section 2.1)')


def check_generation(generation, key, what):
    """A joiner's, enrollee's or rotated root key against the generation's published list and its genesis validators' keys."""
    gen = Path(generation)
    retired = published(gen)
    manifest = gen / 'manifest.json'
    if manifest.is_file():
        retired |= {key_hash(e['key']) for e in json.loads(manifest.read_text()).get('root_signing_keys') or []}
    check_fresh([key], retired, what)
