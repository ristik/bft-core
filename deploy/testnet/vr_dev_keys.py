#!/usr/bin/env python3
"""The DEV keys of a validator-registry development generation (VT-14): one key per identity owner (payee = owner) and the five
FoundationMultisig signers, in the order the plan takes them (owners in id order, signers ascending). Shared by deploy/testnet/vr_genesis.py
--dev-fund and the paired devnet's VR lane (scripts/lib/vr-lib.sh), so both generate the same shapes.

Written into a NEW directory (mode 0700):
  keys.json     the private keys, created atomically at 0600 (O_EXCL): never a network file, never logged
  owners.json   [{owner, payee}] in id order (the `vr-genesis plan --owners` input)
  signers.txt   the five signer addresses, comma-separated, ascending (the `--governor-signers` input)

    python3 deploy/testnet/vr_dev_keys.py <new-dir> <owners>
"""
import json
import os
from pathlib import Path
import subprocess
import sys

SIGNERS = 5


def cast_new_key():
    """A fresh secp256k1 key from foundry's `cast wallet new --json` (both its old list and its new {data: [...]} shapes)."""
    doc = json.loads(subprocess.run(['cast', 'wallet', 'new', '--json'], check=True, text=True, capture_output=True).stdout)
    w = (doc['data'] if isinstance(doc, dict) else doc)[0]
    return {'address': w['address'].lower(), 'privateKey': w['private_key']}


def write_exclusive(path, text, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def write(directory, owners, new_key=cast_new_key):
    """Generates and writes the keys; returns {'owners': [...], 'signers': [...]} (addresses and keys). The directory must not exist."""
    if owners < 1:
        raise ValueError('at least one owner')
    d = Path(directory)
    d.mkdir(mode=0o700, parents=False)
    keys = {'owners': [new_key() for _ in range(owners)], 'signers': sorted((new_key() for _ in range(SIGNERS)), key=lambda k: k['address'])}
    addresses = [k['address'] for k in keys['owners'] + keys['signers']]
    if len(set(addresses)) != len(addresses):
        raise ValueError('a generated address repeats')
    write_exclusive(d / 'keys.json', json.dumps(keys, indent=1) + '\n', 0o600)
    write_exclusive(d / 'owners.json', json.dumps([{'owner': k['address'], 'payee': k['address']} for k in keys['owners']], indent=1) + '\n', 0o644)
    write_exclusive(d / 'signers.txt', ','.join(k['address'] for k in keys['signers']) + '\n', 0o644)
    return keys


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: vr_dev_keys.py <new-dir> <owners>')
    k = write(sys.argv[1], int(sys.argv[2]))
    print(f"vr: dev keys for {len(k['owners'])} owners and {len(k['signers'])} signers in {sys.argv[1]} (keys.json 0600)")
