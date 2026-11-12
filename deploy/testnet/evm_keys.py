#!/usr/bin/env python3
"""Ethereum keys with the standard library only (remote_joiner.py): the laptop joiner's owner, withdrawal and payee accounts are made INSIDE a container
of the laptop's docker VM, which has python3 (the rpc image) but no Foundry. keccak-256 and secp256k1 public-key derivation, nothing else: no signing
(the pinned ubft signs every transaction).

    python3 - wallet <dir>   (the script on stdin): writes <dir>/{owner,withdrawal,payee}.key (0x-hex, mode 0600) and prints {"owner": "0x..", ...}, addresses only
    python3 - identity <wallet dir> <root keys.json> <out> <rootNodeId> <evmNodeId> [--throwaway-evm]
                                                     the `pos-relayer tx join --joiner` file (mode 0600); --throwaway-evm adds a random evmKey for register and bond,
                                                     which never read it (admit is run without it: the signing authority holds the EVM key)
"""
import json
import os
import secrets
import sys

# --- keccak-256 (the original Keccak padding 0x01, not SHA3's 0x06) ---
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081,
       0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B,
       0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    msg = bytearray(data) + b'\x01'
    msg += b'\x00' * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        a = _f(a)
    out = b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))
    return out


# --- secp256k1 ---
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def public_point(k):
    if not 0 < k < N:
        raise ValueError('private key out of range')
    out, add = None, G
    while k:
        if k & 1:
            out = _add(out, add)
        add = _add(add, add)
        k >>= 1
    return out


def address(private_hex):
    x, y = public_point(int(private_hex.removeprefix('0x'), 16))
    digest = keccak256(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[12:].hex()
    upper = keccak256(digest.encode()).hex()   # EIP-55 checksum
    return '0x' + ''.join(c.upper() if int(upper[i], 16) >= 8 else c for i, c in enumerate(digest))


def new_key():
    while True:
        k = int.from_bytes(secrets.token_bytes(32), 'big')
        if 0 < k < N:
            return '0x' + k.to_bytes(32, 'big').hex()


def _write_secret(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)


def wallet(directory):
    """Three fresh accounts in `directory` (kept if they exist: a rerun of init is idempotent). Prints addresses only."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    out = {}
    for name in ('owner', 'withdrawal', 'payee'):
        path = os.path.join(directory, f'{name}.key')
        if not os.path.exists(path):
            _write_secret(path, new_key() + '\n')
        out[name] = address(open(path).read().strip())
    return out


def identity(wallet_dir, root_keys, out, root_node_id, evm_node_id, throwaway_evm=False, expiry=2 ** 62):
    """The joiner file of `pos-relayer tx join` (pos_join.joiner_file), assembled where the keys are; returns the public part."""
    keys = {name: open(os.path.join(wallet_dir, f'{name}.key')).read().strip() for name in ('owner', 'withdrawal', 'payee')}
    root_key = json.load(open(root_keys))['sigKey']['privateKey']
    body = {'ownerKey': keys['owner'], 'rootKey': root_key, 'withdrawal': address(keys['withdrawal']), 'payee': address(keys['payee']),
            'rootNodeId': root_node_id, 'evmNodeId': evm_node_id, 'expiry': expiry}
    if throwaway_evm:
        body['evmKey'] = new_key()
    if os.path.exists(out):
        os.unlink(out)
    _write_secret(out, json.dumps(body))
    return {'owner': address(keys['owner']), 'withdrawal': body['withdrawal'], 'payee': body['payee']}


def main(argv):
    if argv[:1] == ['wallet'] and len(argv) == 2:
        print(json.dumps(wallet(argv[1]), sort_keys=True))
    elif argv[:1] == ['identity'] and len(argv) in (6, 7):
        print(json.dumps(identity(*argv[1:6], throwaway_evm=argv[6:] == ['--throwaway-evm']), sort_keys=True))
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
