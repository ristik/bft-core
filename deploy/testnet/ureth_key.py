#!/usr/bin/env python3
"""The execution client's (ureth's) devp2p node key, kept across restarts, recreates and upgrades (bft-core#1148).

ureth holds one key of its own: the secp256k1 devp2p node key, which is its RLPx peer id (the enode the transaction gossip's trusted peers name). Left to
itself reth makes it on its first start as <datadir>/discovery-secret, mode 0644, and makes a NEW one, silently, whenever that file is missing: after a
cold restore or a joiner restore empties the data directory, the node comes back under another identity. So the package makes the key once, when the
entity's directories are made (generate.py, joiner.py prepare, remote_joiner.py init), in the entity's own directory validator<N>/ureth-key/ (0700),
file p2p-secret (0600, the service user's), outside the data directory, and mounts it read-only into ureth<N> only. ureth reads it with
--p2p-secret-key; it cannot rewrite it, and a preflight in the service's entrypoint refuses to start when it is missing or empty, so a lost key is a
visible restart loop with a clear message, never a new identity. The key is the execution client's alone: no other service mounts it, and it is
not the root's, the shard node's or the signing authority's key.

    python3 ureth_key.py create DIR    make DIR/p2p-secret (DIR is created 0700 if absent); refuses an existing key. Standard library only: the
                                       remote joiner runs it inside a container on the laptop's VM (the key never leaves that volume).
"""
import os
from pathlib import Path
import secrets
import sys

DIR = 'ureth-key'                  # validator<N>/<DIR> on the host
FILE = 'p2p-secret'
MOUNT = '/ureth-key'               # inside ureth<N>, read-only
PATH = f'{MOUNT}/{FILE}'
# secp256k1's group order: a node key is a scalar in [1, N-1]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

PREFLIGHT = (f'if [ ! -s {PATH} ]; then echo "ureth: its persistent devp2p node key {PATH} (validator<N>/{DIR}/{FILE} of the generation) is missing or empty;'
             ' refusing to start under a new identity (bft-core#1148). Restore that file from the generation\'s backup; it is never regenerated." >&2;'
             ' exit 78; fi; exec "$@"')


def mount(i):
    """The read-only mount of validator<i>'s key directory into its ureth."""
    return f'./validator{i}/{DIR}:{MOUNT}:ro'


def entrypoint(command):
    """`command` (unicity-reth node ...) behind the preflight: sh -c PREFLIGHT ureth <command...>. The arguments stay a plain list after the 4th word."""
    return ['/bin/sh', '-c', PREFLIGHT, 'ureth', *command]


def new_secret():
    """A fresh node key: 64 lowercase hex digits and no newline (reth parses the whole file as the key)."""
    return f'{1 + secrets.randbelow(N - 1):064x}'


def create(directory, uid=None):
    """Make `directory`/p2p-secret once: the directory 0700, the file 0600 (whatever the umask), owned by `uid` when given. An existing key is refused,
    never replaced: the key is made exactly once per entity."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / FILE
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, new_secret().encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    if uid is not None:
        for p in (directory, path):
            os.chown(p, uid, uid)
    return path


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'create':
        sys.exit('usage: ureth_key.py create DIR')
    print(create(sys.argv[2]))
