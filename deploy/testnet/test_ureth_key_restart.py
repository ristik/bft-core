#!/usr/bin/env python3
"""bft-core#1148, on Docker: the execution client keeps its devp2p identity across a restart, a recreate and an emptied data directory, and refuses to
start without its key. Opt-in (it starts containers): run as root on a Docker host, with

    URETH_KEY_IMAGE      the node image (an image ID: the package's node image, with unicity-reth)
    URETH_KEY_GENESIS    a generation's network/genesis.json (copied; public)
    URETH_KEY_COMPOSE    that generation's compose.yaml (read only: its ureth1 --unicity.* / --txpool.* bindings and --builder.gaslimit)

    sudo -E python3 -m unittest -v test_ureth_key_restart

The ureth service is the one generate.topology writes (one entity), in a Compose project of its own (vt08-ureth-key-<random>) on an internal network
of its own: it has no consensus client and no peers, it only starts and logs its enode. Nothing of the source generation is started, stopped or written.
"""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest

import generate
import ureth_key

ENODE = re.compile(r'enode://([0-9a-f]{128})@')
ANSI = re.compile(r'\x1b\[[0-9;]*m')
P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def public_key(secret_hex):
    """The uncompressed secp256k1 public key (x||y, 128 hex digits) of a node key: the enode's id."""
    def add(a, b):
        if a is None: return b
        if b is None: return a
        if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
        lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, P)) % P if a == b else ((b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
        x = (lam * lam - a[0] - b[0]) % P
        return x, (lam * (a[0] - x) - a[1]) % P
    k, r, q = int(secret_hex, 16), None, G
    while k:
        if k & 1: r = add(r, q)
        q, k = add(q, q), k >> 1
    return f'{r[0]:064x}{r[1]:064x}'


@unittest.skipUnless(all(os.environ.get(v) for v in ('URETH_KEY_IMAGE', 'URETH_KEY_GENESIS', 'URETH_KEY_COMPOSE')), 'opt-in: needs Docker and a node image')
class UrethKeyOnDocker(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='vt08-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.gen = self.tmp / 'gen'
        (self.gen / 'network').mkdir(parents=True)
        shutil.copy(os.environ['URETH_KEY_GENESIS'], self.gen / 'network' / 'genesis.json')
        source = json.loads(Path(os.environ['URETH_KEY_COMPOSE']).read_text())['services']['ureth1']['entrypoint']
        source = source[source.index('unicity-reth'):]
        bindings = source[source.index(generate.FEE) + 1:]   # the profile bindings generate.topology appends (ureth_flags)
        gas = source[source.index('--builder.gaslimit') + 1]
        images = {k: os.environ['URETH_KEY_IMAGE'] for k in ('node', 'rpc', 'guard', 'signer')}
        cfg = generate.topology(self.gen, 1, {'root': ['r1'], 'evm': ['e1']}, images, 'captcha', bindings, int(gas))
        self.project = 'vt08-ureth-key-' + secrets.token_hex(4)
        compose = {'name': self.project, 'services': {'ureth1': cfg['services']['ureth1']}, 'networks': {'validators': {'internal': True}}}
        (self.gen / 'compose.yaml').write_text(json.dumps(compose, indent=1))
        val = self.gen / 'validator1'
        for kind in ('ureth', 'jwt'):
            (val / kind).mkdir(parents=True)
        (val / 'jwt' / 'jwt.hex').write_text(secrets.token_hex(32) + '\n')
        self.key = ureth_key.create(val / ureth_key.DIR)
        for path in [self.gen, *self.gen.rglob('*')]:
            os.chown(path, 10001, 10001)
        self.addCleanup(self.compose, 'down', '-v', '--remove-orphans')

    def compose(self, *args, check=True):
        return subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), *args], capture_output=True, text=True, check=check)

    def container(self):
        return self.compose('ps', '-a', '-q', 'ureth1').stdout.strip()

    def logs(self, cid):
        run = subprocess.run(['docker', 'logs', cid], capture_output=True, text=True)
        return ANSI.sub('', run.stdout + run.stderr)

    def enodes(self, cid, at_least, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = ENODE.findall(self.logs(cid))
            if len(found) >= at_least:
                return found
            time.sleep(2)
        self.fail(f'ureth logged {len(ENODE.findall(self.logs(cid)))} enode(s), wanted {at_least}:\n' + self.logs(cid)[-3000:])

    def test_identity_survives_restart_recreate_and_an_emptied_datadir_and_a_lost_key_stops_it(self):
        want = public_key(self.key.read_text())
        evidence = {'expected_node_id': want}
        self.compose('up', '-d', 'ureth1')
        first = self.container()
        evidence['first_start'] = self.enodes(first, 1)[-1]
        time.sleep(5)
        per = len(ENODE.findall(self.logs(first)))   # enode lines one start logs
        self.compose('restart', 'ureth1')   # the same container, restarted
        self.assertEqual(self.container(), first)
        evidence['restart'] = self.enodes(first, 2 * per)[-1]
        self.compose('up', '-d', '--force-recreate', 'ureth1')   # a new container from the same compose (an upgrade recreates it like this)
        second = self.container()
        self.assertNotEqual(second, first)
        evidence['recreate'] = self.enodes(second, per)[-1]
        self.compose('stop', 'ureth1')   # a cold restore: the data directory emptied, the key directory untouched
        state = self.gen / 'validator1' / 'ureth'
        for path in state.iterdir():
            shutil.rmtree(path) if path.is_dir() else path.unlink()
        self.compose('up', '-d', 'ureth1')
        evidence['emptied_datadir'] = self.enodes(second, 2 * per)[-1]
        for stage in ('first_start', 'restart', 'recreate', 'emptied_datadir'):
            self.assertEqual(evidence[stage], want, stage)
        self.assertFalse((state / 'discovery-secret').exists(), 'reth made no key of its own in the data directory')
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.key.read_text().strip(), self.key.read_text())
        # the key lost: ureth refuses to start (a restart loop with the message), and never comes up under a new identity
        self.compose('stop', 'ureth1')
        before = len(ENODE.findall(self.logs(second)))
        self.key.unlink()
        self.compose('up', '-d', 'ureth1')
        time.sleep(15)
        logs = self.logs(self.container())
        self.assertIn('refusing to start under a new identity', logs)
        self.assertEqual(len(ENODE.findall(logs)), before, 'no new start reached the network')
        inspect = json.loads(subprocess.run(['docker', 'inspect', self.container()], capture_output=True, text=True, check=True).stdout)[0]['State']
        self.assertEqual(inspect['ExitCode'], 78, inspect)
        self.assertFalse((state / 'discovery-secret').exists())
        self.assertFalse(self.key.exists())
        evidence['missing_key'] = {'exit_code': inspect['ExitCode'], 'restarting': inspect.get('Restarting'),
                                   'message': next(l for l in logs.splitlines() if 'refusing' in l)}
        print(json.dumps(evidence, indent=1))


if __name__ == '__main__':
    unittest.main()
