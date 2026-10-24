#!/usr/bin/env python3
"""Container-package rehearsal of a generated testnet (TN-1: #432, #433, #434, #435).

Drives an already generated and enrolled generation (generate.py ran, the authorities are live) through the checks the package README lists as pending, and
writes the evidence directory it asks for. The same script runs on a GitHub runner (.github/workflows/testnet-rehearsal.yml) and on the real host, so the
runner rehearsal is evidence of the package and never of the host: it proves nothing about capacity, DNS/TLS, real hCaptcha or a second operator.

No third-party service is contacted. The faucet SIGNER is never started (it verifies hCaptcha itself); only the faucet guard runs, and only the requests it
refuses before the signer are sent. A real dispense is host-only. Needs docker compose and foundry's `cast`; run as the user that may read the generation
(host root on Linux, the files belong to UID 10001).
"""
import argparse
import datetime
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import handoff
import handoff_ops
import operator_rpc
import pos_join
import pos_owner
import pos_sample

PUBLIC_RPC = '127.0.0.1:8545'
FAUCET = '127.0.0.1:8088'
PROXY_IPS = ('203.0.113.', '198.51.100.')   # documentation ranges: the client addresses the nginx in front would have set in X-Forwarded-For


class Failure(Exception):
    pass


class Rehearsal:
    def __init__(self, generation, evidence, cast):
        self.gen, self.evidence, self.cast = Path(generation).resolve(), Path(evidence), cast
        self.adopt(self.gen)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.log = (self.evidence / 'rehearsal.log').open('a')
        self.results = []
        self.pods = ()
        self.reset_args = {}
        self.ubft = None
        self.target = 2   # the root epoch the handoff being driven installs (pos-handoff-2 drives the next one, 3)
        self.committed_target = None   # the Abort target of the handoff pos-propose committed (pos-too-late)

    def evh(self):
        """The evidence directory of the handoff being driven (the second handoff keeps its own, the first one's files have the same names)."""
        path = self.evidence / ('handoff' if self.target == 2 else f'handoff-epoch{self.target}')
        path.mkdir(exist_ok=True)
        return path

    def previous_trust_base(self):
        """The trust base of the epoch the handoff leaves: the genesis one, then the one the previous handoff installed."""
        return self.gen / 'network' / ('trust-base.json' if self.target == 2 else f'handoff/trust-base-epoch{self.target - 1}.json')

    def adopt(self, generation):
        """Work on this generation from now on (after a restore or a reset it is another directory with, after a reset, another network identity)."""
        self.gen = Path(generation).resolve()
        self.manifest = json.loads((self.gen / 'manifest.json').read_text())
        self.n = self.manifest['validators']
        self.chain_id, self.genesis = self.manifest['chain_id'], self.manifest['genesis_hash'].lower()

    # --- recording -------------------------------------------------------------------------------------------------------------
    def say(self, text):
        line = f'{datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%SZ")} {text}'
        print(line, flush=True)
        self.log.write(line + '\n')
        self.log.flush()

    def expect(self, condition, what, detail=''):
        if not condition:
            raise Failure(f'{what}' + (f': {detail}' if detail else ''))
        self.say(f'  ok   {what}' + (f' ({detail})' if detail else ''))

    def stage(self, name, fn):
        self.say(f'== {name}')
        try:
            fn()
        except Exception as error:   # a failed stage is recorded as failed, then the run stops: later stages depend on it
            self.say(f'FAIL {name}: {error}')
            self.results.append((name, 'FAIL', str(error)))
            raise
        self.say(f'PASS {name}')
        self.results.append((name, 'PASS', ''))

    # --- docker and RPC --------------------------------------------------------------------------------------------------------
    def compose(self, *args, check=True):
        return subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), *args], check=check, text=True, capture_output=True).stdout

    def services(self):
        return self.compose('config', '--services').split()

    def inner(self, url, method, params=()):
        return self.inner_reply(url, method, params).get('result')

    def inner_reply(self, url, method, params=()):
        """JSON-RPC to a validator's execution client from inside the validator network (the rpc container has python, ureth has no curl)."""
        code = ('import json,sys,urllib.request as u;'
                'r=u.Request(sys.argv[1],json.dumps({"jsonrpc":"2.0","id":1,"method":sys.argv[2],"params":json.loads(sys.argv[3])}).encode(),{"Content-Type":"application/json"});'
                'print(u.urlopen(r,timeout=10).read().decode())')
        out = self.compose('exec', '-T', 'rpc', 'python3', '-c', code, url, method, json.dumps(list(params)))
        return json.loads(out)

    def ureth(self, i, method, params=()):
        return self.inner(f'http://ureth{i}:8545', method, params)

    @staticmethod
    def http(host, method, path, body=None, headers=None, timeout=15):
        """(status, text). A refusal is a status, not an exception; a connection the server closes first is reported as status 0 with the reason."""
        conn = http.client.HTTPConnection(host, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read().decode(errors='replace')
        except (ConnectionError, http.client.HTTPException, OSError) as error:
            return 0, type(error).__name__
        finally:
            conn.close()

    def rpc(self, body, ip, host=PUBLIC_RPC):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        return self.http(host, 'POST', '/', data, {'Content-Type': 'application/json', 'X-Forwarded-For': ip})

    def call(self, method, params=(), ip=PROXY_IPS[0] + '10'):
        for attempt in range(6):
            status, text = self.rpc({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}, ip)
            if status != 429 or attempt == 5:
                break
            self.say(f'  {method}: 429 from the per-client limit (10 requests/s), waiting 1 s ({attempt + 1}/5)')   # the limit is the package's; a driver that bursts waits for it
            time.sleep(1)
        if status != 200:
            raise Failure(f'{method} through the public gateway: {status} {text}')
        return json.loads(text).get('result')

    def wait(self, what, probe, seconds):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            try:
                last = probe()
                if last:
                    return last
            except Exception as error:   # services start in any order; a probe that raises is "not yet"
                last = error
            time.sleep(3)
        raise Failure(f'{what}: not within {seconds} s (last: {last})')

    def cast_run(self, *args):
        return subprocess.run([self.cast, *args], check=True, text=True, capture_output=True).stdout.strip()

    # --- stages ----------------------------------------------------------------------------------------------------------------
    def up(self):
        self.compose('config', '--quiet')
        # every service except the signing authorities (live since generation, never restarted) and the faucet signer (it verifies hCaptcha itself and
        # is the only service that talks to a third party: the host starts it, the rehearsal does not); the faucet guard has no dependency on it
        start = [s for s in self.services() if not s.startswith('authority') and s != 'signer']
        self.compose('up', '-d', '--no-deps', *start)
        def missing():
            running = set(self.compose('ps', '--services', '--status', 'running').split())
            return sorted(set(start) - running)
        try:
            self.wait('every started service is running', lambda: not missing(), 120)
        except Failure:
            self.say('  not running: ' + ' '.join(missing()))
            self.say(self.compose('ps', '-a', check=False))
            for name in missing()[:4]:
                self.say(f'--- last log of {name}\n' + self.compose('logs', '--no-color', '--tail', '25', name, check=False))
            raise
        running = set(self.compose('ps', '--services', '--status', 'running').split())
        self.expect(True, 'every non-authority service except the signer is running', f'{len(start)} services')
        self.expect('signer' not in running, 'the faucet signer is not running (no third-party call in the rehearsal)')
        head = self.wait('the public gateway reports a head (every validator identity checked by the relay)',
                         lambda: self.http(PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 600)
        self.expect(head, 'the public gateway is healthy')

    def identity(self):
        for i in range(1, self.n + 1):
            chain = int(self.ureth(i, 'eth_chainId'), 16)
            genesis = self.ureth(i, 'eth_getBlockByNumber', ['0x0', False])['hash'].lower()
            self.expect(chain == self.chain_id and genesis == self.genesis, f'validator {i} reports the manifest chain id and block-zero hash', genesis)
        self.expect(int(self.call('eth_chainId'), 16) == self.chain_id, 'the public gateway reports the manifest chain id')

    def first_tx(self):
        secrets = self.gen / 'faucet-secrets'
        to = '0x' + '11' * 20   # an ordinary account (0x..01 is the ecrecover precompile)
        before = int(self.call('eth_getBalance', [to, 'latest']), 16)
        receipt = json.loads(self.send_via_gateway(secrets, to))
        self.expect(receipt['status'] == '0x1', 'the funded first transaction succeeded', json.dumps(receipt)[:600])
        self.expect(int(self.call('eth_getBalance', [to, 'latest']), 16) == before + 1, 'the recipient balance grew by the transferred wei')
        for i in range(1, self.n + 1):
            r = self.wait(f'validator {i} has the receipt', lambda i=i: self.ureth(i, 'eth_getTransactionReceipt', [receipt['transactionHash']]), 120)
            self.expect(r['blockHash'] == receipt['blockHash'], f'validator {i} has it in the same block', r['blockHash'])
        self.tx = receipt

    def raw_tx(self, to, nonce, price, value=1):
        secrets = self.gen / 'faucet-secrets'
        return self.cast_run('mktx', '--keystore', str(secrets / 'keystore.json'), '--password-file', str(secrets / 'password'), '--legacy', '--nonce', str(nonce),
                             '--gas-price', str(price), '--gas-limit', '21000', '--chain', str(self.chain_id), '--value', str(value), to)

    def send_via_gateway(self, secrets, to):
        # cast talks to the public gateway: the gateway only accepts the allow-listed methods, and the generated proxy peer is trusted only with X-Forwarded-For,
        # which cast cannot set: sign offline, then submit through the gateway ourselves
        sender = self.manifest['faucet_address']
        nonce = int(self.call('eth_getTransactionCount', [sender, 'latest']), 16)
        price = int(self.call('eth_gasPrice'), 16)
        sent = self.call('eth_sendRawTransaction', [self.raw_tx(to, nonce, price)])
        self.say(f'  submitted {sent} (nonce {nonce}, gas price {price})')
        receipt = self.wait('the transaction is mined', lambda: self.call('eth_getTransactionReceipt', [sent]), 180)
        return json.dumps(receipt)

    def gateway_limits(self):
        a, b = PROXY_IPS[0] + '20', PROXY_IPS[1] + '20'
        ok = {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []}
        s, _ = self.rpc(ok, a)
        self.expect(s == 200, 'an allowed method is served')
        for name, method in (('signing', 'eth_sign'), ('admin', 'admin_peers'), ('engine', 'engine_newPayloadV3'), ('debug', 'debug_traceTransaction'), ('accounts', 'eth_accounts')):
            s, _ = self.rpc(dict(ok, method=method), b)
            self.expect(s == 400, f'a {name} method ({method}) is refused', f'status {s}')
        s, _ = self.rpc([ok], b)
        self.expect(s == 400, 'a batch is refused', f'status {s}')
        s, _ = self.rpc(b'{not json', b)
        self.expect(s == 400, 'malformed JSON is refused', f'status {s}')
        s, text = self.rpc(json.dumps(dict(ok, params=['x' * 20000])).encode(), b)
        self.expect(s in (400, 0), 'a body over 16 KiB (an ordinary method) is refused', f'status {s} {text[:40] if s == 0 else ""}')
        s, _ = self.http(PUBLIC_RPC, 'POST', '/other', json.dumps(ok).encode(), {'X-Forwarded-For': b})
        self.expect(s == 400, 'another path is refused', f'status {s}')
        s, _ = self.http(PUBLIC_RPC, 'POST', '/', json.dumps(ok).encode())
        self.expect(s == 400, 'a request without the proxy-set client address is refused', f'status {s}')
        burst = PROXY_IPS[0] + '30'
        statuses = [self.rpc(ok, burst)[0] for _ in range(40)]
        self.expect(429 in statuses, 'a burst from one client address is rate limited (10/s per address)', f'{statuses.count(200)}x200 {statuses.count(429)}x429')
        s, _ = self.rpc(ok, PROXY_IPS[1] + '31')
        self.expect(s == 200, 'ordinary requests from other clients are still served during the burst window')
        time.sleep(1.2)
        s, _ = self.rpc(ok, burst)
        self.expect(s == 200, 'the limited client is served again after the window')

    def faucet_guard(self):
        self.compose('up', '-d', '--no-deps', 'faucet')
        ip = {'X-Forwarded-For': PROXY_IPS[0] + '40', 'Content-Type': 'application/json'}
        self.wait('the faucet guard answers', lambda: self.http(FAUCET, 'GET', '/api/network')[0] == 200, 120)
        s, text = self.http(FAUCET, 'GET', '/api/network')
        pin = json.loads(text)
        self.expect(pin['chain_id'] == self.chain_id and pin['genesis_hash'].lower() == self.genesis, 'the faucet publishes the manifest network pin')

        def claim(body, headers=ip):
            return self.http(FAUCET, 'POST', '/api/claim', body if isinstance(body, bytes) else json.dumps(body).encode(), headers)
        good = {'address': '0x' + '11' * 20, 'chain_id': self.chain_id, 'genesis_hash': self.genesis}
        for what, body in (('an address that is not hex', dict(good, address='0xnot-an-address')), ('a short address', dict(good, address='0x1234')),
                           ('the zero address', dict(good, address='0x' + '00' * 20)), ('a missing address', {'chain_id': self.chain_id})):
            s, _ = claim(body)
            self.expect(s == 400, f'{what} is refused', f'status {s}')
        s, _ = claim(b'{bad json')
        self.expect(s == 400, 'malformed JSON is refused', f'status {s}')
        s, _ = claim(json.dumps(dict(good, pad='x' * 4096)).encode())
        self.expect(s in (400, 0), 'a body over 2 KiB is refused', f'status {s}')
        s, _ = claim(dict(good, chain_id=self.chain_id + 1))
        self.expect(s == 409, 'a wallet on another chain id gets the wrong-network answer', f'status {s}')
        s, _ = claim(dict(good, genesis_hash='0x' + '22' * 32))
        self.expect(s == 409, 'a wallet pinned to another (reset) genesis gets the wrong-network answer', f'status {s}')
        s, text = claim(good)
        self.expect(s == 400 and 'hCaptcha' in text, 'a claim without a captcha token is refused before any reservation or signer call', f'status {s}')
        running = set(self.compose('ps', '--services', '--status', 'running').split())
        self.expect('signer' not in running, 'the signer was never started: no request reached a third party')
        self.say('  note the duplicate/rate-limited claim (one per address and IP per 24 h) needs a request that passes the captcha: host-only')

    def load(self):
        """Sustained load at the gateway's limits (loadgen.py, the tool the host runs too): 20 signed transfers a second for 20 s from four client addresses (5/s
        each, under the 10/s per-address limit), every accepted transfer must be mined successfully and every validator must agree on the sender's nonce after."""
        secrets, summary = self.gen / 'faucet-secrets', self.evidence / 'load.json'
        out = subprocess.run([sys.executable, str(Path(__file__).with_name('loadgen.py')), '--rpc', 'http://' + PUBLIC_RPC + '/', '--chain-id', str(self.chain_id),
                              '--sender', self.manifest['faucet_address'], '--keystore', str(secrets / 'keystore.json'), '--password-file', str(secrets / 'password'),
                              '--cast', self.cast, '--rate', '20', '--duration', '20', '--ips', '4', '--min-accepted', '350', '--out', str(summary)],
                             text=True, capture_output=True)
        self.say(out.stdout.strip() or out.stderr.strip())
        self.expect(out.returncode == 0, 'the generated load was accepted and every accepted transfer mined successfully', (json.loads(summary.read_text()) if summary.exists() else {}).get('problems', out.stderr[-300:]))
        sender = self.manifest['faucet_address']
        nonces = {i: self.ureth(i, 'eth_getTransactionCount', [sender, 'latest']) for i in range(1, self.n + 1)}
        self.wait('every validator has the same sender nonce', lambda: len({self.ureth(i, 'eth_getTransactionCount', [sender, 'latest']) for i in range(1, self.n + 1)}) == 1, 120)
        self.expect(True, 'every validator agrees on the sender nonce after the load', str(nonces))

    # --- proof-of-stake profile (a generation made with generate.py --pos; TN-S #430, P8-TEST #437) -------------------------------
    REGISTRY = '0xff00000000000000000000000000000000000002'

    def view(self, to, signature, *args):
        """A contract view through the public gateway: eth_call with cast-encoded data, decoded by cast. `signature` is cast's 'name(inputs)(outputs)'."""
        return [int(line.split()[0]) for line in self.view_text(to, signature, *args).splitlines()]

    def view_text(self, to, signature, *args):
        function = signature.split(')(')[0] + ')'
        data = self.cast_run('calldata', function, *args)
        raw = self.call('eth_call', [{'to': to, 'data': data}, 'latest'])
        return self.cast_run('abi-decode', signature, raw)

    def pos_smoke(self):
        """OPERATOR.md 5a's smoke, run: the containers started on the PoS genesis, the contracts are there, the election clock ticks and the custody has applied every
        root record. The first start of the packaged PoS genesis (#587's open item); it says nothing about a handoff (that is a later stage)."""
        pos = self.manifest.get('pos')
        self.expect(bool(pos), 'the manifest carries a pos block (this generation was made with --pos)')
        net = self.gen / 'network'
        self.expect((net / 'pos-genesis-assignment.txt').read_text().strip() == pos['genesis_assignment'], 'the shipped genesis assignment id is the manifest one', pos['genesis_assignment'])
        deployment = json.loads((net / 'pos-deployment.json').read_text())
        for name, address in (('registry', self.REGISTRY), ('custody', deployment['custody']), ('election', deployment['election'])):
            code = self.call('eth_getCode', [address, 'latest'])
            self.expect(len(code) > 100, f'the {name} contract has code at its genesis address', f'{address} {(len(code) - 2) // 2} bytes')
        first = self.view(self.REGISTRY, 'progress()(uint64)')[0]
        self.say(f'  registry progress {first}')
        later = self.wait('the election clock rises (the registry progress)', lambda: (lambda v: v if v > first else None)(self.view(self.REGISTRY, 'progress()(uint64)')[0]), 240)
        self.expect(later > first, 'the registry progress rises on the running chain', f'{first} -> {later}')
        self.say('  election thresholds (rounds, seconds): ' + ' '.join(map(str, self.view(deployment['election'], 'thresholds()(uint256,uint256)'))))
        def applied():
            count = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == self.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None
        self.expect(self.wait('the custody has applied every root record', lambda: applied() is not None, 240), 'recordCursor equals recordCount', str(applied()))
        names = [f'{role}{i}' for i in range(1, self.n + 1) for role in ('root', 'shard')]
        logs = self.compose('logs', '--no-color', *names, check=False)
        bad = [line for line in logs.splitlines() if 'AssignmentNotActive' in line or 'revert' in line.lower()]
        self.expect(not bad, 'no revert or AssignmentNotActive in any root or shard log', f'{len(bad)} lines' + (': ' + bad[0][:200] if bad else ''))

    def faucet_send(self, to, wei):
        """A value transfer from the faucet account through the public gateway (it is the only funded account: the PoS owners hold nothing at genesis)."""
        sender = self.manifest['faucet_address']
        nonce = int(self.call('eth_getTransactionCount', [sender, 'latest']), 16)
        sent = self.call('eth_sendRawTransaction', [self.raw_tx(to, nonce, int(self.call('eth_gasPrice'), 16), wei)])
        receipt = self.wait(f'the funding of {to} is mined', lambda: self.call('eth_getTransactionReceipt', [sent]), 180)
        self.expect(receipt['status'] == '0x1', f'{wei} wei reach {to}', sent)

    def balance(self, address):
        return int(self.call('eth_getBalance', [address, 'latest']), 16)

    def node_run(self, args, mounts=()):
        """`ubft` (the node image) in a one-shot container on the validators network, with the limits of the package's own services: read-only, no capabilities,
        bounded, uid 10001. `mounts` are 'host:container[:ro]' volumes. Returns the finished process (text stdout and stderr)."""
        compose = json.loads((self.gen / 'compose.yaml').read_text())
        network = subprocess.run(['docker', 'network', 'ls', '-q', '--filter', f'label=com.docker.compose.project={compose["name"]}',
                                  '--filter', 'label=com.docker.compose.network=validators'], check=True, text=True, capture_output=True).stdout.split()
        self.expect(len(network) == 1, 'the generation has one validators network', str(network))
        command = ['docker', 'run', '--rm', '--network', network[0], '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--memory', '256m', '--pids-limit', '128', '--tmpfs', '/tmp', '-e', 'HOME=/tmp']
        for mount in mounts:
            command += ['-v', mount]
        return subprocess.run(command + [compose['services']['root1']['image'], *args], text=True, capture_output=True)

    def relayer(self, key_file, *args, joiner=False, mounts=()):
        """`ubft pos-relayer tx ...` in a one-shot container (node_run): the public gateway has no X-Forwarded-For from a host client and the relayer sends each
        transaction to every validator (their pools do not gossip), so it talks to the execution clients directly. The key is copied to a directory only uid 10001
        can read, mounted read-only, and removed afterwards. The relayer's own output is returned: (exit status, stderr). With `joiner` the staged file is a `join`
        identity file instead of a sender key; `mounts` are further volumes."""
        staging = Path(tempfile.mkdtemp(prefix='tn-relayer-key-'))
        try:
            key = staging / 'key'
            key.write_text(Path(key_file).read_text())
            for path, mode in ((key, 0o400), (staging, 0o500)):
                os.chown(path, 10001, 10001)
                os.chmod(path, mode)
            urls = ','.join(f'http://ureth{i}:8545' for i in range(1, self.n + 1))
            run = self.node_run(['pos-relayer', 'tx', *args, '--eth-rpc', urls, '--pos-deployment', '/deployment.json', *(('--joiner',) if joiner else ('--sender-key',)), '/key/key'],
                                [f'{staging}:/key:ro', f'{self.gen / "network" / "pos-deployment.json"}:/deployment.json:ro', *mounts])
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        self.say('  relayer ' + ' '.join(args) + f': exit {run.returncode}: ' + ' | '.join(run.stderr.strip().splitlines()[-4:]))
        return run.returncode, run.stderr

    def pos_rewards(self):
        """The owner keys the ceremony generated, used: an owner and a payee funded from the faucet account, the reward pool funded by the relayer (its balance
        rises by exactly the funding), `reward settle` run against a chain with no root record yet (it must find nothing to close and say so), and a claim by a
        payee with no credit (nothing may leave the pool). Credits, a paid claim and an owner's custody calls (top-up, exit, withdrawal) need root records or an
        election and are later stages."""
        pos = self.manifest.get('pos')
        self.expect(bool(pos), 'the manifest carries a pos block (this generation was made with --pos)')
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        pool = deployment['rewardPool']
        self.expect(len(self.call('eth_getCode', [pool, 'latest'])) > 100, 'the reward pool has code at its genesis address', pool)
        identity = json.loads((self.gen / 'network' / 'pos-plan.json').read_text())['identities'][0]
        keys = self.gen / pos['owner_keys'] / f'identity-{identity["stakingId"]}'
        for role in ('owner', 'payee'):
            self.expect(self.balance(identity[role]) == 0, f'the {role} of identity {identity["stakingId"]} holds nothing at genesis', identity[role])
            self.faucet_send(identity[role], 10 ** 18)
        funding = 10 ** 15
        before = self.balance(pool)
        self.say(f'  reward pool balance {before}')
        status, out = self.relayer(keys / 'owner.key', 'reward', 'fund', '--value-wei', str(funding))
        self.expect(status == 0, 'reward fund with the owner key succeeds', out.strip()[-300:])
        after = self.wait('the pool balance reflects the funding', lambda: (lambda b: b if b != before else None)(self.balance(pool)), 120)
        self.expect(after == before + funding, 'the pool balance rose by exactly the funding', f'{before} + {funding} = {after}')
        status, out = self.relayer(keys / 'owner.key', 'reward', 'settle', '--max-steps', '4')
        self.expect(status == 0 and 'reward pool idle after' in out, 'reward settle runs to the end of what the chain has (nothing to close, with no root record) and says so', out.strip()[-300:])
        self.expect(self.balance(pool) == after, 'settle moved nothing out of the pool')
        recipient = '0x' + '77' * 20
        status, out = self.relayer(keys / 'payee.key', 'reward', 'claim', '--amount-wei', '1', '--to', recipient)
        self.say(f'  claim without credit: exit {status}')
        self.expect(self.balance(recipient) == 0 and self.balance(pool) == after, 'a claim by a payee without credit moves nothing out of the pool', f'recipient {self.balance(recipient)}, pool {self.balance(pool)}')

    def pos_election(self):
        """The election reserves a result. The first design gave an identity two units by a second bond; the package's caps are (16, 1, 6): lMax is ONE lot per
        identity and a genesis identity has used it, so that bond is refused with LotCapacity (asserted here: the first run of this stage reverted on it, and
        unequal weights therefore need a new identity that bonds several units in one lot, i.e. a joiner, which is a later stage). What this stage checks is that
        the election reserves a result for the unchanged four-member set at its cadence (400 rounds and 300 s past the anchors) and records the frozen members;
        no handoff is made here. A result open BEFORE the stage starts is reported, not hidden."""
        pos = self.manifest.get('pos')
        self.expect(bool(pos), 'the manifest carries a pos block (this generation was made with --pos)')
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        custody, election = deployment['custody'], deployment['election']
        identity = json.loads((self.gen / 'network' / 'pos-plan.json').read_text())['identities'][0]
        zero = '0x' + '00' * 32
        def open_result():
            out = self.view_text(election, 'openResult()(bytes32)').strip()
            return None if out == zero else out
        before = open_result()
        self.say(f'  open result at the start: {before}')
        live = self.view(election, 'liveCount()(uint32)')[0]
        self.expect(live == self.n, 'the election\'s live index holds every genesis identity', str(live))
        if self.balance(identity['owner']) < 10 ** 17:   # pos-rewards funds the owner; this stage must not depend on it
            self.faucet_send(identity['owner'], 10 ** 18)
        # a second lot for an existing identity: an eth_call from the owner (one wei is enough, the lot limit is checked after the zero-value check)
        status, text = self.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{
            'from': identity['owner'], 'to': custody, 'value': '0x1', 'data': self.cast_run('calldata', 'bond(uint64)', str(identity['stakingId']))}, 'latest']},
            PROXY_IPS[0] + '10')
        error = json.loads(text).get('error', {}) if status == 200 else {}
        selector = self.cast_run('sig', 'LotCapacity()')
        self.say(f'  second bond by the owner of identity {identity["stakingId"]}: {error.get("message")} {str(error.get("data"))[:40]}')
        self.expect(str(error.get('data', '')).startswith(selector), 'a second lot is refused with LotCapacity at lMax 1 (no top-up, no unequal weight without a joiner)', text[:200])
        def clock():
            return ' '.join(f'{k}={self.view(to, sig)[0]}' for k, to, sig in (('progress', self.REGISTRY, 'progress()(uint64)'), ('ucTime', self.REGISTRY, 'ucTime()(uint64)'),
                                                                                ('records', self.REGISTRY, 'recordCount()(uint64)'), ('cursor', custody, 'recordCursor()(uint64)')))
        def reserved():
            self.say('  election clock: ' + clock())
            return open_result()
        result = before or self.wait('the election reserves a result', reserved, 1500)
        raw = self.call('eth_call', [{'to': election, 'data': self.cast_run('calldata', 'result(bytes32)', result)}, 'latest'])
        state = int(raw[2:66], 16)   # ResultState: 1 Reserved
        members = self.view_text(election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', result)
        (self.evidence / 'pos-election-frozen-members.txt').write_text(members + '\n')
        self.say(f'  result {result}, state {state}: {members}')
        self.expect(state == 1, 'the open result is Reserved', str(state))
        self.expect(members.count('(') - members.count('((') == self.n, f'the reserved result freezes {self.n} members', members[:200])
        self.expect(before is None, 'no result was open before the stage started', str(before))

    # --- the packaged handoff, OPERATOR.md 5b (TN-S #437) ------------------------------------------------------------------------
    def host_ubft(self, *args):
        """The pinned host binary (--ubft), for the steps that only read and write files; stdout, or a Failure naming the command and its stderr."""
        self.expect(bool(self.ubft), 'the handoff stages need --ubft (the pinned binary)')
        run = subprocess.run([self.ubft, *map(str, args)], text=True, capture_output=True)
        if run.returncode:
            raise Failure(f'ubft {" ".join(map(str, args[:4]))}: exit {run.returncode}: {run.stderr.strip()[-500:]}')
        return run.stdout

    def exec_in(self, service, *command, binary=False):
        run = subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), 'exec', '-T', service, *command], text=not binary, capture_output=True)
        if run.returncode:
            stderr = run.stderr if isinstance(run.stderr, str) else run.stderr.decode(errors='replace')
            raise Failure(f'{service}: {" ".join(command[:5])}: exit {run.returncode}: {stderr.strip()[-500:]}')
        return run.stdout

    def entity_ids(self):
        """(root node id, EVM node id) of every entity: the root's from its home, the EVM validator's from its signing authority's generated command line."""
        services = json.loads((self.gen / 'compose.yaml').read_text())['services']
        ids = []
        for i in range(1, self.n + 1):
            root = self.host_ubft('node-id', '--home', self.gen / f'validator{i}' / 'root').strip().splitlines()[-1]
            command = services[f'authority{i}']['entrypoint']
            ids.append((root, command[command.index('--node-id') + 1]))
        return ids

    def build_assignment(self, tag, work, result, ids, reserved, evm_pops=None):
        """p85_build_assignment: the EVM context, the election's proposal for the result (`reserved` before the proofs exist, with the stored proofs after), every
        member's possession proof made INSIDE its signing authority's namespace (the inputs are copied to the entity's auth directory, which only its authority and
        shard mount), and the assembled EVM assignment. Returns (assignment file, proposal directory name, context file)."""
        net, root_rpc = self.gen / 'network', operator_rpc.common_urls(json.loads((self.gen / 'compose.yaml').read_text()))[0]
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'evm-context', '--root-rpc', root_rpc, '--out', '/tmp/context.json')
        context = work / f'{tag}-context.json'
        context.write_text(self.exec_in('root1', 'cat', '/tmp/context.json'))
        os.chown(work, 10001, 10001)
        node_ids = ','.join(f'{r},{e}' for r, e in ids)
        args = ['pos-relayer', 'proposal', *(['--reserved'] if reserved else []), '--eth-rpc', 'http://ureth1:8545', '--pos-deployment', '/deployment.json',
                '--context', f'/work/{tag}-context.json', '--result-id', result, '--node-ids', node_ids, '--trust-base', '/trust-base.json', '--out-dir', f'/work/{tag}-proposal']
        if evm_pops:
            args += ['--evm-pops', f'/work/{evm_pops}']
        subprocess.run(['chown', '-R', '10001:10001', str(work)], check=True)
        run = self.node_run(args, [f'{work}:/work', f'{net / "pos-deployment.json"}:/deployment.json:ro', f'{self.previous_trust_base()}:/trust-base.json:ro'])
        self.expect(run.returncode == 0, f'{tag}: pos-relayer proposal', run.stderr.strip()[-500:])
        proposal = work / f'{tag}-proposal'
        pops = []
        for i, (_, evm) in enumerate(ids, 1):
            auth = self.gen / f'validator{i}' / 'auth'
            for name, source in (('context.json', context), ('validators.json', proposal / 'validators.json'), ('identities.json', proposal / 'identities.json')):
                shutil.copy(source, auth / name)
                os.chown(auth / name, 10001, 10001)
            out = self.exec_in(f'authority{i}', 'ubft', 'root', 'handoff', 'evm-pop', '--context', '/authority/context.json', '--validators', '/authority/validators.json',
                               '--identities', '/authority/identities.json', '--node-id', evm, '--authority-socket', '/authority/operator.sock',
                               '--authority-credential', '/authority/operator.cred')
            (work / f'{tag}-pop-{i}.json').write_text(out)
            pops.append(str(work / f'{tag}-pop-{i}.json'))
        assignment = work / f'{tag}-assignment.json'
        self.host_ubft('root', 'handoff', 'evm-assemble', '--context', context, '--validators', proposal / 'validators.json', '--identities', proposal / 'identities.json',
                       '--authorization', proposal / 'authorization.json', '--pops', ','.join(pops), '--bindings', proposal / 'bindings.json',
                       *(['--evm-pops', proposal / 'evm-pops.json'] if evm_pops else []), '--out', assignment)
        return assignment, proposal, context

    def pos_proposal(self, resubmit=True):
        """5b steps 0-4 on the election's reserved result: the preflight, the next root trust base (epoch 2, the same four members and weights, signed by each
        root's key), the EVM possession proofs made by the signing authorities over the candidate, their submission to the election and its finalization (sent by
        the relayer container with a funded owner key), and the assignment rebuilt with the stored proofs. Stops before the candidate, readiness and the proposal.
        `resubmit=False` is the next attempt after an Abort before H: the proofs are made again for it (they bind the attempt) but the election already holds its
        published result, which an Abort before the Freeze does not close, so nothing is submitted or finalized again."""
        pos = self.manifest.get('pos')
        self.expect(bool(pos), 'the manifest carries a pos block (this generation was made with --pos)')
        compose = json.loads((self.gen / 'compose.yaml').read_text())
        net, work = self.gen / 'network', self.gen / 'network' / 'handoff'
        deployment = json.loads((net / 'pos-deployment.json').read_text())
        election = deployment['election']
        work.mkdir(exist_ok=True)
        # 0 preflight: every entity running, every root at epoch 1, the election has a reserved result
        running = set(self.compose('ps', '--services', '--status', 'running').split())
        needed = {f'{role}{i}' for i in range(1, self.n + 1) for role in ('pod', 'root', 'shard', 'authority', 'ureth')}
        self.expect(needed <= running, 'every entity service is running', str(sorted(needed - running)))
        root_rpc = operator_rpc.common_urls(compose)[0]
        transport = handoff_ops.DockerTransport(self.gen)   # one-shot python sidecar in the entity's namespace (the operator listener is loopback there)
        for i in range(1, self.n + 1):
            # `ubft q3 signers --out` writes only the signer list, no epoch (the first run of this stage found 5b's step 0 wrong): ask the endpoint it wraps
            status, body = transport.post(i, '/api/v1/q3/signers', b'{}')
            signers = json.loads(body) if status == 200 else {}
            self.expect(status == 200 and signers.get('epoch') == self.target - 1 and signers.get('quorum'), f'root {i} certifies at epoch {self.target - 1} with a quorum', f'{status} {body[:200]!r}')
        zero = '0x' + '00' * 32
        result = self.view_text(election, 'openResult()(bytes32)').strip()
        self.expect(result != zero, 'the election has a reserved result (run pos-election first)')
        ids = self.entity_ids()
        # 1 the next root trust base
        weights = ','.join(['1'] * self.n)
        self.host_ubft('trust-base', 'generate', '--home', work, '--network-id', '3', '--epoch', str(self.target), '--epoch-start', str(200000 * (self.target - 1)), '--previous-trust-base', self.previous_trust_base(),
                       '--root-weights', weights, '--output-file-name', f'trust-base-epoch{self.target}.json',
                       *[x for i in range(1, self.n + 1) for x in ('--node-info', self.gen / f'validator{i}' / 'root' / 'node-info.json')])
        for i in range(1, self.n + 1):
            self.host_ubft('trust-base', 'sign', '--home', self.gen / f'validator{i}' / 'root', '--trust-base', work / f'trust-base-epoch{self.target}.json')
        # 2-3 the assignment with its reserved proofs, the candidate, every authority's proof over it
        assignment, proposal, context = self.build_assignment('reserved', work, result, ids, True)
        attempt = (proposal / 'attempt.txt').read_text().strip()
        self.host_ubft('pos-relayer', 'candidate', '--context', context, '--assignment', assignment, '--next-trust-base', work / f'trust-base-epoch{self.target}.json', '--out', work / 'candidate.hex')
        collected = []
        for i in range(1, self.n + 1):
            auth = self.gen / f'validator{i}' / 'auth'
            for name, source in (('candidate.hex', work / 'candidate.hex'), ('pos-deployment.json', net / 'pos-deployment.json')):
                shutil.copy(source, auth / name)
                os.chown(auth / name, 10001, 10001)
            self.exec_in(f'authority{i}', 'ubft', 'pos-relayer', 'sign-pop', '--candidate', '/authority/candidate.hex', '--pos-deployment', '/authority/pos-deployment.json',
                         '--attempt', attempt, '--authority-socket', '/authority/operator.sock', '--authority-credential', '/authority/operator.cred', '--out', '/authority/evmpop.json')
            shutil.copy(auth / 'evmpop.json', work / f'evmpop-{i}.json')
            collected += ['--pop', work / f'evmpop-{i}.json']
        self.host_ubft('pos-relayer', 'assemble', '--candidate', work / 'candidate.hex', '--pos-deployment', net / 'pos-deployment.json', '--attempt', attempt, *collected,
                       '--out', work / 'evm-pops-collected.json')
        if resubmit:
            # 3 submit the proofs and finalize the result: the funded owner key of a genesis identity pays
            identity = json.loads((net / 'pos-plan.json').read_text())['identities'][0]
            if self.balance(identity['owner']) < 10 ** 17:
                self.faucet_send(identity['owner'], 10 ** 18)
            owner_key = self.gen / pos['owner_keys'] / f'identity-{identity["stakingId"]}' / 'owner.key'
            subprocess.run(['chown', '-R', '10001:10001', str(work)], check=True)
            for step, extra in (('submit-pops', ['--evm-pops', '/work/evm-pops-collected.json']), ('finalize', [])):
                status, out = self.relayer(owner_key, step, '--result-id', result, *extra, mounts=[f'{work}:/work:ro'])
                self.expect(status == 0, f'pos-relayer tx {step}', out.strip()[-500:])
            raw = self.call('eth_call', [{'to': election, 'data': self.cast_run('calldata', 'publication(bytes32)', result)}, 'latest'])
            self.expect(int(raw[2 + 64 * 10:2 + 64 * 11], 16) == 1, 'the result is published (the election holds the proofs)')
        # 4 the assignment again, with the stored proofs
        assignment, proposal, _ = self.build_assignment('published', work, result, ids, False, 'evm-pops-collected.json')
        self.expect(assignment.stat().st_size > 0, 'the published assignment is written', str(assignment))
        kept = self.evh()
        kept.mkdir(exist_ok=True)
        lines = []
        for path in sorted(work.rglob('*')):
            if path.is_file() and path.suffix in ('.json', '.hex', '.txt'):
                lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(work)}')
                target = kept / path.relative_to(work)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(path, target)
        (kept / 'sha256.txt').write_text('\n'.join(lines) + '\n')
        self.say(f'  {len(lines)} handoff artifacts recorded (sha256.txt)')

    def pos_candidate(self):
        """5b steps 5 and 6: the roots' candidate for the epoch-2 trust base and the published assignment (one root derives it) and the readiness receipt of EVERY entity,
        each made by its own root (see pos_propose). Returns the handoff directory and the receipt files."""
        compose = json.loads((self.gen / 'compose.yaml').read_text())
        work = self.gen / 'network' / 'handoff'
        for name in (f'trust-base-epoch{self.target}.json', 'published-assignment.json'):
            self.expect((work / name).is_file(), f'{name} exists (run pos-proposal first)')
        root_rpc, shard_rpc = operator_rpc.common_urls(compose)
        subprocess.run(['chmod', '-R', 'a+rX', str(work)], check=True)   # the host's files (mode 0600, root) are read by the nodes, which mount network/ read-only
        # 5 the candidate, from one root; the files are copied out of its container
        self.exec_in('root1', 'rm', '-rf', '/tmp/candidate')
        try:
            self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-candidate', '--next-trust-base', f'/network/handoff/trust-base-epoch{self.target}.json',
                         '--next-evm-assignment', '/network/handoff/published-assignment.json', '--root-rpc', root_rpc, '--out-dir', '/tmp/candidate')
        except Failure as refused:
            # the root's answer is one line for many causes: ask again without the assignment and on another root, so the report says where the refusal sits
            for service, extra in (('root1', []), ('root2', ['--next-evm-assignment', '/network/handoff/published-assignment.json'])):
                try:
                    self.exec_in(service, 'ubft', 'root', 'handoff', 'q3-candidate', '--next-trust-base', f'/network/handoff/trust-base-epoch{self.target}.json', *extra,
                                 '--root-rpc', root_rpc, '--out-dir', '/tmp/candidate-probe')
                    self.say(f'  probe {service} {"with" if extra else "without"} the assignment: accepted')
                except Failure as probe:
                    self.say(f'  probe {service} {"with" if extra else "without"} the assignment: {str(probe)[-200:]}')
            raise refused
        for name in ('candidate.cbor', 'config.json', 'v3-body-id.txt', 'root-weights.json', 'evm-weights.json'):
            (work / name).write_bytes(self.exec_in('root1', 'cat', f'/tmp/candidate/{name}', binary=True))
        subprocess.run(['chmod', '-R', 'a+rX', str(work)], check=True)
        config = json.loads((work / 'config.json').read_text())
        self.expect(config.get('signingScheme') == 2, 'the candidate selects signing scheme 2', str(config)[:200])
        # 6 the readiness receipt of every entity, in its own root
        genesis = self.call('eth_getBlockByNumber', ['0x0', False])['hash']
        spec = json.loads((self.gen / 'network' / 'genesis.json').read_text())['alloc']
        registry = self.REGISTRY.lower().removeprefix('0x')
        code = {k.lower().removeprefix('0x'): v for k, v in spec.items()}[registry]['code']
        code_hash = hashlib.sha256(bytes.fromhex(code.removeprefix('0x'))).hexdigest()
        self.say(f'  pins: execution genesis {genesis}, registry code sha256 {code_hash}')
        receipts = []
        for i in range(1, self.n + 1):
            self.exec_in(f'root{i}', 'ubft', 'root', 'handoff', 'q3-readiness', '--candidate', '/network/handoff/candidate.cbor', '--key-conf', '/state/keys.json',
                         '--root-rpc', root_rpc, '--shard-rpc', shard_rpc, '--eth-url', f'http://ureth{i}:8545', '--engine-url', f'http://ureth{i}:8551',
                         '--jwt-secret', '/jwt/jwt.hex', '--execution-genesis-hash', genesis, '--execution-code-hash', code_hash, '--out', '/tmp/receipt.json')
            (work / f'receipt-{i}.json').write_text(self.exec_in(f'root{i}', 'cat', '/tmp/receipt.json'))
            receipts.append(str(work / f'receipt-{i}.json'))
        self.expect(len(receipts) == self.n, 'one readiness receipt per entity')
        return work, receipts

    def pos_propose(self):
        """5b steps 5-7 on the files pos-proposal wrote: the roots' candidate for the epoch-2 trust base and the published assignment (one root derives it), the
        readiness receipt of EVERY entity made by its own root (its key file, its shard's loopback RPC, its execution client and its Engine JWT, with the operator's own
        pins of the execution genesis hash and the registry code), then the proposal of that ONE plan to every root by the host wrapper (plan, intent, endorse).
        The pins are not read from the node under test: the registry code hash comes from the shipped genesis; the genesis block hash is entity 1's, taken once here
        (as the lane takes it at its start). Stops with the handoff committed at epoch 1; the install is the next stage."""
        work, receipts = self.pos_candidate()
        # 7 propose, as ONE plan, by the host wrapper
        transport = handoff_ops.DockerTransport(self.gen)
        wrapper_log = self.gen / 'handoff' / 'log.jsonl'
        earlier = len(wrapper_log.read_text().splitlines()) if wrapper_log.exists() else 0   # rows of a rehearsed Abort or of the first handoff are not this proposal's
        try:   # the Abort target needs the context, which the root answers only while idle: read before the plan (pos-too-late names the committed handoff with it)
            context = handoff_ops.abort_context(transport, 1)
        except handoff_ops.HandoffError as error:
            context = None
            self.say(f'  no evm-assignment context before the proposal: {error}')
        run = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'handoff_ops.py'), 'propose', str(self.gen), '--ubft', str(self.ubft),
                              '--next-trust-base', str(work / f'trust-base-epoch{self.target}.json'), '--next-evm-assignment', str(work / 'published-assignment.json'),
                              '--readiness-receipts', ','.join(receipts), '--intent-delay', '1.5'], text=True, capture_output=True)
        self.evh()
        (self.evh() / 'propose.log').write_text(run.stdout + run.stderr)
        if run.returncode:   # the root's refusal is one line for many causes: report what each root holds, so the refusal can be located
            for i in range(1, self.n + 1):
                for path in ('/api/v1/q3/status', '/api/v1/q3/signers'):
                    status, body = transport.post(i, path, b'{}')
                    self.say(f'  root {i} {path}: {status} {body[:400].decode(errors="replace")}')
            # the root reads the election's stored proofs from ITS OWN execution client: ask every client the same question
            election = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())['election']
            result = self.view_text(election, 'openResult()(bytes32)').strip()
            call = [{'to': election, 'data': self.cast_run('calldata', 'publication(bytes32)', result)}, 'latest']
            for i in range(1, self.n + 1):
                raw = self.ureth(i, 'eth_call', call)
                self.say(f'  ureth {i}: block {int(self.ureth(i, "eth_blockNumber"), 16)}, published word {int(raw[2 + 64 * 10:2 + 64 * 11], 16)}, openResult {self.ureth(i, "eth_call", [{"to": election, "data": self.cast_run("calldata", "openResult()")}, "latest"])[:12]}')
        self.expect(run.returncode == 0, 'handoff_ops.py propose', (run.stdout + run.stderr).strip()[-600:])
        accepted = int(run.stdout.strip().splitlines()[-1].split()[1])
        self.expect(accepted >= self.n * 2 // 3 + 1, f'a quorum of the {self.n} roots endorsed the one plan', run.stdout.strip().splitlines()[-1])
        log = [json.loads(line) for line in wrapper_log.read_text().splitlines()][earlier:]
        self.expect(len({row['plan_sha256'] for row in log if row['event'] in ('plan', 'intent', 'endorse')}) == 1, 'every phase of the attempt carries the same plan hash')
        planned = [row for row in log if row['event'] == 'plan'][-1]
        self.committed_target = None if context is None or planned['plan_attempt'] != context['attempt'] else {
            'network': context['network'], 'oldEpoch': self.target - 1, 'predecessorBodyId': '0x' + context['predecessor'].removeprefix('0x'),
            'attempt': planned['plan_attempt'], 'nextBodyId': planned['next_body_id']}
        # the intents were handed over 1.5 s apart (plus the sidecar's second each): the later validators got theirs after the leader had ordered the Prepare, which the
        # root refused before #795. Neither a refusal nor a lapse may appear.
        self.expect(not [row for row in log if row['event'] in ('intent-refused', 'lapsed')], 'slow intent delivery (1.5 s apart) is accepted: no refusal, no lapse', str(log)[-300:])
        for path in sorted(work.glob('receipt-*.json')) + [work / 'candidate.cbor', work / 'config.json', work / 'v3-body-id.txt']:
            self.say(f'  sha256 {hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}')
            shutil.copy(path, self.evh() / path.name)
        shutil.copy(self.gen / 'handoff' / 'log.jsonl', self.evh() / 'log.jsonl')

    def pos_abort(self):
        """5b step 14, before the handoff is committed: the candidate and the receipts as for the proposal, then the plan, every intent and the endorsement of ONE root (below
        the quorum, so no Freeze follows), then `handoff_ops.py abort` with the exact target on all four roots at once. Expects the committed Abort record from every root, the
        epoch unchanged at 1 and the EVM certifying again (a paid transaction through the gateway). Then the proposal's steps 0-4 again for the next attempt (new possession proofs) and the root's candidate for it."""
        work, receipts = self.pos_candidate()
        ops = str(Path(__file__).resolve().parent / 'handoff_ops.py')
        held = subprocess.run([sys.executable, ops, 'hold', str(self.gen), '--ubft', str(self.ubft), '--old-trust-base', str(self.previous_trust_base()), '--next-trust-base', str(work / f'trust-base-epoch{self.target}.json'),
                               '--next-evm-assignment', str(work / 'published-assignment.json'), '--readiness-receipts', ','.join(receipts)], text=True, capture_output=True)
        self.evh()
        (self.evh() / 'abort-hold.log').write_text(held.stdout + held.stderr)
        self.expect(held.returncode == 0, 'one root endorsed the plan, the others hold its intent (the handoff is prepared, not frozen)', (held.stdout + held.stderr).strip()[-500:])
        target = json.loads(held.stdout.strip().splitlines()[-1])
        (self.evh() / 'abort-target.json').write_text(json.dumps(target, indent=1, sort_keys=True) + '\n')
        self.say(f'  target: attempt {target["attempt"]}, old epoch {target["oldEpoch"]}, successor body {target["nextBodyId"]}')
        # the EVM is frozen from the Prepare: a transaction sent now is not mined (a few seconds, well inside the 24 rounds before the freeze lapses) ...
        sender, to = self.manifest['faucet_address'], '0x' + '33' * 20
        frozen_at = int(self.call('eth_blockNumber'), 16)
        nonce = int(self.call('eth_getTransactionCount', [sender, 'latest']), 16)
        sent = self.call('eth_sendRawTransaction', [self.raw_tx(to, nonce, int(self.call('eth_gasPrice'), 16), 1)])
        time.sleep(4)
        self.expect(self.call('eth_getTransactionReceipt', [sent]) is None, 'a transaction sent while the handoff is prepared is not mined (the EVM is frozen)', sent)
        before = int(self.call('eth_blockNumber'), 16)
        self.expect(before == frozen_at, 'the execution chain did not advance across the 4 s frozen window', f'{frozen_at} -> {before}')
        aborted = subprocess.run([sys.executable, ops, 'abort', str(self.gen), '--', '--network', str(target['network']), '--old-epoch', str(target['oldEpoch']),
                                  '--predecessor-body-id', target['predecessorBodyId'], '--attempt', str(target['attempt']), '--next-body-id', target['nextBodyId'],
                                  '--timeout', '90s'], text=True, capture_output=True)
        (self.evh() / 'abort.log').write_text(aborted.stdout + aborted.stderr)
        committed = [line for line in aborted.stdout.splitlines() if 'committed Abort record' in line]
        self.expect(aborted.returncode == 0 and len(committed) == self.n, f'all {self.n} roots report the committed Abort record', (aborted.stdout + aborted.stderr).strip()[-500:])
        self.expect(len({line.split('record ')[1].split()[0] for line in committed}) == 1, 'they name one Abort record', committed[0])
        self.expect(all(self.root_epoch(i) == 1 for i in range(1, self.n + 1)), 'every root is still at epoch 1')
        # ... and it is mined once the Abort has unfrozen the EVM
        receipt = self.wait('the transaction held by the freeze is mined after the Abort', lambda: self.call('eth_getTransactionReceipt', [sent]), 120)
        self.expect(receipt['status'] == '0x1', 'it is mined after the Abort', sent)
        self.expect(int(self.call('eth_blockNumber'), 16) > before, 'the execution chain advanced after the Abort')
        # the next attempt needs new approvals: the possession proofs bind the attempt (popContext), so the assignment made for the Aborted attempt is refused by the
        # root ("invalid proof of possession", run 39962014299). Steps 0-4 again, now at the attempt the root plans (the chain's context names it), then the candidate.
        self.pos_proposal(resubmit=False)
        root_rpc = operator_rpc.common_urls(json.loads((self.gen / 'compose.yaml').read_text()))[0]
        self.exec_in('root1', 'rm', '-rf', '/tmp/candidate-probe')
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-candidate', '--next-trust-base', f'/network/handoff/trust-base-epoch{self.target}.json',
                     '--next-evm-assignment', '/network/handoff/published-assignment.json', '--root-rpc', root_rpc, '--out-dir', '/tmp/candidate-probe')
        self.expect('candidate.cbor' in self.exec_in('root1', 'ls', '/tmp/candidate-probe'), 'the root derives the next attempt\'s candidate from the assignment made for it')

    def pos_too_late(self):
        """5b step 14 after H: the handoff proposed by pos-propose is committed (the roots still certify at the old epoch, the install has not run). An Abort naming that
        exact handoff is not ordered: every root answers "too late" and the CLI exits non-zero, no Abort record is committed, the epoch does not move and the install
        (the next stage) still works. Run right after pos-propose."""
        target = self.committed_target
        self.expect(target is not None, 'the committed handoff\'s target was read by pos-propose (context before the plan)', str(target))
        (self.evh() / 'too-late-target.json').write_text(json.dumps(target, indent=1, sort_keys=True) + '\n')
        before = [self.root_epoch(i) for i in range(1, self.n + 1)]
        ops = str(Path(__file__).resolve().parent / 'handoff_ops.py')
        aborted = subprocess.run([sys.executable, ops, 'abort', str(self.gen), '--', '--network', str(target['network']), '--old-epoch', str(target['oldEpoch']),
                                  '--predecessor-body-id', target['predecessorBodyId'], '--attempt', str(target['attempt']), '--next-body-id', target['nextBodyId'],
                                  '--timeout', '30s'], text=True, capture_output=True)
        (self.evh() / 'too-late.log').write_text(aborted.stdout + aborted.stderr)
        self.say(f'  abort after H: exit {aborted.returncode}: {(aborted.stdout + aborted.stderr).strip()[-600:]}')
        out = aborted.stdout + aborted.stderr
        # handoff_ops.py abort prints one block per entity: "entity i: exit N" and then that root's output
        blocks = {int(m.group(1)): (int(m.group(2)), m.group(3)) for m in re.finditer(r'^entity (\d+): exit (\d+)\n(.*?)(?=^entity \d+: exit |\Z)', out, re.M | re.S)}
        self.expect(aborted.returncode != 0 and sorted(blocks) == list(range(1, self.n + 1)) and all(code != 0 and 'too late' in text for code, text in blocks.values()),
                    f'each of the {self.n} roots answers "too late" and exits non-zero, and so does the abort', out.strip()[-500:])
        self.expect('committed Abort record' not in out and 'Abort already committed' not in out, 'no Abort record was committed')
        self.expect([self.root_epoch(i) for i in range(1, self.n + 1)] == before, 'no root changed epoch', str(before))

    def pos_handoff_2(self):
        """The second handoff, root epoch 2 to 3, from the epoch-2 network the earlier stages left (pos-stale restored its credentials): the election reserves the next
        result (its cadence is 400 rounds and 300 s past the anchors), then the same steps as the first (proposal, propose, install, advance) with `self.target` 3: the
        epoch-3 trust base from the epoch-2 one, the install override for epoch 3 over the epoch-2 stores (kept as root.pre-epoch-3), the Commit of the epoch-2 committee
        (scheme 2), the shard configuration after the last one, paid work at epoch 3."""
        transport = handoff_ops.DockerTransport(self.gen)
        self.expect(all(self.root_epoch(i, transport) == 2 for i in range(1, self.n + 1)), 'every root certifies at epoch 2 (run the first handoff first)')
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        election, zero = deployment['election'], '0x' + '00' * 32
        done = self.view_text(election, 'openResult()(bytes32)').strip()
        self.say(f'  open result at the start: {done} (the first handoff\'s result is {"still open" if done != zero else "closed"})')
        def next_result():
            out = self.view_text(election, 'openResult()(bytes32)').strip()
            self.say(f'  openResult {out}, progress {self.view(self.REGISTRY, "progress()(uint64)")[0]}')
            return out if out != zero and out != done else None
        self.wait('the election reserves the next result', next_result, 1500)
        self.target = 3
        try:
            self.pos_proposal()
            self.pos_propose()
            self.pos_install()
            self.pos_advance()
        finally:
            self.target = 2

    def root_epoch(self, i, transport=None):
        """The epoch of root i's committed certificate, or None while it does not answer."""
        transport = transport or handoff_ops.DockerTransport(self.gen)
        try:
            status, body = transport.post(i, '/api/v1/q3/signers', b'{}')
            return json.loads(body).get('epoch') if status == 200 else None
        except (handoff_ops.HandoffError, ValueError):
            return None

    def root_listens(self, i, transport):
        try:
            transport.post(i, '/api/v1/q3/signers', b'{}')
            return True
        except handoff_ops.HandoffError:
            return False

    def pos_install(self):
        """5b steps 8-10: the installation barrier of epoch 2 and the activation. No root may have a certificate of epoch 2 before its install restart (checked); each root in
        turn is stopped, its four stores kept as root.pre-epoch-2, and recreated with `--install-handoff-epoch 2` (the Compose override handoff.py writes; a plain
        `up -d` would drop the flag); then the first root reports epoch 2, the activation record is read and checked against the candidate, and every shard has logged the
        activation. Needs pos-propose first (the handoff must be committed)."""
        compose = json.loads((self.gen / 'compose.yaml').read_text())
        work = self.gen / 'network' / 'handoff'
        self.expect((work / 'v3-body-id.txt').is_file(), 'the candidate files exist (run pos-propose first)')
        transport = handoff_ops.DockerTransport(self.gen)
        for i in range(1, self.n + 1):
            self.expect(self.root_epoch(i, transport) == self.target - 1, f'root {i} has no certificate of epoch {self.target} before its install restart')
        override = self.gen / f'compose.install-epoch-{self.target}.json'
        if not override.exists():
            override.write_text(json.dumps(handoff.install_override(compose, self.target), indent=1) + '\n')
        files = ['-f', str(self.gen / 'compose.yaml'), '-f', str(override)]
        for i in range(1, self.n + 1):
            self.say(f'  installing epoch {self.target} in root {i}')
            subprocess.run(['docker', 'compose', *files[:2], 'stop', f'root{i}'], check=True, capture_output=True)
            state = self.gen / f'validator{i}' / 'root'
            backup = self.gen / f'validator{i}' / f'root.pre-epoch-{self.target}'
            if not backup.exists():
                subprocess.run(['cp', '-a', str(state), str(backup)], check=True)
            run = subprocess.run(['docker', 'compose', *files, 'up', '-d', '--no-deps', '--force-recreate', f'root{i}'], text=True, capture_output=True)
            self.expect(run.returncode == 0, f'root {i} recreated with the install flag', run.stderr.strip()[-400:])
            # only the listener: a root that has installed epoch 2 certifies nothing until the others are in it too (as in the lane's restart loop)
            self.wait(f'root {i} listens again', lambda i=i: self.root_listens(i, transport), 120)
        epoch = self.wait(f'the roots certify at epoch {self.target}', lambda: self.root_epoch(1, transport) == self.target, 180)
        self.expect(epoch, f'root 1 certifies at epoch {self.target} after the install')
        for i in range(2, self.n + 1):
            self.wait(f'root {i} certifies at epoch {self.target}', lambda i=i: self.root_epoch(i, transport) == self.target, 120)
        # 9 the activation record, read from a running root and checked against the candidate
        root_rpc = operator_rpc.common_urls(compose)[0]
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'q3-activation', '--root-rpc', root_rpc, '--epoch', str(self.target), '--out', '/tmp/activation.json')
        record = json.loads(self.exec_in('root1', 'cat', '/tmp/activation.json'))
        self.evh()
        (self.evh() / f'activation-record-{self.target}.json').write_text(json.dumps(record, indent=1) + '\n')
        self.expect(record.get('epoch') == self.target and record.get('signingScheme') == 2, f'the activation record is epoch {self.target} under scheme 2', str(record)[:200])
        self.expect(record.get('v3BodyId') == (work / 'v3-body-id.txt').read_text().strip(), 'the activation record names the candidate\'s V3 body id')
        self.expect(record['activationRound'] >= record['minActivationRound'], 'A* is not below A_min', f'{record["activationRound"]} / {record["minActivationRound"]}')
        status, body = transport.post(1, '/api/v1/q3/signers', b'{}')
        self.expect(json.loads(body)['round'] >= record['activationRound'], f'the first epoch-{self.target} certificate is at or above A*')
        commit = record['commit']
        want = (1, 1) if self.target == 2 else (2, self.target - 1)   # the genesis committee signs in the legacy scheme, a later one in scheme 2
        self.expect((commit['scheme'], commit['epoch']) == want, f'the Commit is the epoch-{want[1]} committee\'s (scheme {want[0]})', f'scheme {commit["scheme"]}, epoch {commit["epoch"]}')
        # 10 the gate: every shard has activated the root epoch
        for i in range(1, self.n + 1):
            def activated(i=i):
                logs = self.compose('logs', '--no-color', f'shard{i}', check=False)
                # the package's logs are JSON: {"message":"handoff activated","rootEpoch":2,...} (the lane's text format was msg="handoff activated" rootEpoch=2)
                return any('"message":"handoff activated"' in line and f'"rootEpoch":{self.target},' in line for line in logs.splitlines())
            self.wait(f'shard {i} logs the activation of root epoch {self.target}', activated, 90)
        self.say(f'  every shard has activated root epoch {self.target}')

    def pos_advance(self):
        """5b steps 11-13: the shard configuration of the epoch the handoff activates (read from a running root), then, for each entity in turn, the advance of its
        signing authority to the new root epoch and shard configuration and a new session for its shard node (the shard is stopped for it and started again with the
        same command; the authority is never recreated), and finally paid work at the new epoch: a transaction through the public gateway is certified on every
        validator, the roots stay at epoch 2 and the custody has applied every root record. Needs pos-install first."""
        compose = json.loads((self.gen / 'compose.yaml').read_text())
        work = self.gen / 'network' / 'handoff'
        transport = handoff_ops.DockerTransport(self.gen)
        self.expect(all(self.root_epoch(i, transport) == self.target for i in range(1, self.n + 1)), f'every root certifies at epoch {self.target} (run pos-install first)')
        root_rpc = operator_rpc.common_urls(compose)[0]
        # 11 the shard configuration of the activated shard epoch (the EVM partition's epoch after the installed one)
        installed = max([json.loads((self.gen / 'network' / 'full-shard-conf.json').read_text())['epoch']] + [json.loads(f.read_text())['epoch'] for f in work.glob('shard-conf-*.json')])
        shard_epoch = installed + 1
        self.exec_in('root1', 'ubft', 'q3', 'shard-conf', '--root-rpc', root_rpc, '--epoch', str(shard_epoch), '--out', '/tmp/shard-conf.json')
        conf = json.loads(self.exec_in('root1', 'cat', '/tmp/shard-conf.json'))
        self.expect(conf.get('epoch') == shard_epoch and conf.get('partitionId') == 8, f'a root holds the EVM shard configuration of epoch {shard_epoch}', str(conf)[:200])
        (work / f'shard-conf-{shard_epoch}.json').write_text(json.dumps(conf, indent=1) + '\n')
        subprocess.run(['chmod', '-R', 'a+rX', str(work)], check=True)
        # 12 the authorities and the shard nodes, one entity at a time
        for i in range(1, self.n + 1):
            self.say(f'  advancing the authority of entity {i}')
            self.compose('stop', f'shard{i}')
            operator = ['--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred']
            self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'advance-epoch', *operator, '--trust-base', f'/network/handoff/trust-base-epoch{self.target}.json',
                         '--shard-conf', f'/network/handoff/shard-conf-{shard_epoch}.json')
            auth = self.gen / f'validator{i}' / 'auth'
            shutil.copy(auth / 'client.cred', auth / f'client.cred.pre-epoch-{self.target}')   # kept for pos-stale; a credential, so only in the entity's own auth directory
            os.chmod(auth / f'client.cred.pre-epoch-{self.target}', 0o600)
            self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'replace-session', *operator, '--out', '/authority/client.cred')
            self.compose('start', f'shard{i}')
        # 13 paid work at the new epoch
        self.wait('the public gateway is healthy', lambda: self.http(PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 300)
        receipt = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '44' * 20))
        self.expect(receipt['status'] == '0x1', 'a transaction through the gateway is mined after the switch', receipt['transactionHash'])
        for i in range(1, self.n + 1):
            r = self.wait(f'validator {i} has it', lambda i=i: self.ureth(i, 'eth_getTransactionReceipt', [receipt['transactionHash']]), 180)
            self.expect(r['blockHash'] == receipt['blockHash'], f'validator {i} has it in the same block')
        self.expect(all(self.root_epoch(i, transport) == self.target for i in range(1, self.n + 1)), f'every root still certifies at epoch {self.target}')
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        def applied():
            count = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == self.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None
        self.say(f'  recordCount == recordCursor == {self.wait("the custody has applied every root record", lambda: applied() is not None, 300) and applied()}')

    def exec_rc(self, service, *command):
        run = subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), 'exec', '-T', service, *command], text=True, capture_output=True)
        return run.returncode, run.stdout, run.stderr

    def pos_restart(self, epoch=2):
        """The TN-1 pod-restart stage on the switched PoS network: one entity at a time (--pods) its execution client, root and shard node are stopped, the survivors
        certify a transaction, the entity is started again (`start`: the roots keep the container they were recreated with, install flag included) and converges; then every
        root still certifies at the root epoch and the custody has applied every root record. Needs pos-advance first (pos-handoff-2 for epoch 3)."""
        transport = handoff_ops.DockerTransport(self.gen)
        self.expect(all(self.root_epoch(i, transport) == epoch for i in range(1, self.n + 1)), f'every root certifies at epoch {epoch} (run the handoff first)')
        self.pod_restart()
        for i in range(1, self.n + 1):
            self.wait(f'root {i} certifies at epoch {epoch} again', lambda i=i: self.root_epoch(i, transport) == epoch, 180)
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        def applied():
            count = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == self.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None
        self.expect(self.wait('the custody has applied every root record', lambda: applied() is not None, 300), 'recordCursor equals recordCount after the restarts', str(applied()))

    def pos_restart_2(self):
        """pos-restart after the second handoff: the roots were recreated into epoch 3 over the epoch-2 stores and keep that container; the pods restart and stay at epoch 3."""
        self.pos_restart(epoch=3)

    def pos_recreate(self):
        """A root recreated from compose.yaml ALONE, without any --install-handoff-epoch (the plain `docker compose up -d --force-recreate` an operator runs after a
        host reboot): it is recreated in its entity's namespace (--no-deps: pod<i> stays). That it came back is NOT shown by its stored latest certificate (the other
        roots keep certifying without it): root 2 is stopped, which makes root 1 needed for the quorum (4 roots, threshold 3), and the committed round must advance
        at epoch E with root 1 among the live roots; then root 2 is started again and converges. The container's own entrypoint is inspected for the flag. The flag-less
        start is what OPERATOR.md step 8 lists as UNVERIFIED; a failure carries the root's last log lines. Run after pos-advance (E=2) or pos-handoff-2 (E=3)."""
        transport = handoff_ops.DockerTransport(self.gen)
        epoch = self.root_epoch(1, transport)
        self.expect(epoch is not None and epoch >= 2 and all(self.root_epoch(i, transport) == epoch for i in range(1, self.n + 1)),
                    'every root certifies at the same switched epoch (run a handoff first)', str(epoch))
        def signers(i):
            try:
                status, body = transport.post(i, '/api/v1/q3/signers', b'{}')
                return json.loads(body) if status == 200 else None
            except (handoff_ops.HandoffError, ValueError):
                return None
        before = signers(1)
        self.expect(before is not None and before['threshold'] == self.n - 1, 'four roots at unit weight: the quorum threshold is 3', json.dumps(before))
        self.say(f'  recreating root1 from compose.yaml alone (no install flag), epoch {epoch}')
        self.compose('up', '-d', '--no-deps', '--force-recreate', 'root1')
        container = self.compose('ps', '-q', 'root1').strip()
        entry = json.loads(subprocess.run(['docker', 'inspect', '--format', '{{json .Config.Entrypoint}}', container], check=True, text=True, capture_output=True).stdout)
        (self.evh() / 'recreate-entrypoint.json').write_text(json.dumps(entry, indent=1) + '\n')
        self.expect('--install-handoff-epoch' not in entry, 'the running root1 container was created without --install-handoff-epoch', ' '.join(entry)[-200:])
        self.compose('stop', 'root2')
        try:
            # root 2 is down: 1, 3 and 4 are all needed, so a round committed now carries root 1's signature
            start = signers(3)['round']
            def advanced():
                one, three = signers(1), signers(3)
                return one and three and one['epoch'] == epoch and three['epoch'] == epoch and one['round'] > start + 3 and three['round'] > start + 3 and three['quorum'] and len(three['signers']) == self.n - 1
            self.wait(f'with root 2 stopped the committed round advances at epoch {epoch} on roots 1 and 3, signed by the three live roots', advanced, 240)
        except Exception:
            (self.evh() / 'recreate-root.log').write_text(self.compose('logs', '--no-color', '--tail', '80', 'root1', check=False))
            raise
        finally:
            self.compose('start', 'root2')
        for i in range(1, self.n + 1):
            self.wait(f'root {i} certifies at epoch {epoch}', lambda i=i: self.root_epoch(i, transport) == epoch, 180)
        deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
        def applied():
            count = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == self.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None
        self.expect(self.wait('the custody has applied every root record', lambda: applied() is not None, 300), 'recordCursor equals recordCount after the recreate', str(applied()))

    def pos_stale(self):
        """Credentials of the old epoch after the switch. (1) the authority refuses to be advanced back to the epoch-1 trust base and shard configuration, and its
        status does not move; (2) a shard node started with its PRE-advance client credential (kept as client.cred.pre-epoch-2 by pos-advance) is not served by the
        authority: what its logs say is recorded; the current credential is then put back and the entity converges. Needs pos-advance first. The texts are the
        product's and are recorded in the evidence (stale-trust-base.txt, the shard log excerpt)."""
        net = self.gen / 'network'
        operator = ['--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred']
        def status(i):
            # the identity of the authority's state; the reservation fields (reservedRound, responses) move with every certified round
            full = json.loads(self.exec_in(f'authority{i}', 'ubft', 'signing-authority', 'status', *operator))
            return {k: full[k] for k in ('authorityId', 'networkId', 'partitionId', 'shardEpoch', 'rootEpoch', 'shardConfHash', 'generation', 'signingKeyFingerprint', 'enrollmentComplete')}
        before = status(1)
        rc, out, err = self.exec_rc('authority1', 'ubft', 'signing-authority', 'advance-epoch', *operator, '--trust-base', '/network/trust-base.json',
                                    '--shard-conf', '/network/full-shard-conf.json')
        self.say(f'  advance back to epoch 1: exit {rc}: {(out + err).strip()[-300:]}')
        (self.evh() / 'stale-trust-base.txt').write_text(f'exit {rc}\n{out}{err}')
        self.expect(rc != 0 and 'signing-context-mismatch' in err, 'the authority refuses to be advanced back to the epoch-1 trust base and shard configuration (signing-context-mismatch)', (out + err).strip()[-300:])
        after = status(1)
        self.expect(after == before, 'the refused advance changes nothing in the authority status', f'{before} -> {after}')
        # (2) the old client credential
        auth = self.gen / 'validator1' / 'auth'
        old, current = auth / 'client.cred.pre-epoch-2', auth / 'client.cred'
        self.expect(old.is_file(), 'the pre-advance credential was kept (run pos-advance first)')
        shutil.copy(current, auth / 'client.cred.epoch-2')
        self.compose('stop', 'shard1')
        shutil.copy(old, current)
        started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')   # sub-second: a whole-second stamp reaches back to lines of the same second
        self.compose('start', 'shard1')
        time.sleep(30)
        logs = self.compose('logs', '--no-color', '--since', started, 'shard1', check=False)
        fenced = [line for line in logs.splitlines() if 'signing-session-fenced' in line]
        (self.evh() / 'stale-client-credential-shard1.log').write_text('\n'.join(fenced[:40]) + '\n')
        self.say(f'  shard 1 with the pre-advance credential: {len(fenced)} lines "restored authority refused readiness ... signing-session-fenced"')
        self.expect(len(fenced) > 0, 'the authority fences the old client session: the shard node reads signing-session-fenced and abstains', f'{len(fenced)} of {len(logs.splitlines())} log lines are signing-session-fenced' if fenced else f'{len(logs.splitlines())} log lines, none fenced')
        # put the current credential back: the entity signs again, and the fence is not in the log after the restart
        self.compose('stop', 'shard1')
        shutil.copy(auth / 'client.cred.epoch-2', current)
        restored = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')   # sub-second: a whole-second stamp reaches back to lines of the same second
        self.compose('start', 'shard1')
        receipt = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '55' * 20))
        self.expect(receipt['status'] == '0x1', 'a transaction through the gateway is mined with the current credential back', receipt['transactionHash'])
        self.wait('validator 1 has it', lambda: self.ureth(1, 'eth_getTransactionReceipt', [receipt['transactionHash']]), 180)
        time.sleep(20)
        again = [line for line in self.compose('logs', '--no-color', '--since', restored, 'shard1', check=False).splitlines() if 'signing-session-fenced' in line]
        self.expect(not again, 'with the current credential the shard node is not fenced', f'{len(again)} fenced lines')

    def observe(self):
        """The observation sampler (observe.py) as a smoke: four samples five seconds apart on the running generation. It must exit 0 (no alert), write four samples
        with a certified head from every root, and see the certified round move between the first and the last sample. The faucet guard is not sampled: its /healthz
        needs the signer, which a rehearsal does not start. The 24-hour interval is the host's."""
        out = self.evidence / 'observe'
        run = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'observe.py'), str(self.gen), '--out', str(out), '--samples', '4', '--interval', '5', '--no-faucet'],
                             text=True, capture_output=True)
        self.say(f'  observe.py: exit {run.returncode}: {(run.stdout + run.stderr).strip()[-400:]}')
        self.expect(run.returncode == 0, 'the sampler raised no alert on the healthy package', (run.stdout + run.stderr).strip()[-400:])
        samples = [json.loads(line) for line in (out / 'samples.jsonl').read_text().splitlines()]
        self.expect(len(samples) == 4 and all(len(x['roots']) == self.n and all('round' in r for r in x['roots'].values()) for x in samples), 'four samples, each with every root\'s certified head')
        first, last = (max(r['round'] for r in samples[i]['roots'].values()) for i in (0, -1))
        self.expect(last > first, 'the certified round moved between the first and the last sample', f'{first} -> {last}')
        declared = set(json.loads((self.gen / 'compose.yaml').read_text())['services']) - {'signer'}
        self.expect(all(set(x['services']) == declared and not x['missing'] and all(v['state'] == 'running' for v in x['services'].values()) for x in samples),
                    'every declared service (but the signer, not started) was seen running in every sample', str(sorted(declared - set(samples[0]['services']))))
        blocks = [x['gateway']['block'] for x in samples]
        self.expect(all(isinstance(b, int) for b in blocks), 'the gateway block was readable in every sample', str([x['gateway'] for x in samples][:2]))
        self.expect(blocks[-1] > blocks[0], 'the execution chain\'s block moved between the first and the last sample (an idle chain still produces blocks)', str(blocks))

    def pod_restart(self):
        """One validator entity at a time: stop its execution client, root and shard node (its signing authority stays live, as the README requires), check what the
        package promises, start them again and check they rejoin. The PUBLIC gateway fails closed while a validator is down (it checks every validator's identity
        before it serves or broadcasts): that is asserted, not worked around; the survivors are driven directly, as the gateway would fan out."""
        sender, to = self.manifest['faucet_address'], '0x' + '22' * 20
        for i in self.pods:
            names = [f'ureth{i}', f'root{i}', f'shard{i}']
            survivors = [j for j in range(1, self.n + 1) if j != i]
            self.say(f'  stopping validator {i}: {" ".join(names)}')
            self.compose('stop', *names)
            self.wait('the public gateway refuses while a validator is down (fail closed)', lambda: self.http(PUBLIC_RPC, 'GET', '/healthz')[0] == 503, 120)
            self.expect(True, f'validator {i} down: the public gateway fails closed (503), no partial broadcast')
            nonce = int(self.ureth(survivors[0], 'eth_getTransactionCount', [sender, 'latest']), 16)
            price = int(self.ureth(survivors[0], 'eth_gasPrice'), 16)
            raw = self.raw_tx(to, nonce, price)
            # the hash is the transaction's own (keccak of the raw bytes), not what a node answers: a survivor the transaction has already reached by gossip answers
            # "already known" with no result, which is acceptance of the same transaction; "nonce too low" counts only with the receipt (below); any other error is a refusal
            tx = self.cast_run('keccak', raw)
            for j in survivors:
                reply = self.inner_reply(f'http://ureth{j}:8545', 'eth_sendRawTransaction', [raw])
                error = str(reply.get('error', '')).lower()
                # "nonce too low" is acceptance only when this survivor already holds the transaction's receipt: the sends are sequential and a fast block can include it first
                known = 'already known' in error or ('nonce too low' in error and self.ureth(j, 'eth_getTransactionReceipt', [tx]) is not None)
                self.expect(reply.get('result') == tx or known, f'survivor {j} accepts the transaction', json.dumps(reply)[:200])
            self.say(f'  the {len(survivors)} survivors accept transaction {tx}')
            blocks = set()
            for j in survivors:
                r = self.wait(f'survivor {j} mines it with validator {i} down', lambda j=j: self.ureth(j, 'eth_getTransactionReceipt', [tx]), 240)
                self.expect(r['status'] == '0x1', f'survivor {j} has a successful receipt', r['blockHash'])
                blocks.add(r['blockHash'])
            self.expect(len(blocks) == 1, 'the survivors agree on the including block')
            self.say(f'  starting validator {i}')
            self.compose('start', *names)
            r = self.wait(f'validator {i} catches up to the transaction mined without it', lambda: self.ureth(i, 'eth_getTransactionReceipt', [tx]), 300)
            self.expect(r['blockHash'] in blocks, f'validator {i} has the same block after restart', r['blockHash'])
            self.wait('the public gateway is healthy again', lambda: self.http(PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 120)
            receipt = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '33' * 20))
            self.expect(receipt['status'] == '0x1', f'a transaction through the public gateway succeeds after validator {i} rejoined', receipt['transactionHash'])
            for j in range(1, self.n + 1):
                r = self.wait(f'validator {j} has it', lambda j=j: self.ureth(j, 'eth_getTransactionReceipt', [receipt['transactionHash']]), 120)
                self.expect(r['blockHash'] == receipt['blockHash'], f'validator {j} has it in the same block')

    def backup_restore(self):
        """Quiesced backup and same-generation restore (backup.py, README "Quiesced backup"): every non-authority service is stopped, the live authorities are
        recorded, the generation is archived, restored beside it with its authority mounts pointing at the surviving original directories, and started from there.
        Checks the history survived (a receipt from before the backup, on every validator), the network identity, the faucet pin, and that the network goes on."""
        backup = Path(__file__).with_name('backup.py')
        archive = self.gen.parent / 'backups' / (self.gen.name + '.tar.gz')
        archive.parent.mkdir(mode=0o700, exist_ok=True)
        restored = self.gen.parent / (self.gen.name + '-restored')
        marker = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '44' * 20))
        self.expect(marker['status'] == '0x1', 'a transaction before the backup', marker['transactionHash'])
        sender = self.manifest['faucet_address']
        nonce_before = int(self.call('eth_getTransactionCount', [sender, 'latest']), 16)
        out = subprocess.run([sys.executable, str(backup), 'backup', str(self.gen), str(archive)], check=True, text=True, capture_output=True).stdout
        self.say('  ' + out.strip())
        self.expect(archive.is_file() and archive.with_suffix('.gz.sha256').is_file(), 'the archive and its sha256 sidecar exist outside the generation')
        running = set(self.compose('ps', '--services', '--status', 'running').split())
        self.expect(running == {s for s in self.services() if s.startswith('authority')}, 'only the signing authorities run after the backup')
        out = subprocess.run([sys.executable, str(backup), 'restore', str(restored), str(archive), '--live-generation', str(self.gen)], check=True, text=True,
                             capture_output=True).stdout
        self.say('  ' + out.strip())
        subprocess.run(['chown', '-R', '10001:10001', str(restored)], check=True)
        self.gen = restored
        start = [s for s in self.services() if not s.startswith('authority') and s != 'signer']
        self.compose('up', '-d', '--no-deps', *start)
        self.wait('the public gateway is healthy from the restored generation', lambda: self.http(PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 600)
        self.identity()
        for i in range(1, self.n + 1):
            r = self.wait(f'validator {i} has the pre-backup receipt', lambda i=i: self.ureth(i, 'eth_getTransactionReceipt', [marker['transactionHash']]), 120)
            self.expect(r['blockHash'] == marker['blockHash'], f'validator {i} has it in the same block after the restore')
        self.expect(int(self.call('eth_getTransactionCount', [sender, 'latest']), 16) == nonce_before, 'the funded account nonce is what it was at the backup')
        s, text = self.http(FAUCET, 'GET', '/api/network')
        pin = json.loads(text) if s == 200 else {}
        self.expect(pin.get('genesis_hash', '').lower() == self.genesis, 'the faucet guard publishes the same network pin after the restore')
        after = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '55' * 20))
        self.expect(after['status'] == '0x1', 'a fresh transaction through the public gateway succeeds from the restored generation', after['transactionHash'])
        self.expect(int(after['blockNumber'], 16) > int(marker['blockNumber'], 16), 'it lands after the pre-backup block')
        for i in range(1, self.n + 1):
            r = self.wait(f'validator {i} has it', lambda i=i: self.ureth(i, 'eth_getTransactionReceipt', [after['transactionHash']]), 120)
            self.expect(r['blockHash'] == after['blockHash'], f'validator {i} has it in the same block')

    def reset(self):
        """The ASSET-LOSING arbitrary reset (reset.py, README): the old generation is destroyed and a fresh network with a new genesis identity is generated and
        started. Checks: a changed block-zero hash and funded account, the old network pin gets the wrong-network answer from the faucet guard (checked before
        the captcha), the old history is not on the new chain, and the new network serves a paid transfer. Needs the generator's own arguments (--reset-*)."""
        need = ('out', 'ubft', 'b1genesis', 'keygen', 'captcha_sitekey', 'captcha_secret_file')
        missing = [k for k in need if not self.reset_args.get(k)]
        if missing:
            raise Failure('the reset stage needs --reset-' + ', --reset-'.join(m.replace('_', '-') for m in missing))
        old, old_genesis, old_faucet, old_tx = self.gen, self.genesis, self.manifest['faucet_address'], getattr(self, 'tx', None)
        new = Path(self.reset_args['out'])
        a = self.reset_args
        out = subprocess.run([sys.executable, str(Path(__file__).with_name('reset.py')), '--old', str(old), '--lose-all-assets', '--', '--out', str(new),
                              '--validators', str(self.n), '--chain-id', str(self.chain_id), '--ubft', a['ubft'], '--b1genesis', a['b1genesis'], '--keygen', a['keygen'],
                              '--captcha-sitekey', a['captcha_sitekey'], '--captcha-secret-file', a['captcha_secret_file']], check=True, text=True, capture_output=True).stdout
        self.say('  ' + out.strip().splitlines()[-1])
        self.expect(not old.exists(), 'the old generation directory is gone')
        retired = old.with_suffix('.retired-manifest.json')
        self.expect(retired.is_file() and json.loads(retired.read_text())['genesis_hash'].lower() == old_genesis, 'the old public manifest was kept beside it')
        self.adopt(new)
        self.expect(self.genesis != old_genesis, 'the block-zero hash changed', f'{old_genesis[:12]}.. -> {self.genesis[:12]}..')
        self.expect(self.manifest['faucet_address'] != old_faucet, 'the funded (faucet) account is a new one')
        self.up()
        self.identity()
        if old_tx:
            for i in range(1, self.n + 1):
                self.expect(self.ureth(i, 'eth_getTransactionReceipt', [old_tx['transactionHash']]) is None, f'validator {i} does not have the old network\'s transaction')
        ip = {'X-Forwarded-For': PROXY_IPS[0] + '50', 'Content-Type': 'application/json'}
        self.compose('up', '-d', '--no-deps', 'faucet')
        self.wait('the faucet guard answers', lambda: self.http(FAUCET, 'GET', '/api/network')[0] == 200, 120)
        s, text = self.http(FAUCET, 'POST', '/api/claim', json.dumps({'address': '0x' + '11' * 20, 'chain_id': self.chain_id, 'genesis_hash': old_genesis}).encode(), ip)
        self.expect(s == 409, 'a wallet pinned to the old genesis gets the wrong-network answer', f'status {s}')
        s, text = self.http(FAUCET, 'POST', '/api/claim', json.dumps({'address': '0x' + '11' * 20, 'chain_id': self.chain_id, 'genesis_hash': self.genesis}).encode(), ip)
        self.expect(s == 400 and 'hCaptcha' in text, 'a wallet on the new pin passes the network check and stops at the captcha (the signer is not started)', f'status {s}')
        pin = json.loads(self.http(FAUCET, 'GET', '/api/network')[1])
        self.expect(pin['genesis_hash'].lower() == self.genesis, 'the faucet guard publishes the new pin')
        receipt = json.loads(self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '66' * 20))
        self.expect(receipt['status'] == '0x1', 'a paid transfer on the new network succeeds', receipt['transactionHash'])
        self.say('  note the old generation\'s surviving authority directories (the restore pointed at them) are left on disk by reset.py; a host removes them by hand')

STAGES = (('up', 'up'), ('identity', 'identity'), ('first-tx', 'first_tx'), ('gateway-limits', 'gateway_limits'), ('faucet-guard', 'faucet_guard'), ('load', 'load'), ('observe', 'observe'), ('pod-restart', 'pod_restart'), ('backup-restore', 'backup_restore'), ('reset', 'reset'))
# run on a generation made with --pos (the workflow's second generation); not part of the default list
Rehearsal.pos_observe = pos_sample.pos_observe   # the sampler smoke lives in pos_sample.py
Rehearsal.pos_joiner = pos_join.pos_joiner   # the joiner stage lives in pos_join.py; it is not in the default list (it needs its own fresh generation)
Rehearsal.pos_owner = pos_owner.pos_owner   # the owner-key stage lives in pos_owner.py
POS_STAGES = (('pos-smoke', 'pos_smoke'), ('pos-observe', 'pos_observe'), ('pos-rewards', 'pos_rewards'), ('pos-election', 'pos_election'), ('pos-proposal', 'pos_proposal'), ('pos-abort', 'pos_abort'), ('pos-propose', 'pos_propose'), ('pos-too-late', 'pos_too_late'), ('pos-install', 'pos_install'), ('pos-advance', 'pos_advance'), ('pos-restart', 'pos_restart'), ('pos-stale', 'pos_stale'), ('pos-handoff-2', 'pos_handoff_2'), ('pos-restart-2', 'pos_restart_2'), ('pos-recreate', 'pos_recreate'), ('pos-owner', 'pos_owner'), ('pos-joiner', 'pos_joiner'))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--pods', default='2,1', help='validator entities pod-restart stops and restarts, one at a time, in this order')
    for name in ('out', 'ubft', 'b1genesis', 'keygen', 'captcha-sitekey', 'captcha-secret-file'):
        p.add_argument('--reset-' + name, help='the reset stage passes this to generate.py as --' + name + ' (--out: the new generation directory)')
    p.add_argument('--ubft', type=Path, help='the pinned ubft binary, for the handoff stages (they write and read files with it)')
    p.add_argument('--stages', default=','.join(s for s, _ in STAGES), help='comma separated, in order (the default is the PoA stages; POS_STAGES are named explicitly)')
    a = p.parse_args()
    r = Rehearsal(a.generation, a.evidence, a.cast)
    r.ubft = a.ubft.resolve() if a.ubft else None
    r.pods = tuple(int(x) for x in a.pods.split(',') if x)
    r.reset_args = {k[len('reset_'):]: v for k, v in vars(a).items() if k.startswith('reset_')}
    wanted = a.stages.split(',')
    unknown = set(wanted) - {s for s, _ in STAGES + POS_STAGES}
    if unknown:
        p.error(f'unknown stages {sorted(unknown)}')
    code = 0
    try:
        for name, method in STAGES + POS_STAGES:
            if name in wanted:
                r.stage(name, getattr(r, method))
    except Exception:
        code = 1
    finally:
        r.say('RESULT ' + ' '.join(f'{n}={s}' for n, s, _ in r.results))
        (a.evidence / 'result.json').write_text(json.dumps({'generation': r.gen.name, 'stages': r.results}, indent=2) + '\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
