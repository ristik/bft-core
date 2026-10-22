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
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

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
        """JSON-RPC to a validator's execution client from inside the validator network (the rpc container has python, ureth has no curl)."""
        code = ('import json,sys,urllib.request as u;'
                'r=u.Request(sys.argv[1],json.dumps({"jsonrpc":"2.0","id":1,"method":sys.argv[2],"params":json.loads(sys.argv[3])}).encode(),{"Content-Type":"application/json"});'
                'print(u.urlopen(r,timeout=10).read().decode())')
        out = self.compose('exec', '-T', 'rpc', 'python3', '-c', code, url, method, json.dumps(list(params)))
        return json.loads(out).get('result')

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
        self.expect(s in (400, 0), 'a body over 16 KiB is refused', f'status {s} {text[:40] if s == 0 else ""}')
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
        function = signature.split(')(')[0] + ')'
        data = self.cast_run('calldata', function, *args)
        raw = self.call('eth_call', [{'to': to, 'data': data}, 'latest'])
        return [int(line.split()[0]) for line in self.cast_run('abi-decode', signature, raw).splitlines()]

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

    def relayer(self, key_file, *args):
        """`ubft pos-relayer tx ...` in a one-shot container on the validators network: the public gateway has no X-Forwarded-For from a host client and the relayer
        sends each transaction to every validator (their pools do not gossip), so it talks to the execution clients directly. The key is copied to a directory only
        uid 10001 can read, mounted read-only, and removed afterwards; the container has the node image's limits (read-only, no capabilities, bounded). The
        relayer's own output is returned: (exit status, stderr)."""
        services = json.loads((self.gen / 'compose.yaml').read_text())['services']
        project = json.loads((self.gen / 'compose.yaml').read_text())['name']
        network = subprocess.run(['docker', 'network', 'ls', '-q', '--filter', f'label=com.docker.compose.project={project}',
                                  '--filter', 'label=com.docker.compose.network=validators'], check=True, text=True, capture_output=True).stdout.split()
        self.expect(len(network) == 1, 'the generation has one validators network', str(network))
        staging = Path(tempfile.mkdtemp(prefix='tn-relayer-key-'))
        try:
            key = staging / 'key'
            key.write_text(Path(key_file).read_text())
            for path, mode in ((key, 0o400), (staging, 0o500)):
                os.chown(path, 10001, 10001)
                os.chmod(path, mode)
            urls = ','.join(f'http://ureth{i}:8545' for i in range(1, self.n + 1))
            run = subprocess.run(['docker', 'run', '--rm', '--network', network[0], '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
                                  '--security-opt', 'no-new-privileges', '--memory', '256m', '--pids-limit', '128', '--tmpfs', '/tmp', '-e', 'HOME=/tmp',
                                  '-v', f'{staging}:/key:ro', '-v', f'{self.gen / "network" / "pos-deployment.json"}:/deployment.json:ro',
                                  services['root1']['image'], 'pos-relayer', 'tx', *args, '--eth-rpc', urls, '--pos-deployment', '/deployment.json',
                                  '--sender-key', '/key/key'], text=True, capture_output=True)
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
            hashes = {self.ureth(j, 'eth_sendRawTransaction', [raw]) for j in survivors}
            self.expect(len(hashes) == 1, f'the {len(survivors)} survivors accept the same transaction', next(iter(hashes)))
            tx = next(iter(hashes))
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

STAGES = (('up', 'up'), ('identity', 'identity'), ('first-tx', 'first_tx'), ('gateway-limits', 'gateway_limits'), ('faucet-guard', 'faucet_guard'), ('load', 'load'), ('pod-restart', 'pod_restart'), ('backup-restore', 'backup_restore'), ('reset', 'reset'))
# run on a generation made with --pos (the workflow's second generation); not part of the default list
POS_STAGES = (('pos-smoke', 'pos_smoke'), ('pos-rewards', 'pos_rewards'))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--pods', default='2,1', help='validator entities pod-restart stops and restarts, one at a time, in this order')
    for name in ('out', 'ubft', 'b1genesis', 'keygen', 'captcha-sitekey', 'captcha-secret-file'):
        p.add_argument('--reset-' + name, help='the reset stage passes this to generate.py as --' + name + ' (--out: the new generation directory)')
    p.add_argument('--stages', default=','.join(s for s, _ in STAGES), help='comma separated, in order (the default is the PoA stages; POS_STAGES are named explicitly)')
    a = p.parse_args()
    r = Rehearsal(a.generation, a.evidence, a.cast)
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
