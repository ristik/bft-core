#!/usr/bin/env python3
"""Bridge stages of the container-package rehearsal (TN-B #429/#438, briefs/tnb-without-host.md), on a generation that rehearse.py brought up.

    rehearse_bridge.py --generation GEN --evidence DIR [--stages deploy,lockproof,fund,roundtrip,negatives,consolidated,long-history,backup-restore]

  deploy     deploy_bridge.py (TokenVerifier + BridgeVault after genesis, signed with the faucet keystore) and overlay.py (compose.bridge.yaml)
  lockproof  the lock-proof endpoint: a lock through the public gateway, its proof over HTTP equal to `dnb-tool lockproof`'s bytes, malformed (400),
             unknown nonce (404), rate limit (429), the endpoint replaced on another validator's archive serving the same bytes, and a lock older than
             ureth's proof window refused as not found (404)
  fund       a driver key of this generation (GENERATION/bridge/driver.env, never in the evidence) funded from the faucet; the driver funds its own recipient and
             submitter from it
  roundtrip  the native-bridge-plugins live driver (tests/live/anyage.ts) in the bridge tools image: lock, its proof from validator 1's archive, mint, SAVE_TRANSFERS
             transfers and the burn certified by the package's aggregator, the return proof saved and verified (eth_call), then the redemption and the claim with
             one validator stopped, which rejoins with the same blocks; the vault's balance follows every step (custody)
  negatives  on chain, after the round trip: the same envelope redeemed again and the claim repeated are both refused, and the vault keeps the nullifier
  tester     the bridge tester CLI (native-bridge-plugins tester/) as a tester runs it, with its own faucet-funded key and GENERATION/bridge/public/tester-config.json:
             init, lock, mint (the proof from the lock-proof endpoint), two transfers, burn, redeem, claim and status; a repeated step is refused; the vault
             pays back exactly what the tester locked
  consolidated, long-history
             the driver's consolidated redeem (K = 1 anchor on the unsharded aggregator, the per-SID envelope priced as the control) and its long history
             (LONG_TRANSFERS transfers, one gas short reverts and leaves the vault unchanged, then redeemed and claimed)
  backup-restore
             the quiesced backup and same-generation restore (rehearse.py) with the bridge deployed: the redeemed lock stays spent, and a new round trip completes on
             the restored generation
Evidence of the package only, as rehearse.py's. No third-party service is contacted.
"""
import argparse
import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from rehearse import PROXY_IPS, Failure, Rehearsal   # noqa: E402  (the package's recorder and helpers)
from deploy_bridge import TAG, validators_network   # noqa: E402

ENDPOINT = '127.0.0.1:8090'
# a valid first-owner predicate (a signature predicate), the corpus' history/prepare-valid input: the vault's prepareLock refuses a malformed one
P0 = 'd99878830141015821027cc4b4654f1c21a87f2d036eeb6cceeba9d387969e998311708309966a25749d'
LOCK_WEI = 10 ** 15
PROOF_WINDOW = 64   # generate.py: ureth --rpc.eth-proof-window
DRIVER = 'tests/live/anyage.ts'   # in the image's native-bridge-plugins checkout (its WORKDIR)
DRIVER_FUNDS = 30 * 10 ** 18   # each driver token locks 1 ETH and gives its recipient and submitter 1 ETH each
# the driver's fixed recipient, submitter and payee (tests/live/anyage.ts)
RECIPIENT, SUBMITTER, PAYEE = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', '0x000000000000000000000000000000000000bEEF'
GATEWAY_MAX_BODY = 16384   # gateway.py MAX_BODY
# One aggregator answers at most 256 state IDs in one batch (the SDK's BATCH_MAX_STATE_IDS), and the long history's batch holds the mint, every
# transfer and the burn, so with the single aggregator-go it has at most 254 transfers; the driver also requires more than 64 (the former bound).
LONG_TRANSFERS_MAX = 254
# BridgeVault's custom errors at the contracts pin: AlreadyRedeemed(uint256), InsufficientCredit(uint256,uint256)
ALREADY_REDEEMED, INSUFFICIENT_CREDIT = '0xd36d946d', '0x4eb7eaec'
TESTER = 'tester/bridge-tester.ts'   # in the image's native-bridge-plugins checkout
TESTER_FUNDS, TESTER_LOCK_WEI = 2 * 10 ** 18, 5 * 10 ** 17


class BridgeRehearsal(Rehearsal):
    def bridge_compose(self, *args, check=True):
        return subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), '-f', str(self.gen / 'compose.bridge.yaml'), *args],
                              check=check, text=True, capture_output=True).stdout

    def addresses(self):
        return json.loads((self.gen / 'bridge/bridge-addresses.json').read_text())

    def proof(self, block, nonce, ip=PROXY_IPS[0] + '30', path=None):
        """(status, body bytes) of one endpoint request, as the host's nginx would forward it."""
        conn = http.client.HTTPConnection(ENDPOINT, timeout=40)
        try:
            conn.request('GET', path or f'/v1/lockproof?block={block}&nonce={nonce}', headers={'X-Forwarded-For': ip})
            response = conn.getresponse()
            return response.status, response.read()
        except OSError as error:
            return 0, type(error).__name__.encode()
        finally:
            conn.close()

    def lock(self):
        """One lock through the public gateway: signed offline with the faucet keystore, as rehearse.py's first transaction. Returns (nonce, block hash, block number)."""
        vault = self.addresses()['BridgeVault']
        secrets = self.gen / 'faucet-secrets'
        sender = self.manifest['faucet_address']
        nonce = int(self.call('eth_getTransactionCount', [sender, 'latest']), 16)
        price = int(self.call('eth_gasPrice'), 16)
        raw = self.cast_run('mktx', '--keystore', str(secrets / 'keystore.json'), '--password-file', str(secrets / 'password'), '--legacy', '--nonce', str(nonce),
                            '--gas-price', str(price), '--gas-limit', '2000000', '--chain', str(self.chain_id), '--value', str(LOCK_WEI), vault, 'lock(bytes)', '0x' + P0)
        sent = self.call('eth_sendRawTransaction', [raw])
        receipt = self.wait('the lock is mined', lambda: self.call('eth_getTransactionReceipt', [sent]), 180)
        self.expect(receipt['status'] == '0x1', 'the lock succeeded', json.dumps(receipt)[:600])
        locked = [log for log in receipt['logs'] if log['address'].lower() == vault.lower() and len(log['topics']) == 3]
        self.expect(len(locked) == 1, 'the vault emitted one Locked event')
        return int(locked[0]['topics'][1], 16), receipt['blockHash'], int(receipt['blockNumber'], 16)

    def cli_proof(self, block, nonce, validator):
        """The reference bytes: `dnb-tool lockproof` run once in the endpoint's image and mounts, on VALIDATOR's archive and execution client."""
        a = self.addresses()
        out = subprocess.run(['docker', 'compose', '-f', str(self.gen / 'compose.yaml'), '-f', str(self.gen / 'compose.bridge.yaml'), 'run', '--rm', '--no-deps',
                              '-v', f'./validator{validator}/archive:/archive{validator}:ro', '--entrypoint', 'dnb-tool', 'lockproof', 'lockproof',
                              '--archive', f'/archive{validator}', '--block-hash', block, '--eth-url', f'http://ureth{validator}:8545', '--vault', a['BridgeVault'],
                              '--nonce', str(nonce), '--full-shard-conf', '/network/full-shard-conf.json', '--trust-bundle', '/bridge/trust-base.bundle.cbor',
                              '--cfg', a['CFG'], '--out', '/dev/stdout'], check=True, capture_output=True, cwd=self.gen)
        return out.stdout

    def start_endpoint(self, validator):
        subprocess.run([sys.executable, str(HERE / 'overlay.py'), str(self.gen), '--archive-of', str(validator)], check=True, capture_output=True)
        self.bridge_compose('up', '-d', '--no-deps', '--force-recreate', 'lockproof')
        self.wait('the lock-proof endpoint is healthy', lambda: self.http(ENDPOINT, 'GET', '/healthz')[0] == 200, 60)

    def driver(self, *args, transfers=None):
        """One command of the live driver in the bridge tools image, on the validators network, as the tools user: GENERATION/bridge at /work (its lane-config.json
        names /work and /archive), validator 1's certified-block archive read-only at /archive. Returns its output; a failing command fails the stage."""
        env = ['-e', f'SAVE_TRANSFERS={transfers}', '-e', f'LONG_TRANSFERS={transfers}'] if transfers is not None else []
        out = subprocess.run(['docker', 'run', '--rm', '--read-only', '--network', validators_network(self.gen), '--user', '10001:10001',
                              '--env-file', str(self.gen / 'bridge/driver.env'), '-e', 'HOME=/tmp/home', *env, '--tmpfs', '/tmp',
                              '-v', f'{self.gen / "bridge"}:/work', '-v', f'{self.gen / "validator1/archive"}:/archive:ro',
                              TAG, 'npx', '--no-install', 'tsx', DRIVER, *args], text=True, capture_output=True)
        self.say('  ' + '\n  '.join((out.stdout + out.stderr).strip().splitlines()[-25:]))
        if out.returncode != 0:
            raise Failure(f'the driver failed: {args[0]}')
        return out.stdout

    def tester(self, *args, check=True):
        """One command of the bridge tester CLI in the bridge tools image, on the validators network, with its wallet at /work/tester-wallet. The tester has
        no driver key and no archive: only its own key file and the published directory (bridge/public). Returns (exit code, output)."""
        out = subprocess.run(['docker', 'run', '--rm', '--read-only', '--network', validators_network(self.gen), '--user', '10001:10001', '-e', 'HOME=/tmp/home',
                              '--tmpfs', '/tmp', '-v', f'{self.gen / "bridge"}:/work', TAG, 'npx', '--no-install', 'tsx', TESTER, *args, '--wallet', '/work/tester-wallet'],
                             text=True, capture_output=True)
        text = (out.stdout + out.stderr).strip()
        self.say('  $ bridge-tester ' + ' '.join(args) + '\n    ' + '\n    '.join(text.splitlines()[-12:]))
        if check and out.returncode != 0:
            raise Failure(f'the tester failed: {args[0]}')
        return out.returncode, text

    def vault_balance(self):
        return int(self.call('eth_getBalance', [self.addresses()['BridgeVault'], 'latest']), 16)

    def inner_response(self, i, method, params):
        """The whole JSON-RPC response (result or error) of validator I's execution client, from inside the validator network."""
        code = ('import json,sys,urllib.request as u;'
                'r=u.Request(sys.argv[1],json.dumps({"jsonrpc":"2.0","id":1,"method":sys.argv[2],"params":json.loads(sys.argv[3])}).encode(),{"Content-Type":"application/json"});'
                'print(u.urlopen(r,timeout=30).read().decode())')
        return json.loads(self.compose('exec', '-T', 'rpc', 'python3', '-c', code, f'http://ureth{i}:8545', method, json.dumps(list(params))))

    def keep(self, run, *names):
        for name in names:
            src = self.gen / 'bridge' / run / name
            if src.is_file():
                (self.evidence / run).mkdir(parents=True, exist_ok=True)
                (self.evidence / run / name).write_bytes(src.read_bytes())

    def round_trip(self, run, transfers, down=None):
        """save, verify (current epoch), release; with DOWN, validator DOWN is stopped for the release and must rejoin with the redemption's and the claim's blocks."""
        before = self.vault_balance()
        self.driver('save', '/work/lane-config.json', f'/work/{run}', transfers=transfers)
        saved = json.loads((self.gen / 'bridge' / run / 'saved.json').read_text())
        self.expect(saved.get('transfers', 0) == transfers, f'the token carries {transfers} live transfers', str(saved.get('transfers')))
        amount = int(saved['amountWei'])
        self.expect(self.vault_balance() == before + amount, 'the vault holds the locked amount (custody)', f'{before} + {amount}')
        bytes_ = saved['envelope']['bytes']
        fits = 2 * bytes_ + 1024 < GATEWAY_MAX_BODY
        self.say(f'  NOTE the return proof is {bytes_} bytes: a redeem transaction carrying it {"fits" if fits else "does NOT fit"} the public gateway\'s {GATEWAY_MAX_BODY}-byte body limit')
        self.driver('verify', '/work/lane-config.json', f'/work/{run}/saved.json', '--epoch', 'current')
        names = [f'ureth{down}', f'root{down}', f'shard{down}'] if down else []
        if down:
            self.say(f'  stopping validator {down} for the redemption and the claim: {" ".join(names)}')
            self.compose('stop', *names)
        try:
            self.driver('release', '/work/lane-config.json', f'/work/{run}/saved.json')
        finally:
            if down:
                self.compose('start', *names)
        released = json.loads((self.gen / 'bridge' / run / 'release.json').read_text())
        if down:
            for what in ('redeem', 'claim'):
                tx = released[what]['tx']
                mined = self.ureth(1, 'eth_getTransactionReceipt', [tx])
                r = self.wait(f'validator {down} has the {what} after it rejoined', lambda tx=tx: self.ureth(down, 'eth_getTransactionReceipt', [tx]), 300)
                self.expect(r['blockHash'] == mined['blockHash'], f'validator {down} has the {what} in the same block', r['blockHash'])
            # the public gateway fails closed while a validator is down (rehearse.py pod-restart)
            self.wait('the public gateway is healthy again', lambda: self.http('127.0.0.1:8545', 'GET', '/healthz')[0] == 200, 120)
        self.expect(self.vault_balance() == before, 'the vault paid out exactly the locked amount (custody back to where it was)', str(self.vault_balance()))
        self.keep(run, 'saved.json', 'verify-current.json', 'release.json')
        return saved, released

    # --- stages ----------------------------------------------------------------------------------------------------------------
    def deploy(self):
        # the package's one aggregator (aggregator-go, partition 7, one shard: owner decision 40); the lock side and the lock-proof endpoint do not depend
        # on it, the mint/redeem stages (part 2) will
        out = subprocess.run([sys.executable, str(HERE / 'deploy_bridge.py'), str(self.gen), '--agg-conf', 'network/aggregator-conf.json',
                              '--agg-url', 'http://aggregator:8080'], text=True, capture_output=True)
        self.say(out.stdout[-2000:] + out.stderr[-2000:])
        if out.returncode != 0:
            raise Failure('deploy_bridge.py failed')
        a = self.addresses()
        for name in ('BridgeVault', 'TokenVerifier'):
            code = self.call('eth_getCode', [a[name], 'latest'])
            self.expect(code not in (None, '0x'), f'{name} has code at {a[name]} (read through the public gateway)')
        self.expect(len(a['CFG']) == 66 and int(a['CFG'], 16) != 0, 'the vault reports its CFG', a['CFG'])
        for name in ('bridge-deployment.json', 'bridge-addresses.json', 'vault-deploy.log', 'lane-config.json'):
            (self.evidence / name).write_bytes((self.gen / 'bridge' / name).read_bytes())

    def lockproof(self):
        self.start_endpoint(1)
        nonce, block, number = self.lock()
        self.say(f'  lock nonce {nonce} in block {number} {block}')
        status, body = self.wait('the endpoint serves the lock\'s proof (its block certified and archived)',
                                 lambda: (lambda r: r if r[0] == 200 else None)(self.proof(block, nonce)), 180)
        reference = self.cli_proof(block, nonce, 1)
        self.expect(body == reference, 'the endpoint serves exactly `dnb-tool lockproof`\'s bytes', f'{len(body)} bytes')
        (self.evidence / f'lockproof-{nonce}.cbor').write_bytes(body)

        ip = PROXY_IPS[1] + '31'
        for what, path in (('no nonce', f'/v1/lockproof?block={block}'), ('a short block hash', f'/v1/lockproof?block={block[:-2]}&nonce={nonce}'),
                           ('a zero nonce', f'/v1/lockproof?block={block}&nonce=0')):
            s, _ = self.proof(block, nonce, ip, path)
            self.expect(s == 400, f'{what} is refused as malformed', f'status {s}')
            time.sleep(1.1)   # one request per window: these are not the rate-limit case
        s, text = self.proof(block, nonce + 1000)
        self.expect(s == 404, 'a nonce with no lock at that block is not found', f'status {s} {text[:120]!r}')
        burst = [self.proof(block, nonce, PROXY_IPS[1] + '32')[0] for _ in range(4)]
        self.expect(burst.count(429) >= 1 and burst[0] == 200, 'one client\'s burst is rate limited (2 per second)', str(burst))

        # replacement: the endpoint holds no state, so a new one on another validator's archive serves the same proof
        other = 2 if self.n >= 2 else 1
        self.bridge_compose('rm', '-sf', 'lockproof')
        self.expect(self.proof(block, nonce)[0] == 0, 'with the endpoint stopped nothing answers')
        self.start_endpoint(other)
        time.sleep(1.1)
        s, again = self.proof(block, nonce)
        self.expect(s == 200 and again == body, f'a replacement endpoint on validator {other}\'s archive serves the same bytes', f'status {s}')
        self.expect(self.cli_proof(block, nonce, other) == body, f'validator {other}\'s archive gives the CLI the same bytes')

        # past ureth's proof window the proof can no longer be built: a clear not-found, not a server error
        def past_window():
            if int(self.call('eth_blockNumber'), 16) > number + PROOF_WINDOW + 2:
                return True
            self.send_via_gateway(self.gen / 'faucet-secrets', '0x' + '11' * 20)   # a block per transaction: the head must move, whatever the cadence of empty rounds
            return False
        self.wait(f'the head passes the lock by more than the proof window ({PROOF_WINDOW})', past_window, 1200)
        time.sleep(1.1)
        s, text = self.proof(block, nonce)
        self.expect(s == 404, 'a lock older than the proof window is not found (fetch the proof soon after locking)', f'status {s} {text[:160]!r}')
        self.start_endpoint(1)   # leave the endpoint on validator 1, as overlay.py's default

    def fund(self):
        env = self.gen / 'bridge/driver.env'
        if not env.exists():
            env.touch()
            os.chmod(env, 0o600)   # the driver's key: owner only, whatever the umask
            env.write_text(f'DNB_DEPLOYER_KEY=0x{secrets.token_hex(32)}\n')
        key = env.read_text().split('=', 1)[1].strip()
        address = self.cast_run('wallet', 'address', '--private-key', key)
        if self.balance(address) < DRIVER_FUNDS // 2:
            self.faucet_send(address, DRIVER_FUNDS)
        self.expect(self.balance(address) >= DRIVER_FUNDS // 2, f'the driver account {address} is funded from the faucet', str(self.balance(address)))

    def roundtrip(self):
        self.round_trip('roundtrip', 3, down=self.n if self.n >= 4 else None)

    def negatives(self):
        run = self.gen / 'bridge/roundtrip'
        saved = json.loads((run / 'saved.json').read_text())
        envelope = (run / 'envelope.bin').read_bytes()
        vault = self.addresses()['BridgeVault']
        data = '0x9945e3d3' + (32).to_bytes(32, 'big').hex() + len(envelope).to_bytes(32, 'big').hex() + envelope.hex() + '00' * (-len(envelope) % 32)
        word = lambda n: int(n).to_bytes(32, 'big').hex()
        r = self.inner_response(1, 'eth_call', [{'from': SUBMITTER, 'to': vault, 'data': data}, 'latest'])
        self.expect((r.get('error') or {}).get('data') == ALREADY_REDEEMED + word(saved['nonce']),
                    'the redeemed envelope is refused a second time (AlreadyRedeemed of its nonce)', json.dumps(r)[:300])
        spent = self.inner_response(1, 'eth_call', [{'to': vault, 'data': self.cast_run('calldata', 'spentNullifier(uint256)', str(saved['nonce']))}, 'latest'])
        self.expect(spent.get('result', '').lower().removeprefix('0x') == saved['nullifier'].lower().removeprefix('0x'), 'the vault keeps the lock\'s nullifier', spent.get('result', ''))
        claim = self.cast_run('calldata', 'claim(uint256,address)', str(saved['amountWei']), PAYEE)
        r = self.inner_response(1, 'eth_call', [{'from': RECIPIENT, 'to': vault, 'data': claim}, 'latest'])
        self.expect((r.get('error') or {}).get('data') == INSUFFICIENT_CREDIT + word(0) + word(saved['amountWei']),
                    'the claim of an already claimed credit is refused (InsufficientCredit: none left)', json.dumps(r)[:300])

    def tester_stage(self):
        work = self.gen / 'bridge'
        shutil.rmtree(work / 'tester-wallet', ignore_errors=True)   # this stage's own wallet: a new one on every run
        key_file = work / 'tester.key'
        key = f'0x{secrets.token_hex(32)}'
        key_file.write_text(key + '\n')
        os.chmod(key_file, 0o600)
        if os.getuid() == 0:
            os.chown(key_file, 10001, 10001)   # read by the tester as the tools user
        me = self.cast_run('wallet', 'address', '--private-key', key)
        self.faucet_send(me, TESTER_FUNDS)
        self.tester('init', '--config', '/work/public/tester-config.json', '--eth-key-file', '/work/tester.key')
        before = self.vault_balance()
        self.tester('lock', '--amount', f'{TESTER_LOCK_WEI}wei')
        self.expect(self.vault_balance() == before + TESTER_LOCK_WEI, 'the vault holds what the tester locked', str(self.vault_balance() - before))
        self.tester('mint')
        code, text = self.tester('mint', check=False)
        self.expect(code != 0 and 'that step is done' in text, 'a second mint of the same token is refused by the tester', text.splitlines()[-1] if text else '')
        self.tester('transfer', '--count', '2')
        self.tester('burn')
        self.tester('redeem')
        record = json.loads(next((work / 'tester-wallet/tokens').glob('*/token.json')).read_text())
        self.expect(record['phase'] == 'redeemed' and record['transfers'] == 2 and record['recipient'].lower() == me.lower(),
                    'the tester redeemed its token after two transfers, to its own address', json.dumps(record))
        credit = int(self.inner_response(1, 'eth_call', [{'to': self.addresses()['BridgeVault'], 'data': self.cast_run('calldata', 'claimable(address)', me)}, 'latest'])['result'], 16)
        self.expect(credit == TESTER_LOCK_WEI, 'the redemption credits the tester exactly the locked amount', str(credit))
        self.tester('claim')
        self.expect(self.vault_balance() == before, 'the vault paid back exactly what the tester locked (custody back to where it was)', str(self.vault_balance()))
        _, text = self.tester('status')
        self.expect('vault credit 0 wei' in text and 'redeemed, ' in text, 'status shows no credit left and the token redeemed in the vault', text.splitlines()[-1])
        key_file.unlink()
        self.keep_tester()

    def keep_tester(self):
        out = self.evidence / 'tester'
        out.mkdir(parents=True, exist_ok=True)
        for f in (self.gen / 'bridge/tester-wallet/tokens').glob('*/token.json'):
            shutil.copy(f, out / f'token-{f.parent.name}.json')
        shutil.copy(self.gen / 'bridge/public/tester-config.json', out / 'tester-config.json')

    def consolidated(self):
        self.driver('consolidated', '/work/lane-config.json', '/work/consolidated')
        self.keep('consolidated', 'consolidated.json')

    def long_history(self):
        self.driver('long-history', '/work/lane-config.json', '/work/long-history', transfers=self.long_transfers)
        self.keep('long-history', 'long-history.json')

    def backup_restore(self):
        nonce = json.loads((self.gen / 'bridge/roundtrip/saved.json').read_text())['nonce']
        self.bridge_compose('rm', '-sf', 'lockproof')   # quiesced: the overlay's service stops too
        # backup.py restores plain files and directories only (sockets are left out of the archive): name anything else here, before the backup
        odd = [str(f.relative_to(self.gen)) for f in self.gen.rglob('*') if not f.name.endswith(('.sock', '.sock.lock')) and (f.is_symlink() or not (f.is_file() or f.is_dir()))]
        self.expect(not odd, 'the generation holds only plain files and directories (backup.py restores nothing else)', ' '.join(odd[:20]))
        try:
            super().backup_restore()
        except subprocess.CalledProcessError as e:
            self.say(f'  {" ".join(map(str, e.cmd[1:3]))} failed: {(e.stderr or "").strip()[-2000:]}')
            raise
        vault = self.addresses()['BridgeVault']
        self.expect(self.call('eth_getCode', [vault, 'latest']) not in (None, '0x'), 'the vault is there on the restored generation')
        spent = self.inner_response(1, 'eth_call', [{'to': vault, 'data': self.cast_run('calldata', 'spentNullifier(uint256)', str(nonce))}, 'latest'])
        self.expect(int(spent.get('result') or '0x0', 16) != 0, 'the lock redeemed before the backup stays spent')
        self.round_trip('after-restore', 0)
        self.start_endpoint(1)


STAGES = (('deploy', 'deploy'), ('lockproof', 'lockproof'), ('fund', 'fund'), ('roundtrip', 'roundtrip'), ('negatives', 'negatives'), ('tester', 'tester_stage'),
          ('consolidated', 'consolidated'), ('long-history', 'long_history'), ('backup-restore', 'backup_restore'))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--stages', default=','.join(s for s, _ in STAGES), help='comma separated, in order')
    p.add_argument('--long-transfers', type=int, default=250, help=f'the long-history token\'s transfers (65 to {LONG_TRANSFERS_MAX})')
    a = p.parse_args()
    if not 64 < a.long_transfers <= LONG_TRANSFERS_MAX:
        p.error(f'--long-transfers must be 65 to {LONG_TRANSFERS_MAX}: one aggregator batch holds 256 state IDs')
    r = BridgeRehearsal(a.generation, a.evidence, a.cast)
    r.long_transfers = a.long_transfers
    wanted = a.stages.split(',')
    unknown = set(wanted) - {s for s, _ in STAGES}
    if unknown:
        p.error(f'unknown stages {sorted(unknown)}')
    code = 0
    try:
        for name, method in STAGES:
            if name in wanted:
                r.stage(name, getattr(r, method))
    except Exception:
        code = 1
    finally:
        r.say('RESULT ' + ' '.join(f'{n}={s}' for n, s, _ in r.results))
        (a.evidence / 'bridge-result.json').write_text(json.dumps({'generation': r.gen.name, 'stages': r.results}, indent=2) + '\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
