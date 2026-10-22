#!/usr/bin/env python3
"""Bridge stages of the container-package rehearsal (TN-B #429/#438, briefs/tnb-without-host.md), on a generation that rehearse.py brought up.

    rehearse_bridge.py --generation GEN --evidence DIR [--stages deploy,lockproof]

  deploy     deploy_bridge.py (TokenVerifier + BridgeVault after genesis, signed with the faucet keystore) and overlay.py (compose.bridge.yaml)
  lockproof  the lock-proof endpoint: a lock through the public gateway, its proof over HTTP equal to `dnb-tool lockproof`'s bytes, malformed (400),
             unknown nonce (404), rate limit (429), the endpoint replaced on another validator's archive serving the same bytes, and a lock older than
             ureth's proof window refused as not found (404)
Evidence of the package only, as rehearse.py's. No third-party service is contacted.
"""
import argparse
import http.client
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from rehearse import PROXY_IPS, Failure, Rehearsal   # noqa: E402  (the package's recorder and helpers)

ENDPOINT = '127.0.0.1:8090'
# a valid first-owner predicate (a signature predicate), the corpus' history/prepare-valid input: the vault's prepareLock refuses a malformed one
P0 = 'd99878830141015821027cc4b4654f1c21a87f2d036eeb6cceeba9d387969e998311708309966a25749d'
LOCK_WEI = 10 ** 15
PROOF_WINDOW = 64   # generate.py: ureth --rpc.eth-proof-window


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

    # --- stages ----------------------------------------------------------------------------------------------------------------
    def deploy(self):
        # the package's one aggregator (aggregator-go, partition 9, one shard: owner decision 40); the lock side and the lock-proof endpoint do not depend
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


STAGES = (('deploy', 'deploy'), ('lockproof', 'lockproof'))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--stages', default=','.join(s for s, _ in STAGES), help='comma separated, in order')
    a = p.parse_args()
    r = BridgeRehearsal(a.generation, a.evidence, a.cast)
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
