#!/usr/bin/env python3
"""Native bridge v2 stages of the package lanes (NB2-09, bft-core#1105), on a generation that rehearse.py brought up. They replace the protocol 6/7
bridge stages of testnet-bridge and testnet-bridge-pos (README.md "The rehearsal stages"); the vault is the test build with K = 4, B = 2, so segments
rotate after four payments. Every wallet step is the TypeScript plug-in (driver.ts) through the public gateway only; the Go reference (nb2-evidence,
built from this checkout) is the independent verifier.

    rehearse_nb2.py --generation GEN --evidence DIR --nb2-evidence BIN [--stages ...] [--long-transfers N] [--keep-keys]

The driver keys (`fund`: bridge/nb2/driver.env, funded from the faucet) are this run's secrets. They reach the driver only through its environment
file, never a command line (the lane's own signing goes through the driver's `address` and `mktx`), and every console line, log and result is
redacted of them. A run deletes them at its end, on success and on failure. --keep-keys hands them to a later invocation on the same generation: the
PoS sequence's first invocation (deploy,fund,pos-deposit) keeps them, and its last one (pos-return,custody) runs without it and deletes them.

  deploy        deploy_nb2.py: the test pair (K = 4) and the production pair (64, 16); the manifest against the chain; Γ by Go, accepted by the vault
                constructor and by the plug-in (installation check); the companion horizon null (retention); each build refuses the other's (K, B)
  limits        the pinned limits measured: a transaction of exactly maxEncodedTxBytes admitted by every validator through the gateway and included
                (every validator holds the block), one byte more refused by each pool; the gateway's large body bound; a transaction at userGasLimit
                included, and what happens to one above it
  fund          the driver keys (bridge/nb2/driver.env, never in the evidence) funded from the faucet
  circulate     deposit 100 (EIP-1559), mint, transfer, split 60 + 40, split 40 into 15 + 25, transfer again; an origin-only token from a legacy
                deposit; a one-transfer token; a three-level nested split; the 16- and 17-claim tokens (one certificate per transfer)
  returns       the 60, 15 and 25 returned with their own indices while a second key's small returns rotate the segments (at least twice):
                exactly 100 paid; each replay refused before and after its payment left the recent buffers; a witness made stale by two rotations
                refused and then paid after refresh; a deliberately too-low gas limit reverted, the vault unchanged, then paid; a return whose broadcast
                the gateway calls partial (HTTP 503, #1121) found by receipt polling
  evidence      scripts/nb2-evidence/stage.sh (#1102) against the real vault: a Deposited receipt proof and the newest SegmentSealed receipt, Go-verified
  verifier      the deployed verifier against the plug-in and the Go reference on every burned part, byte for byte (origin only, transfer, split,
                nested, typed and legacy receipts, 16 and 17 claims); isolated mutations (each certificate's seal, RSMT paths, unlock recovery IDs 2
                and 3, canonical encoding) judged by all three; fault injection of 0x0100, 0x0102 and the helper's code (eth_call state overrides)
  gas           real transaction gas of the returns (long, nested, claims), with the measured refusals
  boundary      the capacity boundary: a token at the largest transfer history the preflight admits, returned; one transfer more refused before
                the burn (CapacityPreflight), reported as the documented limit, not as recovery
  cold          a burned part redeemed after every derived wallet cache is deleted (journal, token and burn kept)
  custody       the vault's books from its events: deposits once each, every Paid once, Q = deposits - payouts = state().outstanding, balance >= Q,
                the segment logs fold to the stored head
  pos-deposit, pos-return
                PoS lane only, around rehearse.py's handoff: a deposit, mint and transfer in epoch 1, then a transfer, split, burn and redeem after
                the epoch change (the verifier judges each certificate under its own epoch's authority), verdicts by all three
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent))
from rehearse import PROXY_IPS, PUBLIC_RPC, Failure, Rehearsal   # noqa: E402
import release_nb2   # noqa: E402

WALLETS = ('main', 'rot', 'big', 'size', 'gascap')
FUNDS = {'main': 20 * 10 ** 18, 'rot': 20 * 10 ** 18, 'big': 20 * 10 ** 18, 'size': 5 * 10 ** 18, 'gascap': 5 * 10 ** 18}


class NB2Rehearsal(Rehearsal):
    def __init__(self, *args, **kwargs):
        self._addresses = {}
        super().__init__(*args, **kwargs)

    @property
    def nb2(self):
        return self.gen / 'bridge' / 'nb2'

    def lane_json(self):
        return json.loads((self.nb2 / 'lane.json').read_text())

    def release(self):
        return json.loads((self.nb2 / 'public/nb2-release.json').read_text())

    def outfile(self, name):
        return json.loads((self.nb2 / 'out' / f'{name}.json').read_text())

    def keep(self, *names):
        """Copy driver outputs (out/<name>.json) into the evidence."""
        (self.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
        for name in names:
            src = self.nb2 / 'out' / f'{name}.json'
            if src.is_file():
                shutil.copy(src, self.evidence / 'nb2' / src.name)

    def driver(self, *args, check=True):
        env = self.nb2 / 'driver.env'
        if os.getuid() == 0:
            subprocess.run(['chown', '-R', '10001:10001', str(self.gen / 'bridge')], check=True)
        t0 = time.monotonic()
        out = subprocess.run(release_nb2.driver_cmd(self.gen, *args, env_file=env if env.exists() else None), text=True, capture_output=True)
        text = (out.stdout + out.stderr).strip()
        self.say(f'  $ driver {" ".join(args)} ({time.monotonic() - t0:.0f} s)\n    ' + '\n    '.join(text.splitlines()[-20:]))
        if check and out.returncode != 0:
            raise Failure(f'the driver failed: {" ".join(args)}')
        return out.returncode, text

    def go(self, *args):
        return subprocess.run([str(self.nb2_evidence), *args], check=True, text=True, capture_output=True).stdout

    def driver_keys(self):
        """Every driver key of bridge/nb2/driver.env, as written and without its 0x: secrets of this run, whatever the generation's own scan finds."""
        env = self.nb2 / 'driver.env'
        keys = set()
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith('NB2_KEY_') and '=' in line:
                    k = line.split('=', 1)[1].strip()
                    if len(k) >= 16:
                        keys |= {k, k.removeprefix('0x'), k.lower(), k.removeprefix('0x').lower()}
        return keys

    def scrub(self, text, patterns=False):
        """The package's redaction, with the driver keys added: they are not in a file the generation scan knows (driver.env), and a failed command's
        text can carry anything it was given. Fails closed like the inherited scrub."""
        try:
            keys = self.driver_keys()
        except Exception as error:
            return f'[output withheld: the driver keys could not be read: {error}]'
        for k in sorted(keys, key=len, reverse=True):
            text = text.replace(k, '[redacted]')
        out = super().scrub(text, patterns)
        return '[output withheld: a driver key survived the redaction]' if any(k in out for k in keys) else out

    def address(self, wallet):
        """The address of a driver key, from the driver: the key stays in its environment file, never in a command line."""
        if wallet not in self._addresses:
            (self.nb2 / 'tmp').mkdir(parents=True, exist_ok=True)
            self.driver('address', wallet, f'/work/nb2/tmp/address-{wallet}')
            self._addresses[wallet] = (self.nb2 / 'tmp' / f'address-{wallet}').read_text().strip()
        return self._addresses[wallet]

    def mktx(self, wallet, to, value, gas, price, nonce, data='0x', legacy=True):
        """A transaction signed by a driver key, in the driver (no key in any argv); its raw hex."""
        (self.nb2 / 'tmp').mkdir(parents=True, exist_ok=True)
        name = f'tx-{secrets.token_hex(4)}.hex'
        self.driver('mktx', wallet, '--legacy' if legacy else '--1559', to, str(value), str(gas), str(price), str(nonce), data, f'/work/nb2/tmp/{name}')
        return (self.nb2 / 'tmp' / name).read_text().strip()

    def finalize_keys(self, keep):
        """The run's end: the driver keys (funded, disposable) are deleted unless --keep-keys hands them to a later invocation (the PoS sequence's
        stages around the handoff). The generation's faucet keystore is not the driver's and stays."""
        env = self.nb2 / 'driver.env'
        if keep or not env.exists():
            return
        env.unlink()
        self.say('  the driver keys are deleted (bridge/nb2/driver.env)')

    # --- deploy ----------------------------------------------------------------------------------------------------------------
    def deploy(self):
        out = subprocess.run([sys.executable, str(HERE / 'deploy_nb2.py'), str(self.gen), '--nb2-evidence', str(self.nb2_evidence)], text=True, capture_output=True)
        self.say(out.stdout[-3000:] + out.stderr[-3000:])
        if out.returncode != 0:
            raise Failure('deploy_nb2.py failed')
        rel = self.release()
        dep = rel['deployment']
        for build in ('test', 'production'):
            d = dep.get(build)
            if d is None:
                continue
            for part in ('vault', 'verifier', 'helper'):
                c = d[part]
                code = self.call('eth_getCode', [c['address'], 'latest'])
                want = c.get('runtimeCodeHash') or c.get('codeHash')
                self.expect(code not in (None, '0x') and self.cast_run('keccak', code) == want, f'{build} {part}: the code at {c["address"]} has the manifest\'s hash (read through the gateway)', want)
            for part in ('vault', 'verifier'):
                r = self.call('eth_getTransactionReceipt', [d[part]['transaction']])
                self.expect(int(r['blockNumber'], 16) == d[part]['block'] and r['contractAddress'].lower() == d[part]['address'].lower(), f'{build} {part}: created by its manifest transaction in block {d[part]["block"]}')
            config = self.call('eth_call', [{'to': d['vault']['address'], 'data': self.cast_run('calldata', 'config()')}, 'latest'])
            self.expect(self.cast_run('abi-decode', 'f()(bytes)', config).lower() == d['gamma'].lower(), f'{build}: the vault\'s config() is the manifest\'s Γ')
            # the Go reference decodes the deployed Γ to the fields it was built from
            g = json.loads(self.go('gamma', '-decode', str(self.write_tmp(d['gamma']))))
            self.expect(g['gamma'] == d['gamma'].lower() and g['domain'] == d['domain'].lower() and g['vault'] == d['vault']['address'].lower()
                        and g['verifierCodeHash'] == d['verifier']['codeHash'] and (g['K'], g['B']) == (d['K'], d['B']), f'{build}: Go decodes Γ to the deployed fields (D, vault, verifier code, K, B)')
        pins = rel['pins']
        self.expect(pins['deploymentBlock'] == dep[dep['primary']]['vault']['block'] and pins['build'] == 'test' and dep['test']['K'] == 4, 'the wallets\' pins: the test build with K = 4, logs read from the vault\'s block')
        self.expect(int(pins['userGasLimit']) == json.loads((self.gen / 'network/b1-profile.json').read_text())['ordinaryCapacity'], 'userGasLimit is the profile\'s ordinary capacity')
        self.expect(self.call('unicity_sealCompanionHorizonV1', []) is None, 'the companion horizon is null through the gateway: nothing pruned (retention)')
        self.driver('gamma-check')
        self.driver('admission')
        adm = self.outfile('admission')
        self.expect(adm['productionVerifierTestGamma'].get('rule') == 'ConfigShape' and adm['testVerifierProductionGamma'].get('rule') == 'ConfigShape',
                    'each verifier build refuses the other\'s Γ (ConfigShape)', json.dumps(adm))
        self.expect(adm['testVaultProductionGamma'].startswith('BadConfig(16)') and adm.get('productionVaultTestGamma', '').startswith('BadConfig(16)'),
                    'each vault build\'s constructor refuses the other\'s K (BadConfig(16))', json.dumps(adm))
        for name in ('deployment.json', 'lane.json', 'public/nb2-release.json', 'envelope.json'):
            (self.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
            shutil.copy(self.nb2 / name, self.evidence / 'nb2' / Path(name).name)
        self.keep('gamma-check', 'admission')
        env = rel['envelope']
        self.say(f'  envelope: {json.dumps(env["largestToken"])}; reference part {json.dumps(env["referencePart"])}')

    def write_tmp(self, text):
        p = self.nb2 / 'tmp'
        p.mkdir(exist_ok=True)
        f = p / f'{secrets.token_hex(4)}.hex'
        f.write_text(text)
        return f

    # --- limits ----------------------------------------------------------------------------------------------------------------
    def sized_tx(self, wallet, nonce, length):
        """A signed EIP-1559 transaction of exactly LENGTH encoded bytes (zero calldata: the size counts, not the gas), signed by the driver (a
        megabyte of hex does not fit one command-line argument)."""
        name = f'sized-{length}.hex'
        (self.nb2 / 'tmp').mkdir(exist_ok=True)
        self.driver('sized', wallet, str(nonce), str(length), f'/work/nb2/tmp/{name}')
        return (self.nb2 / 'tmp' / name).read_text().strip()

    def inner_big(self, i, method, params):
        """inner_reply with the request on stdin (a body above the 128 KiB argument limit)."""
        code = ('import json,sys,urllib.request as u;b=sys.stdin.buffer.read();'
                'r=u.Request(sys.argv[1],b,{"Content-Type":"application/json"});'
                'print(u.urlopen(r,timeout=60).read().decode())')
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)})
        out = subprocess.run(['docker', 'compose', *self.compose_args(), 'exec', '-T', 'rpc', 'python3', '-c', code, f'http://ureth{i}:8545'], input=body, text=True,
                             capture_output=True, check=True)
        return json.loads(out.stdout)

    def compose_args(self):
        import handoff_ops
        return handoff_ops.compose_files(self.gen)

    def limits(self):
        rel = self.release()
        lmax = rel['pins']['maxEncodedTxBytes']
        ugl = int(rel['pins']['userGasLimit'])
        res = {'maxEncodedTxBytes': lmax, 'userGasLimit': ugl}
        size = self.address('size')
        nonce = int(self.call('eth_getTransactionCount', [size, 'pending']), 16)
        # one byte over the pools' own limit (the B1 profile's --txpool.max-tx-input-bytes, above L_max): refused by every validator's pool
        pool = rel['limits']['poolMaxTxInputBytes']['value']
        over = self.sized_tx('size', nonce, pool + 1)
        refusals = {}
        for i in range(1, self.n + 1):
            r = self.inner_big(i, 'eth_sendRawTransaction', [over])
            refusals[i] = (r.get('error') or {}).get('message', 'ACCEPTED')
        self.expect(all('ACCEPTED' != m and ('size' in m.lower() or 'oversized' in m.lower() or 'max' in m.lower()) for m in refusals.values()),
                    f'a transaction of {pool + 1} encoded bytes (one over the pools\' limit) is refused by every validator\'s pool', json.dumps(refusals))
        res['overPoolBy1'] = {'bytes': pool + 1, 'validators': refusals}
        # exactly L_max: admitted by every pool through the gateway (2 L_max hex bytes of body), included, and every validator holds the block
        exact = self.sized_tx('size', nonce, lmax)
        t0 = time.monotonic()
        status, text = self.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_sendRawTransaction', 'params': [exact]}, PROXY_IPS[0] + '41')
        self.expect(status == 200 and 'result' in json.loads(text), f'a transaction of exactly {lmax} encoded bytes ({len(exact) - 2} hex digits of body) is accepted by the gateway', f'{status} {text[:200]}')
        tx = json.loads(text)['result']
        receipt = self.wait('the L_max transaction is mined', lambda: self.call('eth_getTransactionReceipt', [tx]), 300)
        mined = time.monotonic() - t0
        blocks = {i: (self.ureth(i, 'eth_getTransactionReceipt', [tx]) or {}).get('blockHash') for i in range(1, self.n + 1)}
        self.wait('every validator holds the L_max block', lambda: all((self.ureth(i, 'eth_getTransactionReceipt', [tx]) or {}).get('blockHash') == receipt['blockHash'] for i in range(1, self.n + 1)), 120)
        block = self.call('eth_getBlockByHash', [receipt['blockHash'], False])
        res['exact'] = {'tx': tx, 'status': receipt['status'], 'block': int(receipt['blockNumber'], 16), 'blockSize': int(block['size'], 16), 'gasUsed': int(receipt['gasUsed'], 16),
                        'secondsToReceipt': round(mined, 1), 'validators': blocks}
        self.expect(receipt['status'] == '0x1', f'it is included (block {int(receipt["blockNumber"], 16)}, {int(block["size"], 16)} bytes) and every validator imported that block over the shard\'s payload protocol')
        # the gateway's body bound: 2 L_max + 64 KiB of hex body fits; one byte over MAX_RAW_TX_BODY is 413
        gw = release_nb2.gateway_limits()
        big = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': size, 'data': '0x' + '00' * (gw['MAX_RAW_TX_BODY'] // 2 - 200)}, 'latest']}).encode()
        s1, _ = self.rpc(big, PROXY_IPS[0] + '42')
        s2, t2 = self.rpc(big + b' ' * (gw['MAX_RAW_TX_BODY'] - len(big) + 1), PROXY_IPS[0] + '43')
        # above the bound the gateway answers 413 from the declared length and closes without reading: the client may see the 413 or a broken pipe
        refused = s2 == 413 or (s2 == 0 and ('Pipe' in t2 or 'Reset' in t2))
        self.expect(s1 == 200 and refused, f'the gateway reads an eth_call body of {len(big)} bytes and refuses one over {gw["MAX_RAW_TX_BODY"]} (413, unread)', f'{s1} {s2} {t2[:120]}')
        res['gatewayBody'] = {'accepted': len(big), 'refusedAbove': gw['MAX_RAW_TX_BODY']}
        # user gas: a transaction with gasLimit = userGasLimit is included; one above it (up to the block gas limit) is observed, not assumed
        gc = self.address('gascap')
        gnonce = int(self.call('eth_getTransactionCount', [gc, 'pending']), 16)
        price = int(self.call('eth_gasPrice'), 16) * 2
        at = self.mktx('gascap', size, 1, ugl, price, gnonce)
        h = self.call('eth_sendRawTransaction', [at])
        r = self.wait('the userGasLimit transaction is mined', lambda: self.call('eth_getTransactionReceipt', [h]), 300)
        res['atUserGasLimit'] = {'tx': h, 'status': r['status'], 'block': int(r['blockNumber'], 16)}
        self.expect(r['status'] == '0x1', f'a transaction with gas limit {ugl} (userGasLimit) is included')
        above = self.mktx('gascap', size, 1, ugl + 1, price, gnonce + 1)
        replies = {i: self.inner_reply(f'http://ureth{i}:8545', 'eth_sendRawTransaction', [above]) for i in range(1, self.n + 1)}
        outcome = {'gasLimit': ugl + 1, 'validators': {i: (r.get('error') or {}).get('message', 'ACCEPTED') for i, r in replies.items()}}
        self.expect(all(v != 'ACCEPTED' for v in outcome['validators'].values()), f'a transaction with gas limit {ugl + 1} is refused at admission by every pool (--txpool.max-tx-gas)', json.dumps(outcome))
        res['aboveUserGasLimit'] = outcome
        self.say(f'  above userGasLimit: {json.dumps(outcome)}')
        (self.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
        (self.evidence / 'nb2/limits.json').write_text(json.dumps(res, indent=2) + '\n')

    # --- fund ------------------------------------------------------------------------------------------------------------------
    def fund(self):
        self.nb2.mkdir(parents=True, exist_ok=True)
        env = self.nb2 / 'driver.env'
        if not env.exists():
            env.touch()
            os.chmod(env, 0o600)
            env.write_text(''.join(f'NB2_KEY_{w.upper()}=0x{secrets.token_hex(32)}\n' for w in WALLETS))
        for w in WALLETS:
            a = self.address(w)
            if self.balance(a) < FUNDS[w] // 2:
                self.faucet_send(a, FUNDS[w])
            self.expect(self.balance(a) >= FUNDS[w] // 2, f'the {w} key {a} is funded from the faucet')

    # --- circulate -------------------------------------------------------------------------------------------------------------
    def legacy_deposit(self, wallet, label, units):
        self.driver('deposit', wallet, label, str(units), '--plan-only')
        plan = self.outfile(f'deposit-plan-{label}')
        sender = self.address(wallet)
        nonce = int(self.call('eth_getTransactionCount', [sender, 'pending']), 16)
        price = int(self.call('eth_gasPrice'), 16) * 2
        raw = self.mktx(wallet, plan['vault'], plan['value'], 200000, price, nonce, plan['calldata'])
        self.expect(raw.startswith('0xf8') or raw.startswith('0xf9'), 'the deposit is a legacy (untyped) transaction')
        tx = self.call('eth_sendRawTransaction', [raw])
        r = self.wait('the legacy deposit is mined', lambda: self.call('eth_getTransactionReceipt', [tx]), 180)
        self.expect(r['status'] == '0x1' and r.get('type') in ('0x0', None), f'the legacy deposit succeeded with a legacy receipt (type {r.get("type")})')
        self.driver('deposit', wallet, label, '0', '--adopt')

    def circulate(self):
        d = self.driver
        L = self.L
        d('deposit', 'main', L('root'), '100')
        d('transfer', 'main', L('root'), L('t1'), '1')
        d('split', 'main', L('t1'), '2', f'{L("p60")}=60', f'{L("p40")}=40')
        d('split', 'main', L('p40'), '3', f'{L("p15")}=15', f'{L("p25")}=25')
        d('transfer', 'main', L('p25'), L('p25b'), '0')
        if self.prefix:   # a second pass of the 100 scenario: the other tokens exist already
            return
        self.legacy_deposit('main', 'legacy', 3)          # origin only, legacy receipt
        d('deposit', 'main', 'one', '2')
        d('transfer', 'main', 'one', 'one1', '1')          # one transfer
        d('deposit', 'main', 'deep', '8')
        d('split', 'main', 'deep', '1', 'd4a=4', 'd4b=4')
        d('split', 'main', 'd4a', '2', 'd2a=2', 'd2b=2')
        d('split', 'main', 'd2a', '3', 'd1a=1', 'd1b=1')    # three nested split levels
        # claims: the EVM UC, the mint's, one per transfer (each in its own round) and the burn's: 13 transfers make 16, 14 make 17
        d('deposit', 'main', 'c16', '1')
        d('chain', 'main', 'c16', 'c16x', '13', '--rounds')
        d('deposit', 'main', 'c17', '1')
        d('chain', 'main', 'c17', 'c17x', '14', '--rounds')
        d('deposit', 'main', 'long', '1')
        d('chain', 'main', 'long', 'longx', str(self.long_transfers))   # one aggregator batch: certificates shared
        self.keep(*[f'deposit-{x}' for x in ('root', 'legacy', 'one', 'deep', 'c16', 'c17', 'long')], 'chain-c16x', 'chain-c17x', 'chain-longx')

    # --- returns ---------------------------------------------------------------------------------------------------------------
    def state(self):
        self.driver('state')
        return self.outfile('state')

    def L(self, label):
        """A scenario label with this run's prefix (--prefix: a second pass of the 100 scenario on the same generation)."""
        return self.prefix + label

    def returns(self):
        d, L = self.driver, self.L
        p60, p15, p25 = L('p60'), L('p15'), L('p25b')
        name = {p60: '60', p15: '15', p25: '25'}
        vault = self.release()['deployment']['test']['vault']['address']
        main = self.address('main')
        bal0 = self.balance(main)
        d('rotate', 'rot', '20', '--prepare')     # twenty small returns, burned ahead and paid in bursts
        (self.nb2 / 'tmp').mkdir(exist_ok=True)
        s0 = self.state()

        def recent(part):
            d('replay', 'main', part)
            r = self.outfile(f'replay-{part}')
            self.expect(not r['evicted'] and r['exactCalldata'].startswith('AlreadyPaid') and r['wallet']['state'] == 'paid' and r['wallet']['sends'] == 1,
                        f'the {name[part]}\'s replay while in the recent buffers: AlreadyPaid; the wallet reconciles to the payment without a send', json.dumps(r))

        def evicted(part):
            d('replay', 'main', part)
            r = self.outfile(f'replay-{part}-evicted')
            self.expect(r['evicted'] and r.get('historyPaidInSegment') is not None and r['wallet']['state'] == 'paid' and not r['exactCalldata'].startswith('success')
                        and not r['forgedGapProof'].startswith('success') and not r['zeroHistory'].startswith('success'),
                        f'the {name[part]}\'s replay after its payment left the recent buffers: the wallet\'s builder finds it in sealed segment {r.get("historyPaidInSegment")}; '
                        f'the old calldata ({r["exactCalldata"]}), a zero history ({r["zeroHistory"]}) and a forged gap proof ({r.get("forgedGapProof")}) are refused', json.dumps(r))

        d('burn', 'main', p60)
        d('verdicts', 'main', p60)
        d('redeem', 'main', p60)
        recent(p60)
        d('rotate', 'rot', '4', '--pay')           # one rotation: the 15 is burned at a newer index than the 60
        d('burn', 'main', p15)
        d('verdicts', 'main', p15)
        d('redeem', 'main', p15, '--hold')
        d('rotate', 'rot', '8', '--pay')           # two rotations at K = 4
        d('redeem', 'main', p15, '--stale')
        r = self.outfile(f'redeem-{p15}-stale')
        self.expect(r['simulated'].startswith('StaleEndpoint') and r['staleTx']['status'] == '0x0' and r['result'] == 'paid',
                    'the 15\'s witness made stale by two rotations is refused (StaleEndpoint, its transaction reverted), then paid after refresh', json.dumps({k: r[k] for k in ('heldEndpoint', 'segmentNow', 'simulated', 'staleTx', 'result')}, default=str))
        recent(p15)
        evicted(p60)
        d('burn', 'main', p25)
        d('verdicts', 'main', p25)
        d('redeem', 'main', p25, '--low-gas')
        r = self.outfile(f'redeem-{p25}-low-gas')
        self.expect(r['lowGas']['status'] == '0x0' and r['lowGas']['unchanged'] and r['result'] == 'paid', 'the 25\'s redeem with a too-low gas limit reverts and leaves the vault unchanged; the wallet\'s retry is paid', json.dumps(r['lowGas'], default=str))
        recent(p25)
        d('rotate', 'rot', '8', '--pay')           # two more rotations: every part's payment has left the recent buffers
        evicted(p15)
        evicted(p25)
        # 100 paid: the three parts, each once, to the main key
        paid = {}
        topic = self.cast_run('keccak', 'Paid(bytes32,address,uint256)')
        for part, outname in ((p60, f'redeem-{p60}'), (p15, f'redeem-{p15}-stale'), (p25, f'redeem-{p25}-low-gas')):
            out = self.outfile(outname)
            receipt = self.call('eth_getTransactionReceipt', [out['paid']['tx']])
            logs = [x for x in receipt['logs'] if x['address'].lower() == vault.lower() and x['topics'][0] == topic]
            self.expect(len(logs) == 1 and logs[0]['topics'][2][-40:].lower() == main.lower()[2:], f'{name[part]}: one Paid, to the main key')
            paid[name[part]] = int(logs[0]['data'], 16)
        unit = int(self.lane_json()['unit'])
        self.expect(paid == {'60': 60 * unit, '15': 15 * unit, '25': 25 * unit}, 'exactly 100 units paid: 60 + 15 + 25', json.dumps(paid))
        s1 = self.state()
        self.expect(int(s1['segment']) >= int(s0['segment']) + 2, f'the segments rotated at least twice meanwhile ({s0["segment"]} -> {s1["segment"]})')
        idx = {name[p]: self.outfile(f'burn-{p}')['a'] for p in (p60, p15, p25)}
        self.expect(len(set(idx.values())) == 3, f'each part has its own index a: {idx}')
        names = [f'burn-{p}' for p in (p60, p15, p25)] + [f'redeem-{p60}', f'hold-{p15}', f'redeem-{p15}-stale', f'redeem-{p25}-low-gas'] + \
                [f'replay-{p}' for p in (p60, p15, p25)] + [f'replay-{p}-evicted' for p in (p60, p15, p25)] + [f'verdicts-{p}' for p in (p60, p15, p25)]
        self.keep(*names)
        (self.evidence / 'nb2' / f'paid{self.prefix}.json').write_text(json.dumps({'paid': paid, 'mainBalanceDelta': self.balance(main) - bal0, 'segments': [s0['segment'], s1['segment']], 'indices': idx}, indent=2) + '\n')
        # an ambiguous broadcast (#1121): the redeem reaches validator 1 first, so the gateway's relay sees "already known" beside the others' hash and
        # answers 503 "broadcast may be partial"; the wallet must not resend blindly but poll the receipt of the hash it computed
        d('burn', 'main', 'legacy')
        d('verdicts', 'main', 'legacy')
        d('redeem', 'main', 'legacy', '--ambiguous')
        r = self.outfile('redeem-legacy')
        self.expect(r['result'] == 'paid' and r['broadcasts']['ambiguous'] >= 1 and len(r['sends']) == 1,
                    'the gateway answered 503 (partial broadcast) and the wallet found the payment by receipt polling, with one send', json.dumps(r['broadcasts']))
        self.keep('burn-legacy', 'redeem-legacy', 'verdicts-legacy')

    # --- evidence (#1102) --------------------------------------------------------------------------------------------------------
    def evidence_stage(self):
        rel = self.release()
        t = rel['deployment']['test']
        tx = '0x' + bytes.fromhex(self.outfile('deposit-root')['tx'][2:]).hex()
        env = dict(os.environ, K='4', NB2_EVIDENCE_OUT=str(self.evidence / 'nb2/stage-sh'), NB2_EVIDENCE_FORWARDED_FOR=PROXY_IPS[0] + '50')
        out = subprocess.run(['bash', str(HERE.parent.parent.parent.parent / 'scripts/nb2-evidence/stage.sh'), f'http://{PUBLIC_RPC}/', str(self.nb2 / 'public/trust-base.bundle.cbor'),
                              str(self.nb2 / 'public/trust-base.genesis.entryid'), t['vault']['address'], tx, str(rel['pins']['deploymentBlock'])], text=True, capture_output=True, env=env,
                             cwd=HERE.parent.parent.parent.parent)
        self.say(out.stdout[-3000:] + out.stderr[-2000:])
        self.expect(out.returncode == 0 and 'wallet evidence verified' in out.stdout, 'stage.sh: the deposit receipt proof and the newest seal receipt, built through the gateway only, verify with nb2ref')

    # --- verifier differential ----------------------------------------------------------------------------------------------------
    def go_verdicts(self, files, bundle=None):
        """The Go reference's verdict on each evidence file (paths under bridge/nb2)."""
        rel = self.release()
        g = self.write_tmp(rel['pins']['gamma'])
        b = bundle or (self.nb2 / 'public/trust-base.bundle.cbor')
        lines = self.go('verify-return', '-gamma', str(g), '-trust-bundle', str(b), '-pin', str(self.nb2 / 'public/trust-base.genesis.entryid'), *[str(self.nb2 / f) for f in files])
        return {Path(json.loads(l)['file']).relative_to(self.nb2).as_posix(): json.loads(l) for l in lines.splitlines() if l.strip()}

    def compare(self, name, bundle=None):
        """Three-way: the plug-in, the deployed verifier and Go, on every file a driver output (verdicts-*, mutations-*) names."""
        doc = self.outfile(name)
        go = self.go_verdicts([v['file'] for v in doc.values()], bundle)
        table = {}
        for key, v in doc.items():
            gv = go[v['file']]
            ts, sol = v['ts'], v['solidity']
            same_verdict = ts.get('verdict') is not None and ts.get('verdict') == sol.get('verdict') == gv.get('verdict')
            sol_rule = (sol.get('rule') or '').split('/')[-1]
            same_rule = ts.get('rule') is not None and ts.get('rule') == gv.get('rule') == sol_rule
            table[key] = {'ts': ts.get('verdict', ts.get('rule'))[:20] if ts else None, 'solidity': (sol.get('verdict') or sol.get('rule') or '')[:20], 'go': (gv.get('verdict') or gv.get('rule') or '')[:20],
                          'agree': same_verdict or same_rule, 'gasUsed': v.get('gasUsed')}
        (self.evidence / 'nb2' / f'{name}-3way.json').write_text(json.dumps({'cases': table, 'raw': doc, 'go': go}, indent=2) + '\n')
        return table

    def verifier(self):
        d = self.driver
        for label in ('one1', 'd1a', 'c16x', 'c17x', 'longx'):
            d('burn', 'main', label)
        d('verdicts', 'main', 'one1', 'd1a', 'c16x', 'c17x', 'longx')
        all_parts = {}
        for name in ('verdicts-p60', 'verdicts-p15', 'verdicts-p25b', 'verdicts-legacy', 'verdicts-one1-d1a-c16x-c17x-longx'):
            for k, v in self.compare(name).items():
                all_parts[k] = v
        bad = {k: v for k, v in all_parts.items() if not (v['agree'] and v['solidity'].startswith('0x'))}
        self.expect(not bad, f'the deployed verifier returns exactly the plug-in\'s and Go\'s 192-byte verdict on every part ({", ".join(all_parts)})', json.dumps(bad))
        # isolated mutations of the 17-claim part (each certificate position) and of the nested part
        for label in ('c17x', 'd1a'):
            d('mutations', 'main', label)
            t = self.compare(f'mutations-{label}')
            # one broken signature leaves a quorum only when the seal carries more signatures than the quorum: those variants are judged by agreement
            accepted = [k for k, v in t.items() if v['solidity'].startswith('0x') and not k.endswith('-one-signature')]
            disagree = [k for k, v in t.items() if not v['agree']]
            self.say(f'  mutations of {label}: ' + ', '.join(f'{k}={v["solidity"]}' for k, v in t.items()))
            self.expect(not accepted, f'{label}: every mutation is refused by the deployed verifier (one broken signature of a seal is accepted or refused as its remaining weight decides, by all three alike)', json.dumps(accepted))
            allsig = sorted(k for k in t if k.endswith('-all-signatures'))
            self.say(f'  {label}: every certificate position with all its signatures broken: ' + ', '.join(f'{k.split("-")[0]}={t[k]["solidity"]}' for k in allsig))
            self.expect(not disagree, f'{label}: the plug-in, the deployed verifier and Go name the same rule for every mutation', json.dumps({k: t[k] for k in disagree}))
        d('faults', 'main', 'd1a')
        f = self.outfile('faults-d1a')
        self.expect(f['baseline'].get('ok'), 'fault injection baseline: the simulated verifier accepts the part', json.dumps(f['baseline']))
        helper = self.cast_run('keccak', 'HelperCodeMismatch()')[:10]
        self.expect(all(f[k].get('returnData', '').startswith(helper) for k in ('helper-code-replaced', 'helper-code-removed')),
                    f'the verifier refuses a replaced or removed receipt helper (HelperCodeMismatch(), {helper}): its code hash is pinned, not only its address', json.dumps({k: f[k] for k in ('helper-code-replaced', 'helper-code-removed')}))
        # ureth's eth_call ignores movePrecompileToAddress (even for 0x02) and its eth_simulateV1 refuses unbound blocks: a native primitive
        # cannot be replaced over RPC at this pin. Recorded, not claimed: those cases stay with the forge doubles (pos#82).
        injected = {k: f[k].get('returnData') != f['baseline'].get('returnData') for k in f if k.startswith(('cert-batch', 'membership'))}
        self.say(f'  native-primitive overrides applied by this ureth: {json.dumps(injected)}')
        (self.evidence / 'nb2/faults-note.json').write_text(json.dumps({'precompileOverridesApplied': injected, 'note': 'ureth 10552af2 eth_call ignores movePrecompileToAddress; eth_simulateV1 refuses a block without bound inputs'}, indent=2) + '\n')
        self.keep('faults-d1a', 'mutations-c17x', 'mutations-d1a', 'verdicts-one1-d1a-c16x-c17x-longx')

    # --- gas -------------------------------------------------------------------------------------------------------------------------
    def gas(self):
        d = self.driver
        for label in ('one1', 'c16x', 'c17x', 'longx'):
            d('redeem', 'main', label)
        rows = {}
        for label in ('p60', 'p15', 'p25b', 'legacy', 'one1', 'c16x', 'c17x', 'longx'):
            name = {'p15': 'redeem-p15-stale', 'p25b': 'redeem-p25b-low-gas'}.get(label, f'redeem-{label}')
            o = self.outfile(name)
            b = self.outfile(f'burn-{label}')
            rows[label] = {'gasUsed': o['paid']['gasUsed'], 'gasLimit': o['paid']['gasLimit'], 'preflightGasLimit': b['preflightGas'], 'inputBytes': o['paid']['inputBytes'], 'evidenceBytes': b['evidenceBytes']}
        for m in ('mutations-c17x', 'mutations-d1a'):
            for k, v in self.outfile(m).items():
                rows[f'{m}:{k}'] = {'refusal': (v['solidity'].get('rule')), 'gasUsed': v.get('gasUsed')}
        (self.evidence / 'nb2/gas.json').write_text(json.dumps(rows, indent=2) + '\n')
        for k, v in rows.items():
            if 'gasLimit' in v:
                self.expect(int(v['gasUsed']) <= int(v['gasLimit']) <= int(self.release()['pins']['userGasLimit']), f'{k}: gas used {v["gasUsed"]} within its limit {v["gasLimit"]} and userGasLimit')
        self.say('  gas: ' + json.dumps({k: v for k, v in rows.items() if 'gasLimit' in v}))

    # --- boundary --------------------------------------------------------------------------------------------------------------------
    def boundary(self):
        self.driver('boundary-estimate', 'big', 'ge')
        est = self.outfile('boundary-estimate-ge')['estimate']
        self.driver('boundary', 'big', 'g', str(est))
        b = self.outfile('boundary-g')
        self.say(f'  boundary: {json.dumps(b["tries"], default=str)}')
        self.driver('burn', 'big', b['pass']['label'])
        self.driver('redeem', 'big', b['pass']['label'])
        o = self.outfile(f'redeem-{b["pass"]["label"]}')
        self.driver('preflight', 'big', b['fail']['label'])
        p = self.outfile(f'preflight-{b["fail"]["label"]}')
        self.expect(o['result'] == 'paid' and not p['ok'] and p['rule'] == 'CapacityPreflight',
                    f'the token with {b["pass"]["transfers"]} transfers (the largest the preflight admits) is returned (gas {o["paid"]["gasUsed"]}, {o["paid"]["inputBytes"]} calldata bytes); '
                    f'one with {b["fail"]["transfers"]} is refused before its burn with CapacityPreflight: the documented capacity limit, not recovery', json.dumps(p))
        self.keep('boundary-estimate-ge', 'boundary-g', f'redeem-{b["pass"]["label"]}', f'preflight-{b["fail"]["label"]}', f'burn-{b["pass"]["label"]}')

    # --- cold ------------------------------------------------------------------------------------------------------------------------
    def cold(self):
        w = self.nb2 / 'wallets/main'
        removed = []
        for f in ['trust-history.cbor', *[p.name for p in w.glob('held-*.json')]]:
            if (w / f).exists():
                (w / f).unlink()
                removed.append(f)
        for f in (self.nb2 / 'out').glob('*.json'):
            pass   # outputs are the lane's evidence, not wallet state
        self.say(f'  deleted the derived wallet caches {removed}; kept the journal and tokens')
        self.driver('redeem', 'main', 'd1a')
        self.expect(self.outfile('redeem-d1a')['result'] == 'paid', 'the nested part is redeemed by a cold wallet: its history rebuilt from the segment logs, its trust refetched')
        self.keep('redeem-d1a')

    # --- custody ---------------------------------------------------------------------------------------------------------------------
    def custody(self):
        rel = self.release()
        t = rel['deployment']['test']
        vault = t['vault']['address']
        head = int(self.call('eth_blockNumber'), 16)
        topics = {self.cast_run('keccak', s): n for n, s in (('deposited', 'Deposited(uint64,bytes32,uint256,bytes32,bytes)'), ('paid', 'Paid(bytes32,address,uint256)'),
                                                            ('sealed', 'SegmentSealed(uint64,bytes32,bytes32,bytes)'))}
        logs = []
        lo = t['vault']['block']
        while lo <= head:
            hi = min(head, lo + 9999)
            logs += self.call('eth_getLogs', [{'address': vault, 'fromBlock': hex(lo), 'toBlock': hex(hi)}])
            lo = hi + 1
        deposits, paid, seals = {}, {}, []
        for l in logs:
            kind = topics.get(l['topics'][0])
            if kind == 'deposited':
                n = int(l['topics'][1], 16)
                self.expect(n not in deposits, f'deposit {n} once')
                deposits[n] = int(l['data'][2 + 64:2 + 128], 16)
            elif kind == 'paid':
                self.expect(l['topics'][1] not in paid, f'redemption {l["topics"][1][:18]}.. paid once')
                paid[l['topics'][1]] = int(l['data'], 16)
            elif kind == 'sealed':
                seals.append(int(l['topics'][1], 16))
            else:
                raise Failure(f'an unexpected vault event {l["topics"][0]}')
        st = self.state()
        D, P = sum(deposits.values()), sum(paid.values())
        self.expect(sorted(deposits) == list(range(1, len(deposits) + 1)) or sorted(deposits) == list(range(len(deposits))), 'the deposit numbers are consecutive', str(sorted(deposits))[:200])
        self.expect(int(st['outstanding']) == D - P, f'Q = deposits - payouts = {D - P}', str(st['outstanding']))
        bal = int(self.call('eth_getBalance', [vault, 'latest']), 16)
        self.expect(bal >= D - P, f'the vault holds at least Q ({bal} >= {D - P})')
        self.expect(seals == list(range(len(seals))) and int(st['segment']) == len(seals), f'segments 0..{len(seals) - 1} sealed once each, in order; the vault is at segment {st["segment"]}')
        # the Go reference folds the whole log history from the deployment block (stage.sh's segments command)
        env = dict(os.environ, NB2_EVIDENCE_FORWARDED_FOR=PROXY_IPS[0] + '51')
        seg = subprocess.run([str(self.nb2_evidence), 'segments', '-rpc', f'http://{PUBLIC_RPC}/', '-emitter', vault, '-from', str(t['vault']['block']), '-start', '0'],
                             text=True, capture_output=True, env=env)
        self.expect(seg.returncode == 0 and len(seg.stdout.splitlines()) == len(seals), f'Go reads the {len(seals)} segment logs in order', seg.stderr[-300:])
        (self.evidence / 'nb2/custody.json').write_text(json.dumps({'deposits': len(deposits), 'D': D, 'payouts': len(paid), 'P': P, 'Q': st['outstanding'], 'balance': bal,
                                                                    'segments': len(seals), 'state': st}, indent=2, default=str) + '\n')

    # --- PoS lane --------------------------------------------------------------------------------------------------------------------
    def pos_deposit(self):
        self.driver('deposit', 'main', 'pos', '10')
        self.driver('transfer', 'main', 'pos', 'pos1', '1')
        self.keep('deposit-pos')

    def pos_return(self):
        d = self.driver
        d('transfer', 'main', 'pos1', 'pos2', '2')      # at the new epoch: the wallet extends its trust history first
        d('split', 'main', 'pos2', '3', 'pos6=6', 'pos4=4')
        d('burn', 'main', 'pos6')
        d('verdicts', 'main', 'pos6')
        hist = self.nb2 / 'wallets/main/trust-history.cbor'
        self.expect(hist.exists(), 'the wallet extended its trust-base history past the genesis entry')
        t = self.compare('verdicts-pos6', bundle=hist)
        self.expect(all(v['agree'] and v['solidity'].startswith('0x') for v in t.values()), 'the epoch-spanning part (deposit in epoch 1, burn after the change): the same verdict from the plug-in, the deployed verifier and Go', json.dumps(t))
        d('redeem', 'main', 'pos6')
        self.expect(self.outfile('redeem-pos6')['result'] == 'paid', 'the epoch-spanning part is paid')
        self.keep('burn-pos6', 'verdicts-pos6', 'redeem-pos6')


STAGES = (('deploy', 'deploy'), ('limits', 'limits'), ('fund', 'fund'), ('circulate', 'circulate'), ('returns', 'returns'), ('evidence', 'evidence_stage'),
          ('verifier', 'verifier'), ('gas', 'gas'), ('boundary', 'boundary'), ('cold', 'cold'), ('pos-deposit', 'pos_deposit'), ('pos-return', 'pos_return'),
          ('custody', 'custody'))
POS_STAGES = ('pos-deposit', 'pos-return')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--generation', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--cast', default='cast')
    p.add_argument('--nb2-evidence', required=True, type=Path, help='nb2-evidence built from this checkout (go build -o BIN ./scripts/nb2-evidence)')
    p.add_argument('--stages', default=','.join(s for s, _ in STAGES if s not in POS_STAGES))
    p.add_argument('--keep-keys', action='store_true', help='keep bridge/nb2/driver.env for a later invocation on this generation (the PoS sequence\'s first one); '
                   'the last invocation runs without it and deletes them, on success and on failure')
    p.add_argument('--prefix', default='', help='label prefix of the 100 scenario (circulate, returns): a second, clean pass on the same generation')
    p.add_argument('--long-transfers', type=int, default=40, help='transfers of the long-history part (one aggregator batch, so at most 254)')
    a = p.parse_args()
    if not 1 <= a.long_transfers <= 254:
        p.error('--long-transfers must be 1 to 254')
    # the stages fund a key before deploy needs one only for the driver: run fund first when both are asked
    wanted = a.stages.split(',')
    unknown = set(wanted) - {s for s, _ in STAGES}
    if unknown:
        p.error(f'unknown stages {sorted(unknown)}')
    r = NB2Rehearsal(a.generation, a.evidence, a.cast)
    r.nb2_evidence = a.nb2_evidence.resolve()
    r.long_transfers = a.long_transfers
    r.prefix = a.prefix
    (a.evidence / 'nb2').mkdir(parents=True, exist_ok=True)
    order = ['fund'] + [s for s in wanted if s != 'fund'] if 'fund' in wanted else wanted
    methods = dict(STAGES)
    code = 0
    try:
        for name in order:
            r.stage(name, getattr(r, methods[name]))
    except Exception:
        code = 1
    finally:
        r.say('RESULT ' + ' '.join(f'{n}={s}' for n, s, _ in r.results))
        (a.evidence / 'nb2-result.json').write_text(json.dumps({'generation': r.gen.name, 'stages': r.results}, indent=2) + '\n')
        try:
            r.finalize_keys(a.keep_keys)
        except OSError as error:
            r.say(f'  the driver keys could not be deleted: {error}')
            code = 1
    return code


if __name__ == '__main__':
    sys.exit(main())
