#!/usr/bin/env python3
"""vr-late-joiner (bft-core#1309): a joiner whose shard node starts from an epoch-1 pin after at least two root handoffs, and restarts.

The validator container starts a joiner's shard node as `shard-node restore` from the release's epoch-1 seed pin, without --follow-source, and
repeats that same command on every start until the node is active. On the public candidate such a joiner stopped at the last block of root
epoch 2 (it took no certificate but the installed handoffs' terminal certificates), and its restart refused the pin under root epoch 3.

This stage makes that node beside a Compose VR generation that has passed at least two root handoffs (run it after vr-pos-recover): a fifth
entity (joiner.py) with a fresh shard node key, an empty archive and an empty execution client, a fresh signing authority at the current scope
(it signs nothing: the entity is not registered), and the container's shard command: `restore` with the newest certified record of root
epoch 1 from an incumbent's archive as the pin (h4-restore-pin, H4_RESTORE_MAX_EPOCH=1), no --follow-source, no paired root.

Asserted: the joiner's execution client reaches validator 1's head (the node verified every later epoch from its pin and took the certificates
from the incumbents' archives); after a restart with the same command it starts as `shard-node run` (no pin replay) and reaches the head again.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import time

import handoff_ops
import joiner as joiner_lib
import vr_recover


def drop_flag(entry, flag):
    """entry without `flag` and its value."""
    if flag not in entry:
        return entry
    at = entry.index(flag)
    return entry[:at] + entry[at + 2:]


def restore_entry(entry, body_id):
    """The validator container's joiner shard command: `restore` from the pin, no root-free follow sources and no paired root (bft-core#1309)."""
    entry = drop_flag(drop_flag(list(entry), '--follow-source'), '--paired-activation-rpc')
    entry[entry.index('run')] = 'restore'
    return entry + ['--tip-uc', '/state/tip.uc.cbor', '--tip-tr', '/state/tip.tr.cbor', '--trust-body-id', body_id]


def vr_late_joiner(r):
    if (r.manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('vr-late-joiner needs a VR/P85 Compose generation')
    r.expect(r.ubft is not None and bool(r.restore_pin), 'vr-late-joiner has the pinned ubft (--ubft) and h4-restore-pin (--restore-pin)')
    rec = vr_recover.Recovery(r, 1)
    rec.since = vr_recover.utc()
    ev = r.evidence / 'late-joiner'
    ev.mkdir(parents=True, exist_ok=True)
    epoch = rec.root_view(1)['activeEpoch']
    r.expect(epoch >= 3, 'the generation has passed at least two root handoffs (run after vr-pos-recover)', f'root epoch {epoch}')

    # 1. the pin: the newest certified record of root epoch 1 in an incumbent's archive, as old as the release's seed
    gen = r.gen
    info = joiner_lib.prepare(gen, r.ubft)
    j, val = info['index'], gen / f'validator{info["index"]}'
    pin = subprocess.run([str(r.restore_pin), str(gen / 'validator1' / 'archive'), str(gen / 'network' / 'trust-base.json'), str(val / 'evm' / 'tip')],
                         text=True, capture_output=True, env=dict(os.environ, H4_RESTORE_MAX_EPOCH='1'))
    (ev / 'restore-pin.txt').write_text(pin.stdout + pin.stderr)
    r.expect(pin.returncode == 0, 'validator 1\'s archive yields a root epoch 1 pin', (pin.stdout + pin.stderr).strip()[-300:])
    found = re.search(r'bodyID=(0x[0-9a-fA-F]{64})', pin.stdout)
    height = re.search(r'height=(\d+)', pin.stdout)
    r.expect(bool(found and height), 'the pin names its block and the epoch-1 trust body', pin.stdout.strip()[-300:])
    for name in ('tip.uc.cbor', 'tip.tr.cbor'):
        os.chown(val / 'evm' / name, 10001, 10001)
    r.say(f'  joiner {j}: EVM node {info["evm"]}; pin at block {height.group(1)} of root epoch 1, the chain is at root epoch {epoch}')

    # 2. a fresh authority at the current scope (it never signs here) and the container's shard command
    certified = json.loads(rec.exec('root1', 'ubft', 'validator', 'last-signed-uc', '--execution', 'http://127.0.0.1:8545',
                                    '--root-rpc', rec.root_rpc, '--epoch', str(epoch)).stdout)
    auth = val / 'auth'
    (auth / 'pop').mkdir(mode=0o700, exist_ok=True)
    subprocess.run([str(r.ubft), 'signing-authority', 'credential', '--out', str(auth / 'pop' / 'pop.cred')], check=True, capture_output=True)
    (auth / 'current-trust.json').write_bytes(rec.fetch('root1', 'q3', 'trust-base', '--root-rpc', rec.root_rpc, '--epoch', str(epoch)))
    root_info = json.loads((val / 'root' / 'node-info.json').read_text())
    vr = json.loads((gen / 'network' / 'vr-deployment.json').read_text())
    owner = '0x' + '11' * 20
    (auth / 'registration.json').write_text(json.dumps({'network': vr['networkWord'], 'chainId': r.manifest['chain_id'],
        'registry': rec.deployment['registry'], 'authorized': [{'action': 'register', 'owner': owner, 'payee': owner,
                                                                 'rootNodeId': root_info['nodeId'], 'rootKey': root_info['sigKey']}]}) + '\n')
    (auth / 'lifetime').write_text('fail-stop\n')
    override_path = gen / handoff_ops.JOINER_OVERRIDE
    override = json.loads(override_path.read_text())
    services = override['services']
    services[f'authority{j}']['entrypoint'] = vr_recover.authority_entrypoint(services[f'authority{j}']['entrypoint'], info['evm'], epoch,
        certified['shardEpoch'] + 1, '/authority/current-trust.json', r.manifest['genesis_hash'])
    services[f'shard{j}']['entrypoint'] = restore_entry(services[f'shard{j}']['entrypoint'], found.group(1))
    override_path.write_text(json.dumps(override, indent=1, sort_keys=True) + '\n')
    vr_recover.chown(val)
    r.rescan()
    (ev / 'shard-entrypoint.json').write_text(json.dumps(services[f'shard{j}']['entrypoint'], indent=1) + '\n')

    rpc_image = rec.compose['services']['rpc']['image']
    transport = handoff_ops.DockerTransport(gen)   # with the joiner override written: its pod is a service of every call

    def head(i):
        """eth_blockNumber of entity i's execution client, which serves its RPC on its pod's loopback only: asked from inside that pod."""
        code = ('import json,urllib.request as u;r=u.Request("http://127.0.0.1:8545",json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber",'
                '"params":[]}).encode(),{"Content-Type":"application/json"});print(int(json.load(u.urlopen(r,timeout=10))["result"],16))')
        done = subprocess.run(['docker', 'run', '--rm', '--network', f'container:{transport.holder(i)}', '--read-only', '--cap-drop', 'ALL',
                               '--security-opt', 'no-new-privileges', '--entrypoint', 'python3', rpc_image, '-c', code],
                              text=True, capture_output=True, timeout=60)
        return int(done.stdout.strip()) if done.returncode == 0 and done.stdout.strip() else None

    rec.dc('up', '-d', '--no-deps', f'pod{j}', f'ureth{j}')
    r.wait(f'the joiner\'s execution client {j} answers', lambda: head(j) is not None, 180)
    rec.dc('up', '-d', '--no-deps', f'authority{j}')
    r.wait('the joiner\'s authority answers', lambda: rec.auth_status(j), 60)

    def caught_up(floor):
        def probe():
            mine, tip = head(j), head(1)
            r.say(f'  joiner {j}: execution head {mine}, validator 1 {tip}')
            return mine if mine is not None and tip is not None and mine >= floor and mine + 3 >= tip else None
        return probe

    def shard_log():
        return rec.dc('logs', '--no-color', f'shard{j}', check=False).stdout

    # 3. first start, after the handoffs: it reaches the head
    started = time.monotonic()
    rec.dc('up', '-d', '--no-deps', f'shard{j}')
    first = r.wait(f'the joiner {j}, restored from the epoch-1 pin, reaches validator 1\'s head', caught_up(1), 1800, every=15)
    r.say(f'  first start: at block {first} after {time.monotonic() - started:.0f} s')
    log = shard_log()
    r.keep_redacted(ev / 'shard-first.log', log)
    r.expect(first is not None, f'the joiner reached the head past root epoch {epoch} from the epoch-1 pin', str(first))
    r.expect('profile2 archive restore failed' not in log, 'the first start restored without a refusal')
    offered = [l for l in log.splitlines() if 'archive head offered' in l]
    r.expect(any(re.search(r'rootEpoch\W+%d\b' % epoch, l) for l in offered),
             f'the joiner took the incumbents\' archive heads of root epoch {epoch} (no --follow-source)', f'{len(offered)} offers; shard-first.log')

    # 4. the restart, with the same restore command: started as `run`, no pin replay, and the head again
    rec.dc('restart', f'shard{j}')
    restarted = time.monotonic()
    again = r.wait(f'the restarted joiner {j} reaches the head again', caught_up(first + 2), 1200, every=15)
    r.say(f'  restart: at block {again} after {time.monotonic() - restarted:.0f} s')
    log = shard_log()
    r.keep_redacted(ev / 'shard-restart.log', log)
    r.expect(again is not None, 'the restarted joiner reached the head again', str(again))
    r.expect('archive restore of this BFT data directory is complete' in log, 'the restart started the completed restore as `shard-node run`')
    r.expect('profile2 archive restore failed' not in log and 'configured context mismatch' not in log,
             'the restart did not replay the epoch-1 pin under the current root epoch')
    (ev / 'result.json').write_text(json.dumps({'rootEpoch': epoch, 'pinHeight': int(height.group(1)), 'firstHead': first, 'restartHead': again}, indent=1) + '\n')
