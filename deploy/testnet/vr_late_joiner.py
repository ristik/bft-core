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

Then the joiner joins the committee (#1321), as the container's `join` does: its execution client runs the release's vector
(network/ureth-flags.txt after its own listeners, as validator.py ureth_command), its owner (a fresh key the funder pays) registers, bonds and
delegates with `ubft validator apply` through the signing authority, its root starts with --install-handoff-epoch, and
its first bond lands after one reservation. Its authority refreshes from the missed activation. At the next election every member and the joiner
prove possession, the roots activate the 5-member epoch and the joiner's authority advances with the verified activation proofs. Asserted:
the joiner is a member, it leads at least one round (its shard node submits a leader certification request and never logs a refused build),
and no block gap after the activation exceeds the normal bound (twice the block interval, at least 20 s).

vr-joiner-exit (#1316) follows, on the same entity: `validator exit` (requestRetirement); the next election excludes it; the joiner's own
`pos-publish --participate` sends nothing from then on; a claim watcher previews `validator claim --dry-run` each minute (it anchors the closed
term when the preview plans it), keeps a log per attempt, and the first claim attempt after maturity succeeds. Asserted besides: every
transaction of the joiner's owner after the retirement request goes to custody (anchorTerm, mature, claim), none to the election or VR.
It waits out custody's time floor (3,600 s), so it is not in the default stage list.

vr-finalizer (#1323) follows: two elections in which every member (and the joiner, if it is still one) runs `pos-publish --participate` in its
own loop every few seconds, as each validator's own participation loop polls the certified block (lockstep rounds do not race: the last
prover finalizes in its own run before the others poll again). The first runs with --finalizer-step 0s, the pre-#1323
behaviour in which every member finalizes a ready result at once; the second with the default order, in which the lowest frozen identity
finalizes and publishes and the others only after a delay that grows with their rank. It counts each election's finalizeCandidate and
VR.publish transactions and their reverts, and asserts that the ordered election sent exactly one of each, neither reverted.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

import handoff_ops
import joiner as joiner_lib
import pos_join
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


def release_ureth_entry(entry, shipped):
    """The joiner's execution client as the validator container runs it: its own arguments up to its listeners and log setting, then the
    release's ureth-flags.txt vector unchanged (#1321; validator.py ureth_command)."""
    at = entry.index('--log.file.max-files') + 2
    return list(entry[:at]) + list(shipped)


def max_gap(times):
    """(the largest gap, the block before it) of {block number: timestamp}."""
    numbers = sorted(times)
    return max(((times[b] - times[a], a) for a, b in zip(numbers, numbers[1:])), default=(0, None))


JOINER_STATE = 'joined.json'   # late-joiner/: what vr-joiner-exit continues from
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
    # the joiner's owner (and payee): a fresh key, paid by the funder before it joins; the authority's registration policy names it
    wallet = pos_join.new_wallet(r)
    owner, owner_key = wallet['address'], wallet['private_key']
    (auth / 'registration.json').write_text(json.dumps({'network': vr['networkWord'], 'chainId': r.manifest['chain_id'],
        'registry': rec.deployment['registry'], 'authorized': [{'action': 'register', 'owner': owner, 'payee': owner,
                                                                 'rootNodeId': root_info['nodeId'], 'rootKey': root_info['sigKey']}]}) + '\n')
    (auth / 'lifetime').write_text('fail-stop\n')
    override_path = gen / handoff_ops.JOINER_OVERRIDE
    override = json.loads(override_path.read_text())
    services = override['services']
    services[f'authority{j}']['entrypoint'] = vr_recover.authority_entrypoint(services[f'authority{j}']['entrypoint'], info['evm'], epoch,
        certified['shardEpoch'] + 1, '/authority/current-trust.json', r.manifest['genesis_hash']) + ['--pending-join-scope']
    services[f'shard{j}']['entrypoint'] = restore_entry(services[f'shard{j}']['entrypoint'], found.group(1))
    # the root: a follower until the handoff names it, installed at the current epoch as the container starts it; it starts with the
    # authority, so its catch-up overlaps the restore checks instead of the window before the bond (#1323)
    if epoch > 1 and '--install-handoff-epoch' not in services[f'root{j}']['entrypoint']:
        services[f'root{j}']['entrypoint'] = services[f'root{j}']['entrypoint'] + ['--install-handoff-epoch', str(epoch)]
    shipped = (gen / 'network' / 'ureth-flags.txt').read_text().split()
    services[f'ureth{j}']['entrypoint'] = release_ureth_entry(services[f'ureth{j}']['entrypoint'], shipped)
    (ev / 'ureth-entrypoint.json').write_text(json.dumps(services[f'ureth{j}']['entrypoint'], indent=1) + '\n')
    r.expect(any(a.startswith('--builder.gaslimit=') for a in shipped), 'the release\'s ureth vector names the builder\'s gas limit (#1321)',
             ' '.join(a for a in shipped if a.startswith(('--builder', '--unicity.max-gas'))))
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
    rec.dc('up', '-d', '--no-deps', f'root{j}')

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

    # 5. the join (#1321): the owner registers, bonds and delegates; every member and the joiner prove possession; the joiner leads rounds
    join_committee(r, rec, ev, j, val, auth, owner, owner_key, epoch, certified['shardEpoch'] + 1, override_path, info)


def join_committee(r, rec, ev, j, val, auth, owner, owner_key, epoch, shard_epoch, override_path, info):
    gen = r.gen
    live = 1
    started = vr_recover.utc()
    rec.transport = handoff_ops.DockerTransport(gen)   # with the joiner override: its pod is an entity of every call
    # the operator home: the joiner's root keys, its owner key, and the authority mounted at authority/ (validator.json as `validator init`)
    home = val / 'join-operator'
    home.mkdir(mode=0o700)
    for rel in ('root/keys.json', 'root/node-info.json', 'jwt/jwt.hex', 'ureth-key/p2p-secret'):
        (home / rel).parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(val / rel, home / rel)
    (home / 'operator').mkdir(mode=0o700)
    (home / 'operator/owner.key').write_text(owner_key + '\n')
    (home / 'authority').mkdir(mode=0o700)
    (home / 'validator.json').write_text(json.dumps(vr_recover.operator_config(r.manifest, rec.deployment, owner, 0)) + '\n')
    vr_recover.chown(home)
    r.rescan()
    rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'node-info', *vr_recover.OPERATOR, '--out', '/authority/node-info.json')
    vr_recover.chown(auth)

    # the funder pays the owner the bond and gas (one faucet claim's worth)
    r.funder_send(owner, 200 * 10**18)

    # the root: a follower until the handoff names it, installed at the current epoch as the container starts it
    override = json.loads(override_path.read_text())
    root_entry = override['services'][f'root{j}']['entrypoint']
    if epoch > 1 and '--install-handoff-epoch' not in root_entry:
        override['services'][f'root{j}']['entrypoint'] = root_entry + ['--install-handoff-epoch', str(epoch)]
        override_path.write_text(json.dumps(override, indent=1, sort_keys=True) + '\n')
    rec.dc('up', '-d', '--no-deps', f'root{j}')
    r.wait(f'the joiner\'s root {j} answers', lambda: rec.root_view(j), 300)

    # Let the incumbents' result freeze its roster before the joiner's first bond.
    # Hold publication until the bond has landed, so the authority still starts
    # apply in the old scope and has to refresh during the enrollment wait.
    def reserved():
        result = r.view_text(rec.deployment['election'], 'openResult()(bytes32)').strip()
        return result if int(result, 16) else None

    missed_result = r.wait('an election reserved before the joiner bonds', reserved, 900, every=5)
    r.expect(rec.root_view(live)['activeEpoch'] == epoch, 'the bond was held past reservation in the starting root epoch', missed_result)

    mounts = [(auth, '/home/authority')]
    (auth / 'pos-policy-template.json').write_text(json.dumps({'network': json.loads((gen / 'network/vr-deployment.json').read_text())['networkWord'],
        'chainId': r.manifest['chain_id'], 'election': rec.deployment['election']}) + '\n')
    vr_recover.chown(auth)
    applied = rec.cli(live, home, 'validator', 'apply', '--wait', '5m', '--pin-pos-policy', '/home/authority/pos-policy-template.json',
                      mounts=mounts, check=False)
    r.keep_redacted(ev / 'apply-1.log', applied.stdout + applied.stderr)
    text = applied.stdout + applied.stderr
    ident = json.loads((home / 'validator.json').read_text()).get('id')
    r.expect(applied.returncode == 0 and bool(ident) and f'pinned the signing authority\'s P85 scope to identity {ident}' in text,
             'one validator apply registered, bonded and delegated the joiner, pinning its authority to the identity it registered',
             f'{ident}: ' + r.scrub(text.strip()[-300:]))
    r.say(f'  joiner {j}: identity {ident}, owner {owner}: registered, bonded and delegated')

    missed = rec.participate_until(epoch)
    missed_conf = json.loads(rec.fetch(f'root{live}', 'q3', 'shard-conf', '--root-rpc', rec.root_rpc, '--epoch', str(shard_epoch)))
    r.expect(missed == epoch + 1 and len(missed_conf['validators']) == 4 and
             all(v['nodeId'] != info['evm'] for v in missed_conf['validators']),
             f'the result reserved before bond activated shard epoch {shard_epoch} without the joiner', missed_result)
    (ev / 'missed-shard-conf.json').write_text(json.dumps(missed_conf, indent=1) + '\n')
    before = rec.auth_status(j)
    if rec.root_view(j)['activeEpoch'] < missed:
        r.say(f'  joiner {j}: its root is still a follower; installing verified root epoch {missed}')
        if os.environ.get('VR_LATE_JOINER_UNAVAILABLE_PROOF') == '1':
            probe_unavailable_activation(r, rec, j, override_path, epoch, missed, ev)
        install_joiner_root(rec, j, override_path, missed)
    r.wait(f"the joiner's root follows missed root epoch {missed}",
           lambda: rec.root_view(j)['activeEpoch'] >= missed, 300)
    refreshed = advance_joiner(rec, j, auth, missed, j, scope_only=True)
    after = rec.auth_status(j)
    r.expect(refreshed['rootEpoch'] == missed and refreshed['shardEpoch'] == shard_epoch + 1 and
             not after['enrollmentComplete'] and not after['sessionIssued'] and
             after['signingKeyFingerprint'] == before['signingKeyFingerprint'],
             'the same pending authority moved to the next shard epoch', str(refreshed))
    (ev / 'scope-refresh.json').write_text(json.dumps({'before': before, 'refresh': refreshed, 'after': after}, indent=1) + '\n')
    advance_members(r, rec, missed, ev)

    # The next election admits the joiner with the same authority and bond.
    shard_epoch += 1
    parts = {j: (ident, home, auth)}
    target = rec.participate_until(missed, extra=parts, pods={j: live}, watch=live)
    r.expect(target == missed + 1, 'the election immediately after the missed one admits the joiner', str(target))
    ack = r.wait(f'the first certified block of shard epoch {shard_epoch}', lambda: (lambda u: u if u and u['shardEpoch'] == shard_epoch else None)(
        rec.newest_uc(live, epoch=target)), 600, every=2)
    ack_block = int(rec.block(ack['blockHash'])['number'], 16)
    conf = json.loads(rec.fetch(f'root{live}', 'q3', 'shard-conf', '--root-rpc', rec.root_rpc, '--epoch', str(shard_epoch)))
    named = [v for v in conf['validators'] if v['nodeId'] == info['evm']]
    r.expect(bool(named) and len(conf['validators']) == 5, f'shard epoch {shard_epoch} names the joiner\'s EVM node among five validators',
             f'root epoch {target}, block {ack_block}')
    (ev / f'shard-conf-{shard_epoch}.json').write_text(json.dumps(conf, indent=1) + '\n')
    (auth / 'activated-shard.json').write_text(json.dumps(conf))
    vr_recover.chown(auth)

    # the joiner's authority: enrolled under the activated configuration, advanced with the verified activation proofs (validator.py advance)
    rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'complete-enrollment', *vr_recover.OPERATOR, '--shard-conf', '/authority/activated-shard.json')
    advanced = advance_joiner(rec, j, auth, target, live)
    (ev / 'authority-advanced.json').write_text(json.dumps(advanced, indent=1) + '\n')
    r.expect(advanced['rootEpoch'] == target and not advanced['retired'], f'the joiner\'s authority serves root epoch {target}', str(advanced))
    advance_members(r, rec, target, ev)

    # the joiner leads: its shard node submits a leader's certification request, and its builder is never refused (#1321)
    def led():
        log = rec.dc('logs', '--no-color', '--since', started, f'shard{j}', check=False).stdout
        rounds = [l for l in log.splitlines() if 'submitting block certification request' in l and re.search(r'"leader"\s*:\s*true', l)]
        return rounds or None
    rounds = r.wait(f'the joiner {j} leads a round of shard epoch {shard_epoch}', led, 900, every=10)
    log = rec.dc('logs', '--no-color', '--since', started, f'shard{j}', check=False).stdout
    r.keep_redacted(ev / 'shard-joined.log', log)
    refused = [l for l in log.splitlines() if 'gas_limit mismatch' in l or 'refused a build' in l]
    r.expect(not refused, f'the joiner led {len(rounds)} round(s) and its builder was never refused', r.scrub((refused or rounds)[-1][-300:]))
    interval = (r.manifest.get('evm_block') or {}).get('interval_ms', 10000) / 1000
    bound = max(20.0, 2 * interval)
    head = r.wait('15 blocks after the activation', lambda: (lambda h: h if h >= ack_block + 17 else None)(int(r.call('eth_blockNumber'), 16)), 900, every=10)
    times = {n: int(r.call('eth_getBlockByNumber', [hex(n), False])['timestamp'], 16) for n in range(ack_block + 2, head + 1)}
    gap, at = max_gap(times)
    (ev / 'block-times.json').write_text(json.dumps({'ackBlock': ack_block, 'bound': bound, 'times': times}, indent=1) + '\n')
    r.expect(gap <= bound, f'no block gap above {bound:.0f} s with the joiner in the committee (blocks {ack_block + 2}..{head})',
             f'largest {gap} s after block {at}')
    status = r.wait('validator status shows the joiner a member', lambda: (lambda s: s if s.get('member') else None)(
        rec.status(live, home, auth)), 600)
    (ev / 'status-joined.json').write_text(json.dumps(status, indent=1) + '\n')
    state = {'index': j, 'identity': ident, 'owner': owner, 'home': str(home), 'auth': str(auth), 'rootEpoch': target, 'shardEpoch': shard_epoch,
             'ackBlock': ack_block, 'ledRounds': len(rounds), 'largestGap': gap}
    (ev / JOINER_STATE).write_text(json.dumps(state, indent=1) + '\n')
    r.say(f'  joiner {j}: member from root epoch {target}, led {len(rounds)} round(s), largest block gap {gap} s')


def install_joiner_root(rec, j, override_path, epoch, *, probe=False):
    """Reopen the existing follower DB, optionally requesting one verified activation from peers."""
    override = json.loads(override_path.read_text())
    service = f'root{j}'
    root = override['services'][service]
    entry = root['entrypoint']
    for flag in ('--install-handoff-epoch', '--install-handoff-wait'):
        if flag in entry:
            idx = entry.index(flag)
            del entry[idx:idx + 2]
    if epoch is not None and epoch > 1:
        entry += ['--install-handoff-epoch', str(epoch)]
    if probe:
        # A remote proof cannot be fetched within this deadline. Observe the
        # exit so Compose cannot retry the bad invocation itself.
        entry += ['--install-handoff-wait', '1ns']
        root['restart'] = 'no'
    elif root.get('restart') == 'no':
        root['restart'] = 'unless-stopped'
    override_path.write_text(json.dumps(override, indent=1, sort_keys=True) + '\n')
    rec.dc('up', '-d', '--no-deps', service)


def probe_unavailable_activation(r, rec, j, override_path, previous, target, ev):
    service = f'root{j}'
    others = [f'{name}{j}' for name in ('shard', 'ureth', 'authority')]
    def running():
        return [rec.dc('ps', '-q', name).stdout.strip() for name in others]

    before = running()
    r.expect(all(before), 'the joiner’s shard, execution and authority are running before the failed install')
    install_joiner_root(rec, j, override_path, target, probe=True)
    r.wait('the follower exits when the activation proof cannot be fetched',
           lambda: rec.dc('ps', '-a', '--status', 'exited', '-q', service).stdout.strip(), 60)
    r.keep_redacted(ev / 'unavailable-activation.log', rec.dc('logs', '--no-color', service).stdout)
    install_joiner_root(rec, j, override_path, None)
    view = r.wait('the follower reopens the old database after the failed install',
                  lambda: rec.root_view(j), 60)
    r.expect(view['activeEpoch'] == previous and view.get('follower') and
             before == running(),
             'a failed hinted install leaves the shard, execution and authority running and the follower restarts at its old epoch', view)
    # Match the supervisor's backoff before trying the real installation again.
    time.sleep(60)


def advance_joiner(rec, j, auth, target, live, *, scope_only=False):
    """The joiner's authority advanced to root epoch `target` with the verified activation proofs (validator.py advance), and its shard node
    restarted on the new session, as the container restarts it on the activation journal."""
    with tempfile.TemporaryDirectory(prefix='advance-', dir=auth) as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        proofs = []
        for e in range(2, target + 1):
            f = work / f'activation-{e}.cbor'
            f.write_bytes(rec.fetch(f'root{live}', 'q3', 'proof-envelope', '--root-rpc', rec.root_rpc, '--epoch', str(e)))
            f.chmod(0o644)
            proofs += ['--proof', f'/authority/{work.name}/{f.name}']
        vr_recover.chown(work)
        args = ['--scope-only'] if scope_only else ['--client-socket', '/authority/client.sock', '--out', '/authority/client.cred']
        advanced = json.loads(rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'advance-with-proof', *vr_recover.OPERATOR,
                                       *args, *proofs).stdout)
    if not scope_only:
        rec.dc('restart', f'shard{j}')
    return advanced


def advance_members(r, rec, target, ev):
    """The genesis members' authorities to root epoch `target`: each follows it itself, or the operator's advance (vr_advance.py) moves the
    lagging ones and restarts their shard nodes. A rehearsal generation runs no participant containers that would do it."""
    lagging = []
    for m in r.members():
        try:
            if not rec.follows(m):
                raise ValueError('no root-follow mode')
            r.wait(f'authority {m} follows root epoch {target} itself', lambda m=m: rec.auth_status(m)['rootEpoch'] >= target or None, 120)
        except Exception:   # rehearse.Failure (the module runs as __main__)
            lagging.append(m)
    if lagging:
        import vr_advance
        r.say(f'  advancing authorities {lagging} to root epoch {target}')
        vr_advance.advance(r.gen, target, ev / f'advance-{target}', only=lagging)


def tx_selectors(r):
    return {name: r.cast_run('sig', f'{name}({args})') for name, args in (
        ('anchorTerm', 'bytes32,bytes32,bytes32'), ('mature', 'uint256[]'), ('claim', 'uint256,address'), ('requestRetirement', 'uint64'))}


def vr_joiner_exit(r):
    """#1316: the late joiner exits; it sends no election transaction after its retirement request, and its first claim attempt succeeds."""
    rec = vr_recover.Recovery(r, 1)
    rec.since = vr_recover.utc()
    ev = r.evidence / 'late-joiner'
    exit_ev = ev / 'exit'
    exit_ev.mkdir(parents=True, exist_ok=True)
    r.expect((ev / JOINER_STATE).exists(), 'vr-late-joiner joined an entity first', str(ev / JOINER_STATE))
    state = json.loads((ev / JOINER_STATE).read_text())
    j, ident, owner = state['index'], state['identity'], state['owner']
    home, auth = Path(state['home']), Path(state['auth'])
    live, mounts = 1, [(auth, '/home/authority')]
    custody, election, registry = rec.deployment['custody'].lower(), rec.deployment['election'].lower(), rec.deployment['registry'].lower()
    parts = rec.participants(extra={j: (ident, home, auth)})
    outputs = {}

    # 1. the retirement request
    done = rec.cli(live, home, 'validator', 'exit', mounts=mounts)
    r.keep_redacted(exit_ev / 'exit.log', done.stdout + done.stderr)
    r.expect('retirement requested' in done.stdout, f'validator exit requested identity {ident}\'s retirement', r.scrub(done.stdout.strip()[-300:]))
    # the block of the requestRetirement receipt (`sent: <hash>, included in block N`): the owner's later transactions are scanned from it
    found = re.findall(r'included in block (\d+)', done.stdout)
    r.expect(bool(found), 'validator exit printed the block of its requestRetirement receipt', r.scrub(done.stdout.strip()[-300:]))
    exit_block = int(found[-1])
    epoch = rec.root_view(live)['activeEpoch']

    # 2. the next election excludes it; the joiner's own participation sends nothing
    target = rec.participate_until(epoch, extra={j: (ident, home, auth)}, pods={j: live}, watch=live, outputs=outputs)
    excluded = r.wait(f'the committee of root epoch {target} or later no longer has identity {ident}',
                      lambda: (lambda s: s if not s.get('member') else None)(rec.status(live, home, auth)), 900, every=10)
    (exit_ev / 'status-excluded.json').write_text(json.dumps(excluded, indent=1) + '\n')
    r.say(f'  identity {ident} excluded at root epoch {target}')
    advance_members(r, rec, target, exit_ev)
    active = target

    # 3. the claim watcher: every minute the members' participation, then the preview; an anchoring run when it plans one; then the claim
    attempts, anchors, deadline = 0, 0, time.monotonic() + 100 * 60
    claimed = None
    watch = exit_ev / 'claim-watch.jsonl'
    while time.monotonic() < deadline and claimed is None:
        rec.participate_once(parts, {j: live}, outputs)
        now = rec.root_view(live)
        if now['activeEpoch'] > active and not (now.get('switch') and now['switch']['phase'] not in ('running', 'following')):
            active = now['activeEpoch']
            r.say(f'  root epoch {active} activated during the wait')
            advance_members(r, rec, active, exit_ev)
        dry = rec.cli(live, home, 'validator', 'claim', '--dry-run', mounts=mounts, check=False)
        text = r.scrub(dry.stdout + dry.stderr)
        with watch.open('a') as w:
            w.write(json.dumps({'utc': vr_recover.utc(), 'exit': dry.returncode, 'preview': text}) + '\n')
        if '[anchor]' in text:
            anchors += 1
            run = rec.cli(live, home, 'validator', 'claim', mounts=mounts, check=False)
            (exit_ev / f'anchor-{anchors}.log').write_text(r.scrub(run.stdout + run.stderr).rstrip('\n') + f'\nrc={run.returncode}\n')
            r.say(f'  anchoring run {anchors}: exit {run.returncode}')
        elif dry.returncode == 0 and 'REFUSED' not in text and 'not run' not in text:
            attempts += 1
            run = rec.cli(live, home, 'validator', 'claim', mounts=mounts, check=False)
            (exit_ev / f'claim-attempt-{attempts}.log').write_text(r.scrub(run.stdout + run.stderr).rstrip('\n') + f'\nrc={run.returncode}\n')
            r.say(f'  claim attempt {attempts}: exit {run.returncode}')
            if run.returncode == 0:
                claimed = run
                break
        time.sleep(60)
    r.expect(claimed is not None, f'the claim succeeded within 100 minutes ({attempts} attempt(s), {anchors} anchoring run(s))', str(watch))
    r.expect(attempts == 1, 'the first claim attempt after maturity succeeded', f'claim-attempt-1..{attempts}.log')
    r.expect('claimed' in claimed.stdout, 'the claim withdrew the bond to the owner', r.scrub(claimed.stdout.strip()[-200:]))
    (exit_ev / 'participation.json').write_text(json.dumps(outputs, indent=1) + '\n')

    # 4. the joiner's participation after its retirement request said "no election transactions" every time, and its owner sent only custody steps
    mine = outputs.get(j, [])
    r.expect(bool(mine) and all('no election transactions' in o['output'] and o['exit'] == 0 for o in mine),
             f'the exited identity\'s own pos-publish --participate sent nothing on {len(mine)} open result(s)', json.dumps(mine[-1:])[:300])
    sel = tx_selectors(r)
    allowed = {sel['anchorTerm'], sel['mature'], sel['claim'], sel['requestRetirement']}
    head = int(r.call('eth_blockNumber'), 16)
    sent = []
    for n in range(exit_block, head + 1):
        for tx in r.call('eth_getBlockByNumber', [hex(n), True])['transactions']:
            if tx['from'].lower() == owner.lower():
                rc = r.call('eth_getTransactionReceipt', [tx['hash']])
                sent.append({'block': n, 'to': (tx.get('to') or '').lower(), 'selector': tx['input'][:10], 'status': rc['status'], 'hash': tx['hash']})
    (exit_ev / 'owner-txs.json').write_text(json.dumps(sent, indent=1) + '\n')
    election_txs = [t for t in sent if t['to'] in (election, registry) or t['selector'] not in allowed]
    r.expect(not election_txs, f'every transaction of the owner from the retirement request on is a custody step ({len(sent)}), none an election one',
             json.dumps(election_txs[:2]))
    r.expect(all(t['to'] == custody and t['status'] == '0x1' for t in sent), 'every one of them went to custody and succeeded', json.dumps(sent)[:300])


def publication_summary(txs, *, exclude=()):
    """Per result: how many finalizeCandidate and VR.publish transactions were sent, how many reverted, and their gas."""
    out = {}
    for t in txs:
        if t['result'] in exclude:
            continue
        k = out.setdefault(t['result'], {'finalizeCandidate': 0, 'finalizeReverted': 0, 'VR.publish': 0, 'publishReverted': 0, 'gas': 0, 'wastedGas': 0})
        k[t['kind']] += 1
        k['gas'] += t['gasUsed']
        if t['status'] != '0x1':
            k['finalizeReverted' if t['kind'] == 'finalizeCandidate' else 'publishReverted'] += 1
    for rid, k in out.items():   # every transaction but the first successful one of its kind does nothing useful
        ok = [t for t in txs if t['result'] == rid and t['status'] == '0x1']
        firsts = {}
        for t in ok:
            firsts.setdefault(t['kind'], t)
        k['wastedGas'] = sum(t['gasUsed'] for t in txs if t['result'] == rid and firsts.get(t['kind']) is not t)
    return out


def vr_finalizer(r):
    """#1323: the finalizeCandidate and VR.publish race without the finalizer order, and the single finalizer with it."""
    rec = vr_recover.Recovery(r, 1)
    rec.since = vr_recover.utc()
    ev = r.evidence / 'finalizer'
    ev.mkdir(parents=True, exist_ok=True)
    extra, pods = {}, {}
    joined = r.evidence / 'late-joiner' / JOINER_STATE
    if joined.exists():
        state = json.loads(joined.read_text())
        extra = {state['index']: (state['identity'], Path(state['home']), Path(state['auth']))}
        pods = {state['index']: 1}
    report = {}
    before_results = set()
    # 'after' names the default step (180 s since the second #1323 lane run) explicitly, so a run against an image built before it measures the
    # same order
    for name, step in (('before', '0s'), ('after', '180s')):
        rec.finalizer_step = step
        epoch = rec.root_view(1)['activeEpoch']
        first = int(r.call('eth_blockNumber'), 16)
        outputs = {}
        target = rec.participate_polling(epoch, rec.participants(extra=extra), pods=pods, outputs=outputs)
        last = int(r.call('eth_blockNumber'), 16)
        txs = rec.publication_txs(first, last)
        summary = publication_summary(txs, exclude=before_results)
        if name == 'before':
            before_results = set(summary)
        report[name] = {'finalizerStep': step or 'default', 'rootEpoch': target, 'blocks': [first, last], 'results': summary, 'txs': txs}
        (ev / f'participation-{name}.json').write_text(json.dumps(outputs, indent=1) + '\n')
        totals = {k: sum(v[k] for v in summary.values()) for k in ('finalizeCandidate', 'finalizeReverted', 'VR.publish', 'publishReverted', 'wastedGas')}
        report[name]['totals'] = totals
        r.say(f'  {name} (--finalizer-step {step or "default"}): root epoch {target}: {totals}')
        advance_members(r, rec, target, ev)
        for j, (ident, home, auth) in extra.items():
            if rec.status(1, home, auth).get('member'):
                advanced = advance_joiner(rec, j, auth, target, 1)
                r.say(f'  joiner {j}: authority at root epoch {advanced["rootEpoch"]} (retired: {advanced["retired"]})')
    (ev / 'finalizer.json').write_text(json.dumps(report, indent=1) + '\n')
    after = report['after']['totals']
    published = [k for k in report['after']['results'].values() if k['VR.publish']]
    r.expect(len(published) == 1 and after['finalizeCandidate'] == 1 and after['VR.publish'] == 1,
             'with the finalizer order one member sent the election\'s finalizeCandidate and VR.publish, once each', json.dumps(after))
    r.expect(after['finalizeReverted'] == 0 and after['publishReverted'] == 0, 'none of them reverted',
             f'before: {json.dumps(report["before"]["totals"])}; after: {json.dumps(after)}')
