#!/usr/bin/env python3
"""vr-pos-recover (#1286): recover a bonded genesis identity of a Compose VR/P85 generation whose EVM signing authority is lost.

A new EVM key is a new EVM node identity. The stage kills only validator i's authority container (by its exact name), keeps that authority's
directory and fail-stop marker, and builds a fresh node slot beside it, validator<i>/recover-<k>/: a fresh authority directory (auth/), a fresh
shard node key in an empty shard home (evm/), an empty archive and an empty execution data directory (ureth/: a fresh shard node cannot
admit an execution head certified in an epoch its own verified history does not hold yet, so it syncs the execution from genesis, as a joiner). `ubft validator recover` (the owner's key, the unchanged root key) admits the
delegation of the new EVM node and key at custody's generation, then stages the identical VR binding. compose.recover.json points the
entity's authority, root (possession-proof endpoint) and shard node at the slot; the shard node starts as a staging-only joiner that follows
the other shard nodes. Every frozen member then submits its own possession proof (the stage runs each member's `pos-publish --participate`)
and anyone publishes; the roots activate the next epoch, the fresh authority is enrolled under the activated shard configuration and advanced
with the verified activation proofs.

Asserted: `validator status` shows the identity a member with the new EVM node and key as VR's current binding (localKeys current) at the
unchanged generation, its lots unchanged; the fresh authority serves the activated epoch and signs (its reserved round rises); the root's
newest verified UC of the new epoch carries that root's individual signature; the old authority directory, its marker and the old shard home
are unchanged and mounted by no container.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

import handoff_ops
import operator_rpc

OPERATOR = ['--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred']
NODE_PARTS = ('auth', 'evm', 'archive', 'ureth')
REFUSAL = ('VR Freeze refused', 'EVM-only validator change', 'registry output refused')


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def b64int(value):
    return int.from_bytes(base64.b64decode(value), 'big')


def b64address(value):
    return '0x' + base64.b64decode(value).hex()


def genesis_identity(gen, i):
    """(identity id, payee, root node id, EVM node id) of validator i's genesis identity: the genesis-identities.json entry of its root node."""
    root = json.loads((gen / f'validator{i}/root/node-info.json').read_text())['nodeId']
    found = [m for m in json.loads((gen / 'network/genesis-identities.json').read_text()) if m['rootNodeId'] == root]
    if len(found) != 1:
        raise ValueError(f'validator{i}: {len(found)} genesis identities name root {root}')
    m = found[0]
    return b64int(m['stakingId']), b64address(m['operatorPayee']), root, m['evmNodeId']


def owner_key(gen, manifest, address):
    """The DEV owner key of a genesis identity (vr_dev_keys: payee = owner)."""
    keys = json.loads((gen / manifest['pos']['owner_keys'] / 'keys.json').read_text())['owners']
    found = [k['privateKey'] for k in keys if k['address'].lower() == address.lower()]
    if len(found) != 1:
        raise ValueError(f'no single DEV owner key for {address}')
    return found[0]


def mount_source(service, target):
    """The host path (relative to the generation) a Compose service mounts at `target`."""
    for volume in service.get('volumes', []):
        source, _, rest = volume.partition(':')
        if rest.split(':')[0] == target:
            return source
    raise ValueError(f'no volume at {target}')


def authority_dir(gen, compose, i):
    """The host directory authority i runs in now (compose.recover.json moves a recovered entity's)."""
    return (Path(gen) / mount_source(compose['services'][f'authority{i}'], '/authority')).resolve()


def next_slot(gen, i):
    k = 2
    while (Path(gen) / f'validator{i}/recover-{k}').exists():
        k += 1
    return k


def replace_volume(volumes, target, source):
    out, done = [], False
    for volume in volumes:
        parts = volume.split(':')
        if parts[1] == target:
            out.append(':'.join([source, target, *parts[2:]]))
            done = True
        else:
            out.append(volume)
    if not done:
        raise ValueError(f'no volume at {target}')
    return out


def authority_entrypoint(entry, evm_node, root_epoch, shard_epoch, trust, genesis_hash):
    """The fresh authority's entrypoint from the genesis one: the new EVM node, the scope it will sign in (the current root epoch, the
    successor shard epoch), a binding registration policy, and the joiner's activation pins instead of the genesis fence provisioning
    (it advances with verified activation proofs, as the container joiner does: no root-follow mode)."""
    out, skip = [], 0
    drop = {'--fence-provision-file': 1, '--follow-root-activations': 1, '--follow-client-credential': 1}
    values = {'--node-id': evm_node, '--root-epoch': str(root_epoch), '--shard-epoch': str(shard_epoch), '--trust-base': trust}
    for n, arg in enumerate(entry):
        if skip:
            skip -= 1
            continue
        if arg in drop:
            skip = drop[arg]
            continue
        if n and entry[n - 1] in values:
            out.append(values[entry[n - 1]])
            continue
        out.append(arg)
    if '--authority-id' in out:
        out[out.index('--authority-id') + 1] += '-recovered'
    for flag in ('--node-id', '--root-epoch', '--shard-epoch', '--trust-base', '--pop-socket', '--require-pos-policy'):
        if flag not in out:
            raise ValueError(f'the genesis authority entrypoint has no {flag}')
    return out + ['--registration-policy', '/authority/registration.json', '--b1-profile', '/network/b1-profile.json',
                  '--activation-source-url', 'http://127.0.0.1:8545', '--execution-genesis-hash', genesis_hash]


def recover_services(compose, i, slot, evm_node, root_epoch, shard_epoch, trust, genesis_hash):
    """compose.recover.json's services for entity i on node slot `slot` (validator<i>/recover-<slot>/): its authority, root, execution client
    and shard node."""
    base = f'./validator{i}/recover-{slot}'
    svc = compose['services']
    authority = dict(svc[f'authority{i}'])
    authority['entrypoint'] = authority_entrypoint(authority['entrypoint'], evm_node, root_epoch, shard_epoch, trust, genesis_hash)
    authority['volumes'] = replace_volume(authority['volumes'], '/authority', f'{base}/auth')
    root = dict(svc[f'root{i}'])
    root['volumes'] = replace_volume(root['volumes'], '/pop', f'{base}/auth/pop')
    shard = dict(svc[f'shard{i}'])
    volumes = shard['volumes']
    for target, part in (('/state', 'evm'), ('/authority', 'auth'), ('/archive', 'archive')):
        volumes = replace_volume(volumes, target, f'{base}/{part}')
    shard['volumes'] = volumes
    entry = list(shard['entrypoint'])
    if '--follow-source' not in entry:
        # a staging-only joiner: it follows the other shard nodes until the verified activation that names it
        others = [b for b in entry[entry.index('--bootnodes') + 1].split(',') if '/dns4/shard' in b]
        entry += ['--follow-source', ','.join(others)]
    shard['entrypoint'] = entry
    ureth = dict(svc[f'ureth{i}'])
    ureth['volumes'] = replace_volume(ureth['volumes'], '/state', f'{base}/ureth')
    return {f'authority{i}': authority, f'root{i}': root, f'shard{i}': shard, f'ureth{i}': ureth}


def operator_config(manifest, deployment, payee, ident):
    return {'format': 'unicity.validator.config.v1', 'rpc': 'http://127.0.0.1:8545', 'localRpc': 'http://127.0.0.1:8545',
            'registry': deployment['registry'], 'chainId': manifest['chain_id'], 'rootKeys': 'root/keys.json', 'evmKeys': '',
            'evmAuthority': {'socket': 'authority/operator.sock', 'credential': 'authority/operator.cred', 'nodeInfo': 'authority/node-info.json'},
            'urethKey': 'ureth-key/p2p-secret', 'jwt': 'jwt/jwt.hex', 'operatorKey': 'operator/owner.key', 'payee': payee, 'id': ident,
            'dataDir': '.', 'ports': [8000, 9000, 30303]}


def chown(path):
    if os.geteuid() == 0:
        for p in [path, *Path(path).rglob('*')]:
            os.chown(p, 10001, 10001)


def tree(path):
    """{relative path: sha256} of the regular files under `path` (sockets and links are skipped)."""
    out = {}
    for p in sorted(Path(path).rglob('*')):
        if p.is_file() and not p.is_symlink():
            out[str(p.relative_to(path))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class Recovery:
    def __init__(self, r, index):
        self.r, self.gen, self.i = r, r.gen, index
        self.manifest = r.manifest
        self.deployment = json.loads((self.gen / 'network/deployment.json').read_text())
        self.compose = handoff_ops.load_compose(self.gen)
        self.project = self.compose['name']
        self.root_rpc = operator_rpc.common_urls(self.compose)[0]
        self.image = self.compose['services'][f'root{index}']['image']
        self.transport = handoff_ops.DockerTransport(self.gen)
        self.ev = r.evidence / 'recover'
        self.ev.mkdir(parents=True, exist_ok=True)

    # --- docker -------------------------------------------------------------------------------------------------------------------
    def dc(self, *args, check=True):
        return subprocess.run(['docker', 'compose', *handoff_ops.compose_files(self.gen), *args], check=check, text=True, capture_output=True)

    def exec(self, service, *args, check=True):
        return self.dc('exec', '-T', service, *args, check=check)

    def fetch(self, service, *args):
        """Run a ubft command in `service` that writes --out /tmp/<x>, and return the file's bytes."""
        remote = '/tmp/' + uuid.uuid4().hex
        try:
            self.exec(service, 'ubft', *args, '--out', remote)
            return subprocess.run(['docker', 'compose', *handoff_ops.compose_files(self.gen), 'exec', '-T', service, 'cat', remote],
                                  check=True, capture_output=True).stdout
        finally:
            self.exec(service, 'rm', '-f', '--', remote, check=False)

    def container(self, service):
        cid = self.dc('ps', '-q', service).stdout.strip()
        if not cid:
            return None
        return subprocess.run(['docker', 'inspect', '--format', '{{.Name}}', cid], check=True, text=True, capture_output=True).stdout.strip().lstrip('/')

    def cli(self, pod, home, *args, mounts=(), check=True):
        """`ubft` as the operator, in entity `pod`'s network namespace (its own ureth at 127.0.0.1:8545), with the operator home mounted."""
        command = ['docker', 'run', '--rm', '--network', f'container:{self.transport.holder(pod)}', '--user', '10001:10001', '--read-only',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp', '-e', 'HOME=/tmp', '-e', 'UBFT_HOME=/home',
                   '-v', f'{home}:/home']
        for source, target in mounts:
            command += ['-v', f'{source}:{target}']
        done = subprocess.run(command + ['--entrypoint', 'ubft', self.image, *args], text=True, capture_output=True, timeout=600)
        if check and done.returncode:
            raise RuntimeError(f'ubft {" ".join(args[:2])} in pod{pod}: exit {done.returncode}: {self.r.scrub(done.stderr.strip()[-600:])}')
        return done

    def root_view(self, i):
        code, body = self.transport.post(i, '/api/v1/q3/status', b'{}')
        if code != 200:
            raise RuntimeError(f'root{i} status {code}')
        return json.loads(body)

    def auth_status(self, i):
        return json.loads(self.exec(f'authority{i}', 'ubft', 'signing-authority', 'status', *OPERATOR).stdout)

    # --- operator homes -----------------------------------------------------------------------------------------------------------
    def home(self, m, name):
        """An operator home for genesis entity m (validator.json, its root keys, its owner key), under validator<m>/<name>/."""
        ident, payee, _, _ = genesis_identity(self.gen, m)
        v = self.gen / f'validator{m}'
        home = v / name
        if home.exists():
            return home
        home.mkdir(mode=0o700)
        for rel in ('root/keys.json', 'root/node-info.json', 'jwt/jwt.hex', 'ureth-key/p2p-secret'):
            (home / rel).parent.mkdir(mode=0o700, exist_ok=True)
            shutil.copyfile(v / rel, home / rel)
        (home / 'operator').mkdir(mode=0o700)
        (home / 'operator/owner.key').write_text(owner_key(self.gen, self.manifest, payee).strip() + '\n')
        for mountpoint in ('authority', 'authority-new'):   # where the stage mounts the authority directories
            (home / mountpoint).mkdir(mode=0o700)
        (home / 'validator.json').write_text(json.dumps(operator_config(self.manifest, self.deployment, payee, ident)) + '\n')
        chown(home)
        self.r.rescan()
        return home

    def status(self, pod, home, auth):
        done = self.cli(pod, home, 'validator', 'status', '--custody', self.deployment['custody'], '--json', mounts=[(auth, '/home/authority:ro')])
        return json.loads(done.stdout)

    # --- the stage ----------------------------------------------------------------------------------------------------------------
    def run(self):
        r, gen, i = self.r, self.gen, self.i
        self.since = utc()
        times = self.times = {'start': self.since}
        r.expect(r.ubft is not None, 'vr-pos-recover has the pinned ubft (--ubft): it makes the fresh shard node key and credentials')
        members = r.members()
        r.expect(i in members and len(members) >= 4, f'validator {i} is an active member of a committee of at least four', str(members))
        live = next(m for m in members if m != i)
        ident, payee, root_node, old_evm = genesis_identity(gen, i)
        old_auth = authority_dir(gen, self.compose, i)
        old_evm_dir = (gen / mount_source(self.compose['services'][f'shard{i}'], '/state')).resolve()
        old_ureth_dir = (gen / mount_source(self.compose['services'][f'ureth{i}'], '/state')).resolve()
        r.say(f'  validator {i}: identity {ident}, root {root_node}, EVM node {old_evm}; transactions through pod{live}')
        home = self.home(i, f'recover-operator')
        before = self.status(live, home, old_auth)
        (self.ev / 'status-before.json').write_text(json.dumps(before, indent=1) + '\n')
        r.expect(before.get('member') and before.get('evmNodeId') == old_evm, 'before: the identity is a member on its genesis EVM node', f'generation {before.get("generation")}')
        lots_before = self.position(ident)

        # 1. the loss: the old authority's marker (the container writes it before an authority first starts), then only its container dies
        marker = old_auth / 'lifetime'
        if not marker.exists():
            marker.write_text('fail-stop\n')
            chown(marker)
            r.say('  note: this generation predates the generated fail-stop marker; written now, before the loss')
        old_status = self.auth_status(i)
        old_tree = tree(old_auth)
        old_evm_tree = sorted(p.name for p in old_evm_dir.iterdir())
        name = self.container(f'authority{i}')
        r.expect(bool(name) and name.startswith(self.project + '-'), f'authority{i} runs as a container of this generation', str(name))
        subprocess.run(['docker', 'rm', '-f', name], check=True, capture_output=True)
        r.expect(self.container(f'authority{i}') is None, f'only {name} was removed; its directory and marker stay', str(old_auth))
        lost = time.monotonic()
        times['loss'] = utc()
        # the committee certifies on n-1 signers again (the fault transition) before the owner's transactions are sent
        first = int(r.call('eth_blockNumber'), 16)
        resumed = r.wait('the chain makes progress without the lost signer', lambda: (lambda b: b if b >= first + 2 else None)(int(r.call('eth_blockNumber'), 16)), 900)
        r.say(f'  blocks {first} -> {resumed}, {time.monotonic() - lost:.0f} s after the loss')

        # 2. the fresh slot: authority directory, shard node key, empty shard data, archive and execution data
        k = next_slot(gen, i)
        slot = gen / f'validator{i}/recover-{k}'
        auth = slot / 'auth'
        (auth / 'pop').mkdir(parents=True, mode=0o700)
        for part in ('archive', 'ureth'):
            (slot / part).mkdir(mode=0o700)
        subprocess.run([str(r.ubft), 'shard-node', 'init', '--home', str(slot / 'evm'), '--generate'], check=True, capture_output=True)
        new_evm = subprocess.run([str(r.ubft), 'node-id', '--home', str(slot / 'evm')], check=True, capture_output=True, text=True).stdout.strip().splitlines()[-1]
        r.expect(new_evm != old_evm, 'the fresh shard node key is a new EVM node identity', new_evm)
        for cred in ('operator.cred', 'pop/pop.cred'):
            subprocess.run([str(r.ubft), 'signing-authority', 'credential', '--out', str(auth / cred)], check=True, capture_output=True)
        epoch = self.root_view(i)['activeEpoch']
        certified = json.loads(self.exec(f'root{live}', 'ubft', 'validator', 'last-signed-uc', '--execution', 'http://127.0.0.1:8545',
                                         '--root-rpc', self.root_rpc, '--epoch', str(epoch)).stdout)
        r.expect(certified and certified['rootEpoch'] == epoch, f'a verified UC of root epoch {epoch} names the certified shard epoch', str(certified))
        shard_epoch = certified['shardEpoch'] + 1
        trust = '/network/trust-base.json'
        if epoch > 1:
            (auth / 'current-trust.json').write_bytes(self.fetch(f'root{i}', 'q3', 'trust-base', '--root-rpc', self.root_rpc, '--epoch', str(epoch)))
            trust = '/authority/current-trust.json'
        root_info = json.loads((gen / f'validator{i}/root/node-info.json').read_text())
        vr = json.loads((gen / 'network/vr-deployment.json').read_text())
        (auth / 'registration.json').write_text(json.dumps({'network': vr['networkWord'], 'chainId': self.manifest['chain_id'],
            'registry': self.deployment['registry'], 'authorized': [{'action': 'binding', 'owner': payee, 'id': ident, 'payee': payee,
                                                                       'rootNodeId': root_info['nodeId'], 'rootKey': root_info['sigKey']}]}) + '\n')
        (auth / 'pos-policy.json').write_text(json.dumps({'network': vr['networkWord'], 'chainId': self.manifest['chain_id'],
                                                         'election': self.deployment['election'], 'ids': [ident]}) + '\n')
        (auth / 'lifetime').write_text('fail-stop\n')
        services = recover_services(self.compose, i, k, new_evm, epoch, shard_epoch, trust, self.manifest['genesis_hash'])
        (gen / handoff_ops.RECOVER_OVERRIDE).write_text(json.dumps({'services': services}, indent=1, sort_keys=True) + '\n')
        chown(slot)
        r.rescan()
        r.say(f'  slot recover-{k}: EVM node {new_evm}, scope root epoch {epoch} / shard epoch {shard_epoch}')

        # 3. the fresh authority, then the two transactions (delegation first), from the owner's wallet
        self.dc('up', '-d', '--no-deps', f'authority{i}')
        r.wait('the fresh authority answers', lambda: self.auth_status(i), 60)
        self.exec(f'authority{i}', 'ubft', 'signing-authority', 'node-info', *OPERATOR, '--out', '/authority/node-info.json')
        self.exec(f'authority{i}', 'ubft', 'signing-authority', 'pos-policy', *OPERATOR, '--policy', '/authority/pos-policy.json')
        info = json.loads((auth / 'node-info.json').read_text())
        r.expect(info['nodeId'] == new_evm, 'the fresh authority is enrolled for the new EVM node', info['sigKey'])
        new_status = self.auth_status(i)
        r.expect(new_status['signingKeyFingerprint'] != old_status['signingKeyFingerprint'], 'the fresh authority holds a new key',
                 new_status['signingKeyFingerprint'])
        mounts = [(old_auth, '/home/authority:ro'), (auth, '/home/authority-new')]
        # A result that is open now froze the old, dead key: it never publishes and ends only by RejectResult after its reservation
        # lifetime (the incumbents continue meanwhile). Recovery fences later snapshots only, so the rehearsal needs none open here.
        open_before = r.view_text(self.deployment['election'], 'openResult()(bytes32)').strip()
        r.expect(int(open_before, 16) == 0, 'no election result is open before the delegation (an open one froze the old key and only '
                 'RejectResult ends it: rehearse with an election cadence longer than the recovery)', open_before)
        refused = self.cli(live, home, 'validator', 'recover', '--old-authority-home', 'authority-new', '--new-evm-authority-socket',
                           'authority-new/operator.sock', '--new-evm-authority-credential', 'authority-new/operator.cred',
                           '--new-evm-node-info', 'authority-new/node-info.json', mounts=mounts, check=False)
        r.expect(refused.returncode != 0 and 'marked volume' in refused.stderr, 'recover refuses a new authority inside the named old volume',
                 r.scrub(refused.stderr.strip()[-200:]))
        done = self.cli(live, home, 'validator', 'recover', '--old-authority-home', 'authority', '--new-evm-authority-socket',
                        'authority-new/operator.sock', '--new-evm-authority-credential', 'authority-new/operator.cred',
                        '--new-evm-node-info', 'authority-new/node-info.json', '--wait', '10m', mounts=mounts)
        r.keep_redacted(self.ev / 'recover.log', done.stdout + done.stderr)
        r.say(f'  recover confirmed {time.monotonic() - lost:.0f} s after the loss')
        times['recoverConfirmed'] = utc()
        r.expect('confirmed: VR stages identity' in done.stdout, 'recover: the delegation, then the identical VR binding, confirmed', r.scrub(done.stdout.strip()[-400:]))
        again = self.cli(live, home, 'validator', 'recover', '--old-authority-home', 'authority', '--new-evm-authority-socket',
                         'authority-new/operator.sock', '--new-evm-authority-credential', 'authority-new/operator.cred',
                         '--new-evm-node-info', 'authority-new/node-info.json', mounts=mounts)
        r.expect('nothing to do' in again.stdout, 'a re-run of recover sends nothing', r.scrub(again.stdout.strip()[-200:]))

        # 4. the entity's execution client, root and shard node on the slot: an empty execution data directory, the root's possession-proof
        # endpoint, a staging-only joiner shard node that drives the execution from genesis
        self.dc('up', '-d', '--no-deps', f'ureth{i}', f'root{i}', f'shard{i}')
        r.wait(f'root{i} answers again', lambda: self.root_view(i), 180)
        time.sleep(15)
        running = self.dc('ps', '--status', 'running', '--services').stdout.split()
        r.expect(f'shard{i}' in running, f'the fresh shard node shard{i} stays up as a staging-only joiner')

        # 5. the next election: every frozen member proves possession itself, anyone publishes; the roots activate the next epoch
        target = self.participate_until(epoch, {i: home}, {i: live}, watch=live)
        times['activated'] = utc()
        # the roots admitted the recovered committee's Freeze: the epoch activated, and no root logged a refusal since the stage started
        handoff = ''.join(self.logs(f'root{m}') for m in members)
        r.keep_redacted(self.ev / 'root-handoff.log', '\n'.join(l for l in handoff.splitlines() if 'VR handoff' in l or any(x in l for x in REFUSAL)))
        refused = [l for l in handoff.splitlines() if any(x in l for x in REFUSAL)]
        r.expect(not refused, f'the roots admitted the recovered committee\'s Freeze and activated root epoch {target} (no refusal logged)',
                 f'{sum("ordering the" in l for l in handoff.splitlines())} ordering lines; root-handoff.log')
        ack = r.wait(f'the first certified block of shard epoch {shard_epoch} (the acknowledgement)', lambda: (lambda u: u if u and u['shardEpoch'] == shard_epoch else None)(
            self.newest_uc(live, epoch=target)), 600, every=2)
        times['ackObserved'] = utc()
        ack['block'] = self.block(ack['blockHash'])
        (self.ev / 'ack-uc.json').write_text(json.dumps(ack, indent=1) + '\n')
        r.expect(True, f'a verified UC of shard epoch {shard_epoch} certifies the successor\'s first observed block',
                 f'block {ack["block"]["number"]} with {len(ack["block"]["transactions"])} transaction(s), shard round {ack["shardRound"]}')
        conf = json.loads(self.fetch(f'root{i}', 'q3', 'shard-conf', '--root-rpc', self.root_rpc, '--epoch', str(shard_epoch)))
        named = [v for v in conf['validators'] if v['nodeId'] == new_evm]
        r.expect(named and named[0]['sigKey'].lower() == info['sigKey'].lower() and old_evm not in [v['nodeId'] for v in conf['validators']],
                 f'shard epoch {shard_epoch} names the new EVM node with the fresh key and not the old node', f'root epoch {target}')
        retired = json.loads((old_auth / 'node-info.json').read_text())['sigKey'].lower()
        r.expect(retired not in [v['sigKey'].lower() for v in conf['validators']], f'the retired EVM key is not in shard epoch {shard_epoch}', retired)
        (self.ev / f'shard-conf-{shard_epoch}.json').write_text(json.dumps(conf, indent=1) + '\n')
        (auth / 'activated-shard.json').write_text(json.dumps(conf))
        chown(auth / 'activated-shard.json')

        # 6. the fresh authority: enrolled under the activated configuration, advanced with the verified activation proofs
        self.exec(f'authority{i}', 'ubft', 'signing-authority', 'complete-enrollment', *OPERATOR, '--shard-conf', '/authority/activated-shard.json')
        with tempfile.TemporaryDirectory(prefix='advance-', dir=auth) as tmp:
            work = Path(tmp)
            work.chmod(0o755)
            proofs = []
            for e in range(2, target + 1):
                f = work / f'activation-{e}.cbor'
                f.write_bytes(self.fetch(f'root{i}', 'q3', 'proof-envelope', '--root-rpc', self.root_rpc, '--epoch', str(e)))
                f.chmod(0o644)
                proofs += ['--proof', f'/authority/{work.name}/{f.name}']
            chown(work)
            advanced = json.loads(self.exec(f'authority{i}', 'ubft', 'signing-authority', 'advance-with-proof', *OPERATOR,
                                            '--client-socket', '/authority/client.sock', '--out', '/authority/client.cred', *proofs).stdout)
        (self.ev / 'authority-advanced.json').write_text(json.dumps(advanced, indent=1) + '\n')
        r.expect(advanced['rootEpoch'] == target and not advanced['retired'], f'the fresh authority serves root epoch {target}', str(advanced))
        lagging = []
        for m in members:
            if m == i:
                continue
            try:
                if not self.follows(m):
                    raise ValueError('no root-follow mode')
                r.wait(f'authority {m} follows root epoch {target} itself', lambda m=m: self.auth_status(m)['rootEpoch'] >= target or None, 120)
            except Exception:   # rehearse.Failure: not within the wait (the module runs as __main__, its class is not importable here)
                lagging.append(m)
        if lagging:
            import vr_advance   # an authority without root-follow mode: the operator's advance, as vr-pos-advance
            r.say(f'  advancing authorities {lagging} to root epoch {target}')
            vr_advance.advance(gen, target, self.ev / 'advance', only=lagging)

        # 7. a user block in the new shard epoch: a plain value transfer through the gateway, mined and certified, the fresh authority signing
        times['advanced'] = utc()
        before_user = self.auth_status(i)
        receipt = self.transfer()
        times['userMined'] = utc()
        mined = int(receipt['blockNumber'], 16)
        user = r.wait(f'a verified UC of shard epoch {shard_epoch} certifies the user block {mined}', lambda: (lambda u: u if u and u['shardEpoch'] >= shard_epoch
            and int(self.block(u['blockHash'])['number'], 16) >= mined else None)(self.newest_uc(live)), 600, every=3)
        times['userCertified'] = utc()
        user['block'] = self.block(user['blockHash'])
        user['transfer'] = receipt['transactionHash']
        (self.ev / 'user-block-uc.json').write_text(json.dumps(user, indent=1) + '\n')
        r.expect(receipt['status'] == '0x1', f'the transfer is mined in block {mined} and certified in shard epoch {user["shardEpoch"]}',
                 f'{receipt["transactionHash"]}, UC shard round {user["shardRound"]}')
        rose = r.wait('the fresh authority\'s reserved round rises across the user block',
                      lambda: (lambda s: s if s['reservedRound'] > before_user['reservedRound'] else None)(self.auth_status(i)), 300)
        r.expect(True, 'the fresh authority signs in the new shard epoch', f'reserved round {before_user["reservedRound"]} -> {rose["reservedRound"]}')
        r.keep_redacted(self.ev / f'shard{i}-recovered.log', self.logs(f'shard{i}'))

        # 8. the assertions
        after = r.wait('validator status shows the identity a member on the new EVM node',
                       lambda: (lambda s: s if s.get('member') and s.get('evmNodeId') == new_evm else None)(self.status(live, home, auth)), 600)
        (self.ev / 'status-after.json').write_text(json.dumps(after, indent=1) + '\n')
        r.expect(after.get('localKeys') == 'current' and not after.get('staged'), 'VR\'s current binding is the fresh authority\'s key (nothing staged)',
                 str(after.get('localKeys')))
        r.expect(after.get('generation') == before.get('generation'), 'the binding is installed at the unchanged custody generation', str(after.get('generation')))
        r.expect(self.position(ident) == lots_before, 'custody\'s position (generation, lots, root key) is unchanged: nothing unbonded', str(lots_before))
        first = self.auth_status(i)
        signed = r.wait('the fresh authority signs certification requests (its reserved round rises)',
                        lambda: (lambda s: s if s['reservedRound'] > first['reservedRound'] else None)(self.auth_status(i)), 300)
        r.expect(signed['rootEpoch'] == target and signed['sessionIssued'], 'the fresh authority holds a session of the activated epoch',
                 f'fingerprint {signed["signingKeyFingerprint"]}, reserved round {signed["reservedRound"]}')
        uc = r.wait(f'a verified UC of root epoch {target} carries root {i}\'s signature', lambda: json.loads(self.exec(
            f'root{i}', 'ubft', 'validator', 'last-signed-uc', '--execution', 'http://127.0.0.1:8545', '--root-rpc', self.root_rpc,
            '--signer', root_node, '--epoch', str(target)).stdout or 'null'), 300)
        (self.ev / 'last-signed-uc.json').write_text(json.dumps(uc, indent=1) + '\n')
        r.expect(uc['signer'] == root_node and uc['shardEpoch'] >= shard_epoch, 'last-signed-uc names the recovered validator\'s root, verified individually',
                 f'root round {uc["rootRound"]}, shard epoch {uc["shardEpoch"]} round {uc["shardRound"]}')
        r.expect(marker.read_text() == 'fail-stop\n' and tree(old_auth) == old_tree, 'the old authority directory and its fail-stop marker are unchanged', str(old_auth))
        r.expect(sorted(p.name for p in old_evm_dir.iterdir()) == old_evm_tree, 'the old shard home is kept', str(old_evm_dir))
        used = set()
        for service in (f'authority{i}', f'root{i}', f'shard{i}', f'ureth{i}'):
            cid = self.dc('ps', '-q', service).stdout.strip()
            mounts_json = subprocess.run(['docker', 'inspect', '--format', '{{json .Mounts}}', cid], check=True, text=True, capture_output=True).stdout
            used |= {Path(m['Source']).resolve() for m in json.loads(mounts_json)}
        r.expect(old_auth not in used and (old_auth / 'pop') not in used and old_evm_dir not in used and old_ureth_dir not in used,
                 'no container mounts the old authority directory, the old shard home or the old execution data')
        (self.ev / 'summary.json').write_text(json.dumps({'validator': i, 'identity': ident, 'oldEvmNode': old_evm, 'newEvmNode': new_evm,
            'slot': f'recover-{k}', 'rootEpoch': target, 'shardEpoch': shard_epoch, 'generation': after.get('generation'),
            'oldFingerprint': old_status['signingKeyFingerprint'], 'newFingerprint': signed['signingKeyFingerprint'],
            'ackBlock': ack['block']['number'], 'userBlock': mined, 'times': times}, indent=1) + '\n')
        r.say('  timings: ' + ', '.join(f'{k} {v}' for k, v in times.items()))

    def logs(self, service):
        return self.dc('logs', '--no-color', '--timestamps', '--since', self.since, service, check=False).stdout

    def newest_uc(self, pod, epoch=None, signer=None):
        """`validator last-signed-uc` in root<pod>: the newest UC its local root and execution verify (None when there is none yet)."""
        args = ['--epoch', str(epoch)] if epoch else []
        args += ['--signer', signer] if signer else []
        done = self.exec(f'root{pod}', 'ubft', 'validator', 'last-signed-uc', '--execution', 'http://127.0.0.1:8545', '--root-rpc', self.root_rpc,
                         *args, check=False)
        return json.loads(done.stdout) if done.returncode == 0 and done.stdout.strip() else None

    def block(self, block_hash):
        b = self.r.call('eth_getBlockByHash', [block_hash, False])
        return {'number': b['number'], 'hash': b['hash'], 'parentHash': b['parentHash'], 'transactions': b['transactions']}

    def transfer(self):
        """A plain value transfer from the funder through the public gateway; its receipt."""
        r = self.r
        sender = r.funder_address()
        nonce = int(r.call('eth_getTransactionCount', [sender, 'latest']), 16)
        to = '0x' + uuid.uuid4().hex[:20] + '0' * 20
        sent = r.call('eth_sendRawTransaction', [r.raw_tx(to, nonce, int(r.call('eth_gasPrice'), 16), 1)])
        return r.wait('the transfer is mined', lambda: r.call('eth_getTransactionReceipt', [sent]), 600)

    def participate_until(self, epoch, homes=None, pods=None, seconds=3600, watch=None):
        """Until the roots activate an epoch after `epoch`: every genesis member's own `pos-publish --participate` on the open result (its
        possession proof from its own authority, then anyone's publication), each in its own pod unless `pods` names another (a member
        whose own shard node does not sign yet sends through a live one). Returns the activated epoch."""
        r, gen = self.r, self.gen
        members = r.members()
        homes = {m: (homes or {}).get(m) or self.home(m, 'recover-participant') for m in members}
        auths = {m: authority_dir(gen, handoff_ops.load_compose(gen), m) for m in members}
        ids = {m: genesis_identity(gen, m)[0] for m in members}
        election = self.deployment['election']

        def participate():
            if watch is not None:
                # stop early when the roots refuse the Freeze (each leader would re-propose it, and rounds end by timeout)
                refused = [l for l in self.logs(f'root{watch}').splitlines() if any(x in l for x in REFUSAL)]
                if refused:
                    r.keep_redacted(self.ev / 'root-refusal.log', '\n'.join(refused[-200:]))
                    return f'the roots refuse the Freeze ({len(refused)} lines, root-refusal.log): ' + r.scrub(refused[-1][-400:])
            result = r.view_text(election, 'openResult()(bytes32)').strip()
            if int(result, 16):
                for m in members:
                    done = self.cli((pods or {}).get(m, m), homes[m], 'validator', 'pos-publish', '--participate', '--result', result,
                                    '--proof-member', str(ids[m]), mounts=[(auths[m], '/home/authority')], check=False)
                    r.say(f'  member {ids[m]} on result {result[:18]}: exit {done.returncode}: ' +
                          r.scrub(' | '.join((done.stdout + done.stderr).strip().splitlines()[-2:])[-240:]))
            view = self.root_view(self.i)
            switching = view.get('switch') and view['switch']['phase'] not in ('running', 'following')
            return view['activeEpoch'] if view['activeEpoch'] > epoch and not switching else None
        got = r.wait(f'the roots activate an epoch after {epoch}', participate, seconds, every=10)   # r.wait takes a raising probe as "not yet"
        if isinstance(got, str):
            raise RuntimeError(got)
        return got

    def follows(self, m):
        entry = handoff_ops.load_compose(self.gen)['services'][f'authority{m}']['entrypoint']
        return '--follow-root-activations' in entry

    def position(self, ident):
        """custody.positions(id) as text: owner, withdrawal, root key hash, staged root key hash, generation, role nonce, open lots, lots, retirement."""
        return self.r.view_text(self.deployment['custody'], 'positions(uint64)(address,address,bytes32,bytes32,uint64,uint64,uint32,uint32,bool)', str(ident))


def vr_pos_publish(r):
    """The next election after the current epoch, published by the genesis members' own proofs (no relay): for a Compose VR generation that
    runs no participant containers, before vr-pos-advance."""
    if (r.manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('vr-pos-publish needs a VR/P85 Compose generation')
    rec = Recovery(r, r.n)
    epoch = rec.root_view(r.n)['activeEpoch']
    target = rec.participate_until(epoch)
    r.expect(target > epoch, f'the members published the election after root epoch {epoch} and the roots activated it', str(target))


def vr_pos_recover(r):
    if (r.manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('vr-pos-recover needs a VR/P85 Compose generation')
    Recovery(r, r.recover_index or r.n).run()
