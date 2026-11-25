#!/usr/bin/env python3
"""Entrypoint for the public VR validator's two container roles."""
import argparse
import contextlib
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HOME = Path('/data')
RELEASE = HOME / 'release'
CONFIG = HOME / 'validator.json'
# #1286: the node slot names the authority, shard home and activation journal the node runs on. Slot 1 is the original layout
# (authority/, evm/, shard-active.json). `recover` adds slot k >= 2 (authority-k/, evm-k/, shard-active-k.json): a fresh authority,
# a fresh shard node key and an empty shard data directory. A slot's directories are never reused once its authority lifetime started.
SLOT, RECOVERY = 'node-slot', 'recover.json'   # under HOME
RECOVERING = ('authority', 'transactions', 'linking', 'electing', 'activation')
LOCK = '/opt/validator/release-lock.json'
ROOT = 'http://127.0.0.1:26852'
SHARD = 'http://127.0.0.1:29352'
EXECUTION = 'http://127.0.0.1:18552'
ENGINE = 'http://127.0.0.1:18553'
RPC = 'http://127.0.0.1:18485'
UTB = ['--utb-genesis', RELEASE/'utb-genesis.cbor']
MAX_RELEASE_FILE = 32 << 20
FILES = frozenset({
    'manifest.json', 'deployment.json', 'vr-deployment.json', 'genesis.json', 'genesis-identities.json',
    'full-shard-conf.json', 'b1-profile.json', 'trust-base.json', 'utb-genesis.cbor', 'utb-genesis.id',
    'ureth-flags.txt', 'fee-collector.txt', 'aggregator-conf.json', 'root-peers.txt', 'shard-peers.txt',
})
BINARIES = {'ubft': '/usr/local/bin/ubft', 'unicity-reth': '/usr/local/bin/unicity-reth'}


AUTHORITY_LOST = (
    'Preserve the volume and fail-stop marker. A registered and bonded identity recovers in place: run '
    '`ubft-validator recover --yes` in the node container, start the fresh authority container it names on the same volume, '
    'then run `recover --yes` again. Recovery uses a fresh authority directory, a fresh shard node key and an empty shard '
    'data directory, never the marked ones. If chain evidence confirms the identity is unregistered and has no pending '
    'registration or bond, initialize a fresh identity in a separate volume instead. See Authority loss in the validator handbook.'
)


def slot():
    try:
        value = (HOME/SLOT).read_text().strip()
    except FileNotFoundError:
        return 1
    if not re.fullmatch(r'[1-9][0-9]{0,3}', value):
        raise ValueError(f'invalid node slot {value!r} in {HOME/SLOT}')
    return int(value)


def auth_name(k):
    return 'authority' if k == 1 else f'authority-{k}'


def auth_dir(k=None):
    return HOME/auth_name(slot() if k is None else k)


def evm_name(k):
    return 'evm' if k == 1 else f'evm-{k}'


def evm_dir(k=None):
    return HOME/evm_name(slot() if k is None else k)


def active_file(k=None):
    k = slot() if k is None else k
    return HOME/('shard-active.json' if k == 1 else f'shard-active-{k}.json')


def auth_flags(d=None):
    d = auth_dir() if d is None else d
    return ['--operator-socket', d/'operator.sock', '--operator-credential', d/'operator.cred']


def command(*args, output=False, check=True, timeout=120):
    return subprocess.run([str(arg) for arg in args], text=True, capture_output=output, check=check,
                          timeout=timeout, stdin=subprocess.DEVNULL, cwd=HOME)


def ubft(*args, **options):
    return command('ubft', *args, **options)


def read(path):
    return json.loads(Path(path).read_text())


def write(path, data):
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    with contextlib.ExitStack() as clean:
        clean.callback(Path(tmp).unlink, missing_ok=True)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        with directory(path.parent) as parent:
            os.fsync(parent)


@contextlib.contextmanager
def directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def lock(name, wait=False):
    with (HOME/name).open('a') as file:
        fcntl.flock(file, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirects are refused for release artifacts')


def download(url, limit):
    with urllib.request.build_opener(NoRedirect()).open(url, timeout=15) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('release artifact exceeds the size limit')
    return data


def bootstrap(a, pins):
    sums = download(a.release_url + '/SHA256SUMS', 1 << 16)
    if digest(sums) != pins['sha256sums']:
        raise ValueError('release SHA256SUMS differs from the authenticated image pin')
    entries = {}
    for line in sums.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)', line)
        if not match:
            raise ValueError('invalid release checksum entry')
        sha, name = match.groups()
        if name in entries or any(part in ('.', '..') for part in name.split('/')):
            raise ValueError('duplicate or invalid release path')
        entries[name] = sha
    release_files = FILES | {name for name in entries if name.startswith('seed/')}
    if not (release_files | BINARIES.keys()) <= entries.keys() or 'seed/manifest.json' not in release_files:
        raise ValueError('release is missing a required file')
    for name, path in BINARIES.items():
        if file_digest(path) != entries[name]:
            raise ValueError(f'{name} differs from the authenticated release')
    if RELEASE.exists():
        for name in release_files:
            if file_digest(RELEASE/name) != entries[name]:
                raise ValueError(f'cached release file differs: {name}')
    else:
        with tempfile.TemporaryDirectory(prefix='.release-', dir=HOME) as temp:
            stage = Path(temp)/'release'
            (stage/'seed').mkdir(parents=True)
            for name in sorted(release_files):
                data = download(a.release_url + '/' + name, MAX_RELEASE_FILE)
                if digest(data) != entries[name]:
                    raise ValueError(f'release checksum mismatch: {name}')
                write(stage/name, data)
            if (stage/'utb-genesis.id').read_text().strip() != pins['utb_genesis_id']:
                raise ValueError('UTB genesis EntryID differs from the image pin')
            stage.rename(RELEASE)
            with directory(HOME) as parent:
                os.fsync(parent)
    if (RELEASE/'utb-genesis.id').read_text().strip() != pins['utb_genesis_id']:
        raise ValueError('UTB genesis EntryID differs from the image pin')
    if 'public_peers' in pins:
        output = HOME/'public-peers'
        output.mkdir(mode=0o700, exist_ok=True)
        for name, expected in pins['public_peers'].items():
            data = download(a.release_url + '/validator-container/' + name, 4096)
            if digest(data) != expected:
                raise ValueError(f'public peer list differs from the image pin: {name}')
            write(output/name, data)
    proof = HOME/'bootstrap.json'
    if not proof.exists():
        for name in ('root', 'evm'):
            (HOME/name).mkdir(mode=0o700, exist_ok=True)
        utb = ['--utb-genesis-id', pins['utb_genesis_id']]
        full = ['--full-shard-conf', RELEASE/'full-shard-conf.json']
        args = ['--dir', RELEASE/'seed', *utb, *full]
        with tempfile.TemporaryDirectory(prefix='.pin-', dir=HOME) as temp:
            prefix = Path(temp)/'seed-pin'
            restored = ubft('seed', 'restore-pin', *args, '--trust-base', RELEASE/'trust-base.json',
                            '--out', prefix, output=True).stdout
            body = re.search(r'bodyID=(0x[0-9a-f]{64})', restored)
            if body is None:
                raise ValueError('seed verification returned no trust body ID')
            for name in ('seed-pin.uc.cbor', 'seed-pin.tr.cbor'):
                write(HOME/name, (Path(temp)/name).read_bytes())
        ubft('seed', 'import', *args, '--home', HOME, '--source', a.release_url + '/seed', *UTB,
             '--root-utb-db', 'root/root-utb-entries.db', '--shard-utb-db', 'evm/shard-utb-entries.db')
        write(proof, json.dumps({'body':body[1]}).encode())


def rpc(url, method, params, *, evm=True):
    data = {'jsonrpc':'2.0', 'id':1, 'method':method, 'params':params} if evm else params
    req = urllib.request.Request(url, json.dumps(data).encode(), {'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=12) as response:
        result = json.load(response)
    if evm and 'result' not in result:
        raise ValueError(f'{method} failed: {result.get("error")}')
    return result['result'] if evm else result


def wait_for(description, read_value, limit=None):
    end = None if limit is None else time.monotonic() + limit
    while end is None or time.monotonic() < end:
        try:
            value = read_value()
            if value:
                return value
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(2)
    raise RuntimeError(f'timed out waiting for {description}')


def init(a, pins):
    with lock('.init.lock'):
        bootstrap(a, pins)
        if not CONFIG.exists():
            ubft('validator', 'init', '--rpc', a.rpc_url, '--local-rpc', EXECUTION,
                 '--chain-id', read(RELEASE/'manifest.json')['chain_id'], '--ports', ','.join(map(str, a.ports)))
        if not (HOME/'network.json').exists():
            write(HOME/'network.json', json.dumps({
                'rpc':a.rpc_url, 'release':a.release_url, 'ports':a.ports, 'announce':a.announce_addresses,
                'rootEpoch':a.root_epoch, 'shardEpoch':a.shard_epoch,
            }).encode())
        info = read(CONFIG)
        print(f"Payee {info['payee']}. Fund 100 UCT plus gas. One faucet claim pays 200 UCT.")


def authority(*args, home=None, **options):
    return ubft('signing-authority', *args, *auth_flags(home), **options)


def authority_status(home=None):
    return json.loads(authority('status', home=home, output=True, timeout=8).stdout)


def authority_lost(home=None):
    """Whether the authority in `home` is gone: it does not answer, or answers that its key is lost or it latched faulted."""
    try:
        status = authority_status(home)
    except (OSError, ValueError, subprocess.SubprocessError):
        return True
    return bool(status.get('keyLost') or status.get('faulted'))


def recovery():
    return read(HOME/RECOVERY) if (HOME/RECOVERY).exists() else None


def recovering():
    rec = recovery()
    return rec is not None and rec['phase'] in RECOVERING


def authority_target():
    """(slot, directory, recovery) of the authority this container may start. The slot's own directory while its lifetime has not
    started; once it has, only the fresh directory a pending `recover` prepared, never the marked one."""
    k = slot()
    d = auth_dir(k)
    if not (d/'lifetime').exists():
        return k, d, None
    rec = recovery()
    if rec and rec['phase'] == 'authority' and rec['old'] == k and rec['new'] != k:
        fresh = auth_dir(rec['new'])
        if not (fresh/'lifetime').exists():
            return rec['new'], fresh, rec
    raise ValueError(f'The authority lifetime has already started. {AUTHORITY_LOST}')


def authority_process(a, pins):
    with lock('.authority.lock'):
        k, d, rec = authority_target()
        if rec is None:
            n = wait_for('the node’s verified initial authority scope',
                         lambda: read(HOME/'authority-scope.json'), limit=360)
        else:
            n = rec['scope']
        d.mkdir(mode=0o700, exist_ok=True)
        for name in ('operator.cred', 'pop.cred'):
            if not (d/name).exists():
                ubft('signing-authority', 'credential', '--out', d/name)
        owner = read(CONFIG)['payee']
        root = read(HOME/'root/node-info.json')
        deployment = read(RELEASE/'vr-deployment.json')
        # a recovering identity's fresh key proves possession for VR.proposeBinding of the registered identity (the binding domain)
        entry = ({'action':'register', 'owner':owner, 'payee':owner} if rec is None else
                 {'action':'binding', 'owner':owner, 'id':rec['id'], 'payee':owner})
        doc = {'network':deployment['networkWord'], 'chainId':read(RELEASE/'manifest.json')['chain_id'],
               'registry':read(RELEASE/'deployment.json')['registry'],
               'authorized':[{**entry, 'rootNodeId':root['nodeId'], 'rootKey':root['sigKey']}]}
        write(d/'registration.json', json.dumps(doc).encode())
        node = ubft('node-id', '--home', evm_dir(k), output=True).stdout.strip().splitlines()[-1]
        trust = RELEASE/'trust-base.json'
        if n['rootEpoch'] > 1:
            trust = d/'current-trust.json'
            wait_for('the local root to verify the incumbent trust epoch',
                     lambda: ubft('q3', 'trust-base', '--root-rpc', ROOT, '--epoch', n['rootEpoch'],
                                  '--out', trust, output=True).returncode == 0, limit=300)
        # A lost process must never be recreated with the old enrollment.
        write(d/'lifetime', b'fail-stop\n')
        args = ['ubft', 'signing-authority', 'run', '--home', d, '--authority-id', node,
                '--network-id', 3, '--partition-id', 8, '--shard-id', '0x80', '--node-id', node,
                '--shard-epoch', n['shardEpoch'], '--root-epoch', n['rootEpoch'], '--trust-base', trust,
                '--client-socket', d/'client.sock', *auth_flags(d),
                '--pop-socket', d/'pop.sock', '--pop-credential', d/'pop.cred',
                '--registration-policy', d/'registration.json', '--dev-allow-late-pos-policy', '--require-pos-policy',
                '--lineage-genesis-trust-base', RELEASE/'trust-base.json', '--lineage-utb-genesis',
                '--b1-profile', RELEASE/'b1-profile.json', '--activation-source-url', EXECUTION,
                '--execution-genesis-hash', read(RELEASE/'manifest.json')['genesis_hash']]
        proc = subprocess.Popen([str(x) for x in args], cwd=HOME)
        signal.signal(signal.SIGTERM, lambda *_: proc.terminate())
        raise SystemExit(proc.wait())


def peers(role):
    folder = HOME/'public-peers'
    file = (folder if folder.exists() else RELEASE)/f'{role}-peers.txt'
    return file.read_text().splitlines()


def p2p(n, role, index):
    port = n['ports'][index]
    result = ['--address', f'/ip4/0.0.0.0/tcp/{port}']
    if n['announce']:
        result.extend(['--announce-addresses', f'{n["announce"]}/tcp/{port}'])
    return result


def root_status():
    r = rpc(ROOT + '/api/v1/q3/status', '', {}, evm=False)
    if r.get('switch') and r['switch']['phase'] not in ('running', 'following'):
        return None
    return r


def active_member_epoch(status, previous):
    if status and not status.get('follower', False) and status['activeEpoch'] > previous:
        return status['activeEpoch']
    return None


def provision_scope(network, epoch):
    view = root_status()
    if not view or view['activeEpoch'] != epoch or not view.get('follower'):
        return None
    result = command('handoff-ubft', 'validator', 'last-signed-uc', '--execution', RPC,
                     '--root-rpc', ROOT, '--epoch', epoch, output=True)
    certified = json.loads(result.stdout)
    if not certified or certified['rootEpoch'] != epoch:
        return None
    return {'rootEpoch': epoch, 'shardEpoch': network['shardEpoch'] or certified['shardEpoch'] + 1}


def recovery_scope():
    """The scope a recovering identity's fresh authority starts at: the root epoch the local root runs now (it is a member or a
    follower: its root key is unchanged) and the successor of the certified shard epoch, the epoch whose configuration names the new
    EVM node once the next election installs it (the join path)."""
    view = root_status()
    if not view:
        return None
    epoch = view['activeEpoch']
    result = command('handoff-ubft', 'validator', 'last-signed-uc', '--execution', RPC,
                     '--root-rpc', ROOT, '--epoch', epoch, output=True)
    certified = json.loads(result.stdout)
    if not certified or certified['rootEpoch'] != epoch:
        return None
    return {'rootEpoch': epoch, 'shardEpoch': certified['shardEpoch'] + 1}


def stamp_authority(d):
    """Record the authority's signing key fingerprint in its directory; a changed fingerprint is a new lifetime, refused."""
    status = authority_status(d)
    observed = status['signingKeyFingerprint']
    stamp = d/'fingerprint'
    if stamp.exists() and stamp.read_text() != observed:
        raise ValueError(f'Authority identity changed. {AUTHORITY_LOST}')
    write(stamp, observed.encode())
    return status


def configure_authority(k):
    """validator init --force selecting slot k's authority (its node info is written first); the identity id is kept."""
    d = auth_dir(k)
    authority('node-info', '--out', d/'node-info.json', home=d)
    n = read(HOME/'network.json')
    cfg = read(CONFIG) if CONFIG.exists() else {}
    ident = ['--id', cfg['id']] if cfg.get('id') else []
    ubft('validator', 'init', '--force', '--rpc', RPC, '--local-rpc', EXECUTION,
         '--chain-id', read(RELEASE/'manifest.json')['chain_id'], '--ports', ','.join(map(str, n['ports'])), *ident,
         '--evm-authority-socket', f'{d.name}/operator.sock', '--evm-authority-credential', f'{d.name}/operator.cred',
         '--evm-authority-node-info', f'{d.name}/node-info.json')


def link_authority():
    d = auth_dir()
    wait_for('the long-lived authority container', lambda: authority_status(d), limit=60)
    stamp_authority(d)
    if not read(CONFIG).get('evmAuthority'):
        configure_authority(slot())


class SlotChanged(Exception):
    """`recover` switched the node slot: the node process restarts every service on the new slot."""


def root_command(n, pins, k):
    d = auth_dir(k)
    utb = [*UTB, '--utb-genesis-id', pins['utb_genesis_id']]
    return ['ubft', 'root-node', 'run', '--home', HOME/'root', *p2p(n, 'root', 0), '--bootnodes', ','.join(peers('root')),
            '--rpc-server-address', '127.0.0.1:26852', '--trust-base', RELEASE/'trust-base.json',
            '--shard-conf', RELEASE/'full-shard-conf.json', '--shard-conf', RELEASE/'aggregator-conf.json',
            '--profile-3', '--q3-lane', '--b1-registry', '--genesis-identities', RELEASE/'genesis-identities.json',
            '--vr-deployment', RELEASE/'vr-deployment.json', '--pos-evm-rpc', EXECUTION, '--vr-shard-rpc', SHARD, *utb]


def shard_command(n, pins, k):
    """The shard node of slot k: `run` once the slot's activation journal exists, before that a staging-only `restore` from the
    verified seed pin into the slot's own (empty) home, as a joiner starts."""
    d, evm = auth_dir(k), evm_dir(k)
    roots, shards = peers('root'), peers('shard')
    args = ['--home', evm, *p2p(n, 'shard', 1), '--bootnodes', ','.join(roots + shards),
            '--rpc-server-address', '127.0.0.1:29352', '--trust-base', RELEASE/'trust-base.json',
            '--full-shard-conf', RELEASE/'full-shard-conf.json', '--executor', 'engine-api',
            '--genesis', RELEASE/'genesis.json', '--b1-profile', RELEASE/'b1-profile.json',
            '--engine-url', ENGINE, '--eth-url', EXECUTION, '--jwt-secret', HOME/'jwt/jwt.hex',
            '--engine-fee-collector', (RELEASE/'fee-collector.txt').read_text().strip(),
            '--execution-journal', evm/'execution-journal.db', '--archive-store', evm/'archive',
            '--archive-prune', '--archive-replica', shards[0].rsplit('/',1)[1],
            '--archive-replica', shards[1].rsplit('/',1)[1], '--trust-history-profile-2', '--q3-lane',
            '--journal-candidates', 4096, '--journal-observations', 8192, '--journal-bytes', 134217728,
            '--signing-authority-socket', d/'client.sock', '--signing-authority-credential', d/'client.cred',
            '--target-block-interval', '10000ms', *UTB, '--utb-genesis-id', pins['utb_genesis_id']]
    if active_file(k).exists():
        return ['ubft', 'shard-node', 'run', *args]
    return ['ubft', 'shard-node', 'restore', *args, '--tip-uc', HOME/'seed-pin.uc.cbor', '--tip-tr', HOME/'seed-pin.tr.cbor',
            '--trust-body-id', read(HOME/'bootstrap.json')['body']]


def run(a, pins):
    try:
        with lock('.node.lock'):
            node(a, pins)
    except SlotChanged:
        # every child has stopped and the lock is released (its descriptor is close-on-exec): start over on the new slot
        print('validator: the node slot changed; restarting the node services on the recovered authority', flush=True)
        os.execv(sys.executable, [sys.executable, *sys.argv])


def node(a, pins):
    n = read(HOME/'network.json')
    bootstrap(a, pins)
    k = slot()
    procs = {}

    def start(name, args):
        procs[name] = subprocess.Popen([str(x) for x in args], cwd=HOME, stdin=subprocess.DEVNULL)

    def stop(name):
        p = procs.pop(name)
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(12)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def shutdown(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        private_rpc = ['--allow-private-http'] if pins.get('private_rehearsal') else []
        start('rpc', ['python3', '/opt/validator/validator_rpc.py', '--upstream', n['rpc'], '--listen-port', 18485,
                      *private_rpc])
        start('ureth', ['unicity-reth', 'node', '--chain', RELEASE/'genesis.json', '--datadir', HOME/'ureth',
              '--p2p-secret-key', HOME/'ureth-key/p2p-secret', '--disable-discovery', '--addr', '127.0.0.1', '--port', n['ports'][2],
              '--ipcdisable', '--http', '--http.addr', '127.0.0.1', '--http.port', 18552, '--http.api', 'eth,net,debug',
              '--unicity.archive-state-proofs', '--authrpc.addr', '127.0.0.1', '--authrpc.port', 18553,
              '--authrpc.jwtsecret', HOME/'jwt/jwt.hex', '--log.file.max-files', 0,
              *(RELEASE/'ureth-flags.txt').read_text().split()])
        wait_for('execution', lambda: rpc(EXECUTION, 'eth_chainId', []), limit=50)
        root_args = root_command(n, pins, k)
        d = auth_dir(k)
        if not (d/'fingerprint').exists():
            epoch = n['rootEpoch']
            if epoch is None:
                # A chain observation selects what the local root must
                # verify from genesis. It cannot authorize the authority.
                def hint():
                    result = ubft('validator', 'status', '--rpc', RPC, '--json', output=True, check=False)
                    if result.stdout:
                        return json.loads(result.stdout).get('rootEpoch')
                    return None
                epoch = wait_for('the current registry epoch', hint, limit=60)
            install = ['--install-handoff-epoch', epoch] if epoch > 1 else []
            start('root', [*root_args, *install])
            scope = wait_for('the locally verified initial root and shard scope',
                             lambda: provision_scope(n, epoch), limit=300)
            write(HOME/'authority-scope.json', json.dumps(scope).encode())
            link_authority()
            stop('root')
        else:
            try:
                link_authority()
            except RuntimeError:
                # a fail-stop authority that is gone: keep the root, execution and RPC up so that `recover` can run
                if not (d/'lifetime').exists():
                    raise
                print(f'validator: the authority in {d} does not answer. {AUTHORITY_LOST}', flush=True)
        start('root', [*root_args, '--vr-evm-authority-socket', d/'pop.sock', '--vr-evm-authority-credential', d/'pop.cred'])
        active = active_file(k)

        def shard():
            start('shard', shard_command(n, pins, k))

        shard()
        enrolled = active.read_bytes() if active.exists() else None

        class Health(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    ready = bool(root_status()) and all(p.poll() is None for p in procs.values())
                except (OSError, ValueError):
                    ready = False
                self.send_response(200 if ready else 503)
                self.end_headers()
                self.wfile.write(b'{"ready":true}\n' if ready else b'{"ready":false}\n')

        with HTTPServer(('127.0.0.1', 29452), Health) as health:
            health.timeout = 1
            halted = threading.Event()
            participant = threading.Thread(target=participate, args=(halted,), daemon=True)
            participant.start()
            while True:
                if slot() != k:
                    raise SlotChanged()
                if active.exists() and active.read_bytes() != enrolled:
                    stop('shard')
                    shard()
                    enrolled = active.read_bytes()
                for name, proc in procs.items():
                    if proc.poll() is not None:
                        raise RuntimeError(f'{name} exited with status {proc.returncode}')
                health.handle_request()
    finally:
        if 'halted' in locals():
            halted.set()
        for name in reversed(list(procs)):
            stop(name)


def local_status():
    return ubft('validator', 'status', '--custody', read(RELEASE/'deployment.json')['custody'],
                '--json', output=True, check=False, timeout=25)


def show_status(_a, _pins):
    result = local_status()
    report = json.loads(result.stdout)
    try:
        info = authority_status()
    except (OSError, ValueError, subprocess.SubprocessError):
        info = None   # a lost authority: the report still shows the chain state and the recovery
    report['seat'] = (report.get('committee') or []).index(report['id']) + 1 if report.get('member') else None
    report['authorityDirectory'] = auth_dir().name
    report['shardHome'] = evm_dir().name
    rec = recovery()
    report['recovery'] = {'phase':rec['phase'], 'from':auth_name(rec['old']), 'to':auth_name(rec['new'])} if rec else None
    report['authorityFingerprint'] = info['signingKeyFingerprint'] if info else None
    report['lastSignedCertificationRound'] = info['reservedRound'] if info and info['responseRetained'] else None
    try:
        with urllib.request.urlopen(SHARD + '/api/v1/operator/status', timeout=5) as response:
            report['certifiedTip'] = json.load(response).get('certifiedTip')
    except (OSError, ValueError):
        report['certifiedTip'] = None
    report['lastSignedUC'] = None
    if report.get('member') and report.get('rootNodeId'):
        observed = command('handoff-ubft', 'validator', 'last-signed-uc', '--execution', EXECUTION,
                           '--root-rpc', ROOT, '--signer', report['rootNodeId'], output=True, check=False)
        if observed.returncode == 0:
            report['lastSignedUC'] = json.loads(observed.stdout)
    print(json.dumps(report, indent=2))
    return result.returncode


def journal(path, phase, **data):
    write(path, json.dumps({'phase':phase, **data}).encode())


def participate(halted, *, execution=RPC, root=ROOT, member=None):
    deployment = read(RELEASE/'deployment.json')
    manifest = RELEASE/'manifest.json' if member is None else HOME/'deployment-manifest.json'
    expected_genesis = read(manifest)['genesis_hash']
    while not halted.wait(5):
        try:
            journal_path = HOME/'join.json'
            if member is None and not recovering() and (not journal_path.exists() or
                                   read(journal_path)['phase'] not in ('electing', 'activation', 'activated')):
                continue
            if rpc(execution, 'eth_getBlockByNumber', ['0x0', False])['hash'] != expected_genesis:
                raise ValueError('the election source is on a different execution genesis')
            block = rpc(execution, 'eth_getBlockByNumber', ['finalized', False])
            result = rpc(execution, 'eth_call', [{'to':deployment['election'], 'data':'0x5552dcb8'},
                                           {'blockHash':block['hash'], 'requireCanonical':True}])
            if re.fullmatch(r'0x[0-9a-f]{64}', result) and int(result, 16):
                local = ['--proof-member', member] if member is not None else []
                with lock('.tx.lock'):
                    command('handoff-ubft', 'validator', 'pos-publish', '--participate', '--result', result, *local)
            view = rpc(root + '/api/v1/q3/status', '', {}, evm=False)
            if view.get('switch') and view['switch']['phase'] not in ('running', 'following'):
                continue
            active = active_file()
            # while `recover` runs, the old authority is gone and the fresh one is enrolled and advanced by recover itself
            if view['activeEpoch'] > 1 and (member is not None or (active.exists() and not recovering())):
                old = authority_status()
                if (old['rootEpoch'] < view['activeEpoch'] or not old['sessionIssued'] or
                        not active.exists() or read(active)['rootEpoch'] < view['activeEpoch']):
                    advance(view['activeEpoch'], root=root, member=member)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(f'authority handoff: {error}', flush=True)


def advance(target, *, root=ROOT, member=None):
    with lock('.advance.lock'), tempfile.TemporaryDirectory(prefix='.activation-', dir=HOME) as temp:
        proofs = []
        for epoch in range(2, target + 1):
            path = Path(temp)/f'activation-{epoch}.cbor'
            ubft('q3', 'proof-envelope', '--root-rpc', root, '--epoch', epoch, '--out', path)
            proofs.extend(['--proof', path])
        d = auth_dir()
        advanced = json.loads(authority('advance-with-proof', '--client-socket', d/'client.sock',
                              '--out', d/'client.cred', *proofs, home=d, output=True).stdout)
        if advanced['rootEpoch'] != target or advanced['retired']:
            raise ValueError('verified activation did not admit this authority')
        journal(active_file(), 'activated', rootEpoch=target, shardEpoch=advanced['shardEpoch'],
                id=read(CONFIG)['id'] if member is None else member)


def incumbent(a, _pins):
    if not a.member_id:
        raise ValueError('incumbent participation requires this authority’s --member-id')
    with lock('.node.lock'):
        participate(threading.Event(), execution='http://127.0.0.1:8545',
                    root='http://127.0.0.1:8002', member=a.member_id)


def join(a, pins):
    if not a.yes:
        raise ValueError('confirm the bond and gas payment with join --yes')
    with lock('.join.lock'):
        cfg = read(CONFIG)
        if not cfg.get('evmAuthority'):
            raise ValueError('start the authority and node containers before joining')
        active = active_file()
        if active.exists():
            show_status(a, pins)
            return 0
        progress = HOME/'join.json'
        if not progress.exists():
            journal(progress, 'waiting-funding')
        phase = read(progress)['phase']
        if phase == 'waiting-funding':
            def funded():
                value = rpc(RPC, 'eth_getBalance', [cfg['payee'], 'latest'])
                return int(value, 16) >= 101 * 10**18 or read(CONFIG).get('id')
            wait_for('funding', funded)
            journal(progress, 'applying')
        if read(progress)['phase'] == 'applying':
            first = ubft('validator', 'apply', output=True, check=False)
            if first.returncode and 'signing-pos-policy-refused' not in first.stdout + first.stderr:
                raise RuntimeError(first.stderr or first.stdout)
            ident = read(CONFIG)['id']
            if first.returncode:
                policy = {'network':read(RELEASE/'vr-deployment.json')['networkWord'],
                          'chainId':read(RELEASE/'manifest.json')['chain_id'], 'election':read(RELEASE/'deployment.json')['election'],
                          'ids':[ident]}
                provision_pos_policy(auth_dir(), ident)
                ubft('validator', 'apply')
            journal(progress, 'electing', id=ident)
        ident = read(CONFIG)['id']
        status = authority_status()
        scope = HOME/'authority-scope.json'
        base = read(scope if scope.exists() else HOME/'network.json')
        target = wait_for('activated root epoch', lambda: active_member_epoch(root_status(), base['rootEpoch']))
        journal(progress, 'activation', id=ident, rootEpoch=target)
        shard = base['shardEpoch']
        conf = auth_dir()/'activated-shard.json'
        ubft('q3', 'shard-conf', '--root-rpc', ROOT, '--epoch', shard, '--out', conf)
        if not status['enrollmentComplete']:
            authority('complete-enrollment', '--shard-conf', conf)
        advance(target)
        journal(progress, 'activated', id=ident, rootEpoch=target)
        wait_for('committee membership', lambda: json.loads(local_status().stdout).get('member'))
        show_status(a, pins)
        return 0


def provision_pos_policy(d, ident):
    """The authority's PoS policy for this identity: it signs the election's delegation possession (admitDelegation) only for it."""
    policy = {'network':read(RELEASE/'vr-deployment.json')['networkWord'],
              'chainId':read(RELEASE/'manifest.json')['chain_id'], 'election':read(RELEASE/'deployment.json')['election'],
              'ids':[ident]}
    write(d/'pos-policy.json', json.dumps(policy).encode())
    authority('pos-policy', '--policy', d/'pos-policy.json', home=d)


def next_slot():
    """A slot no directory or journal of this volume has used: above every existing one, so a marked slot is never reused."""
    used = [1, slot()]
    for path in HOME.iterdir():
        found = re.fullmatch(r'(?:authority|evm|seed|shard-active)-([1-9][0-9]{0,3})(?:\.json)?', path.name)
        if found:
            used.append(int(found[1]))
    return max(used) + 1


def prepare_recovery(a, pins, cfg):
    """Check the fail-stop evidence of the current slot's authority, then prepare a fresh slot: a new shard node key in an empty
    shard home (its UTB entry store loaded from the verified seed), and the scope its fresh authority starts at."""
    k = slot()
    old = auth_dir(k)
    marker = old/'lifetime'
    if not marker.exists() or not marker.read_text().startswith('fail-stop'):
        raise ValueError(f'recover needs the lost authority’s fail-stop marker in {old}: an unreachable authority alone is not '
                         'evidence of key loss')
    if not authority_lost(old):
        raise ValueError(f'the authority in {old} still answers and holds its key: this is not an authority loss '
                         '(change keys with `ubft validator rotate`)')
    n = next_slot()
    evm = evm_dir(n)
    ubft('shard-node', 'init', '--home', evm, '--generate')
    utb = ['--utb-genesis-id', pins['utb_genesis_id']]
    (HOME/f'seed-{n}').mkdir(mode=0o700)
    ubft('seed', 'import', '--dir', RELEASE/'seed', *utb, '--full-shard-conf', RELEASE/'full-shard-conf.json',
         '--home', HOME/f'seed-{n}', '--source', a.release_url + '/seed', *UTB, '--shard-utb-db', f'{evm.name}/shard-utb-entries.db')
    scope = wait_for('the local root’s epoch and the certified shard epoch', recovery_scope, limit=300)
    if a.shard_epoch:
        scope['shardEpoch'] = a.shard_epoch
    journal(HOME/RECOVERY, 'authority', id=cfg['id'], old=k, new=n, scope=scope)
    return read(HOME/RECOVERY)


def recover(a, pins):
    """#1286: move a bonded identity whose authority is lost to a fresh EVM node identity, then join with it at the next boundary."""
    if not a.yes:
        raise ValueError('confirm the delegation and binding transactions with recover --yes')
    with lock('.join.lock'):
        cfg = read(CONFIG)
        if not cfg.get('evmAuthority') or not cfg.get('id'):
            raise ValueError('recover is for a registered and bonded identity whose authority was lost (no identity in the config)')
        rec = recovery()
        fresh = rec is None or rec['phase'] not in RECOVERING or (
            (auth_dir(rec['new'])/'lifetime').exists() and authority_lost(auth_dir(rec['new'])))
        if fresh:
            if rec is not None and rec['phase'] in RECOVERING:
                print(f'validator: the fresh authority {auth_name(rec["new"])} of the pending recovery is lost too; preparing another slot')
            rec = prepare_recovery(a, pins, cfg)
            print(f'Prepared {auth_name(rec["new"])} and {evm_name(rec["new"])} (scope: root epoch {rec["scope"]["rootEpoch"]}, '
                  f'shard epoch {rec["scope"]["shardEpoch"]}). The old {auth_name(rec["old"])} and its marker are kept.')
            print('Next: start a new authority container on this volume (`docker run -d --restart=no ... authority`), '
                  'then run `ubft-validator recover --yes` again.')
            return 0
        old, new, ident, scope = rec['old'], rec['new'], rec['id'], rec['scope']
        d = auth_dir(new)
        if rec['phase'] == 'authority':
            wait_for(f'the fresh authority in {d} (start the authority container)', lambda: authority_status(d), limit=300)
            stamp_authority(d)
            authority('node-info', '--out', d/'node-info.json', home=d)
            provision_pos_policy(d, ident)
            journal(HOME/RECOVERY, 'transactions', **{k: rec[k] for k in ('id', 'old', 'new', 'scope')})
        if read(HOME/RECOVERY)['phase'] == 'transactions':
            with lock('.tx.lock', wait=True):
                ubft('validator', 'recover', '--old-authority-home', auth_name(old),
                     '--new-evm-authority-socket', f'{d.name}/operator.sock',
                     '--new-evm-authority-credential', f'{d.name}/operator.cred', '--new-evm-node-info', f'{d.name}/node-info.json')
            journal(HOME/RECOVERY, 'linking', **{k: rec[k] for k in ('id', 'old', 'new', 'scope')})
        if read(HOME/RECOVERY)['phase'] == 'linking':
            configure_authority(new)
            write(HOME/SLOT, f'{new}\n'.encode())   # the node process restarts its services on the fresh slot
            journal(HOME/RECOVERY, 'electing', **{k: rec[k] for k in ('id', 'old', 'new', 'scope')})
        if read(HOME/RECOVERY)['phase'] == 'electing':
            target = wait_for('the root epoch whose committee names the new EVM node',
                              lambda: active_member_epoch(root_status(), scope['rootEpoch']))
            journal(HOME/RECOVERY, 'activation', target=target, **{k: rec[k] for k in ('id', 'old', 'new', 'scope')})
        target = read(HOME/RECOVERY)['target']
        conf = d/'activated-shard.json'
        ubft('q3', 'shard-conf', '--root-rpc', ROOT, '--epoch', scope['shardEpoch'], '--out', conf)
        check_activated_conf(read(conf), read(d/'node-info.json'))
        if not authority_status(d)['enrollmentComplete']:
            authority('complete-enrollment', '--shard-conf', conf, home=d)
        advance(target)
        journal(HOME/RECOVERY, 'activated', target=target, **{k: rec[k] for k in ('id', 'old', 'new', 'scope')})
        wait_for('committee membership', lambda: json.loads(local_status().stdout).get('member'))
        show_status(a, pins)
        return 0


def check_activated_conf(conf, info):
    """The activated shard configuration must name the fresh EVM node with the fresh authority's key; otherwise the boundary was another
    election's (the scope is fixed for an authority's lifetime) and a further fresh authority is needed."""
    named = [v for v in conf.get('validators') or [] if v.get('nodeId') == info['nodeId']]
    if not named or str(named[0].get('sigKey', '')).lower() != str(info['sigKey']).lower():
        raise ValueError(f'shard epoch {conf.get("epoch")} does not name the fresh EVM node {info["nodeId"]} with the fresh key: '
                         'another election activated first. Stop the fresh authority container (keep its volume), then run '
                         '`ubft-validator recover --yes` again to prepare another slot.')


def leave(a, _pins):
    if not a.yes:
        raise ValueError('confirm retirement with exit --yes, or claim after maturity with exit --claim --yes')
    with lock('.join.lock'), lock('.tx.lock'):
        ubft('validator', 'claim' if a.claim else 'exit')


def main():
    os.umask(0o077)
    os.environ['UBFT_HOME'] = str(HOME)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['init', 'authority', 'run', 'join', 'status', 'exit', 'incumbent', 'recover'])
    p.add_argument('--ports', type=int, nargs=3, default=(27652, 29252, 31452))
    p.add_argument('--announce-addresses', help='a reachable IPv4 multiaddress prefix, e.g. /ip4/192.0.2.10')
    p.add_argument('--root-epoch', type=int, help='override the initial root epoch hint')
    p.add_argument('--shard-epoch', type=int, help='override the successor shard epoch hint')
    p.add_argument('--yes', action='store_true')
    p.add_argument('--claim', action='store_true')
    p.add_argument('--member-id', type=int)
    a = p.parse_args()
    pins = read(LOCK)
    a.release_url, a.rpc_url = (pins[k] for k in ('release_url', 'rpc_url'))
    if a.announce_addresses:
        prefix, kind, address = a.announce_addresses.split('/')
        if prefix or kind != 'ip4':
            p.error('--announce-addresses requires an IPv4 multiaddress prefix')
        ipaddress.IPv4Address(address)
    if len(set(a.ports)) != 3 or any(not 1024 <= port <= 65535 for port in a.ports):
        p.error('choose three distinct unprivileged P2P ports')
    if HOME.stat().st_mode & 0o077:
        p.error('/data must be private (0700)')
    try:
        fn = {'init':init, 'authority':authority_process, 'run':run, 'join':join, 'status':show_status, 'exit':leave,
              'incumbent':incumbent, 'recover':recover}
        raise SystemExit(fn[a.action](a, pins) or 0)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        p.exit(1, f'validator: {error}\n')


if __name__ == '__main__':
    main()
