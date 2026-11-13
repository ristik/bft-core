#!/usr/bin/env python3
"""A validator entity on a laptop (macOS + colima, or any docker host behind NAT) that joins a running package PoS generation over ONE ssh connection to the
generation's host. Its keys are made here and never leave this machine: the root key and the shard node key in docker volumes of the laptop's VM, the EVM
key only in the memory of its signing authority, the owner, withdrawal and payee keys in a volume (made by evm_keys.py inside a container). Only public
material travels, over ssh: node ids and node-info, trust bases and their signatures, possession proofs, readiness receipts, shard configurations, pins.

    remote_joiner.py init    --host HOST --generation GEN [--home DIR]   keys, volumes, compose.json; this checkout's deploy/testnet to HOST:~/rjoin/testnet,
                                                                           the host relay (remote_entity.py relay-up), the public facts (register)
    remote_joiner.py start   [--home DIR]   the follower (peer stubs, pod, execution client, root), then the agent and the tunnel in the background under
                                            caffeinate (logs and pids in <home>/run/)
    remote_joiner.py join    [--home DIR]   on the host: remote_entity.py join (fund, register, bond, prepare after an acknowledgement, admit, wait, drive)
    remote_joiner.py status  [--home DIR]   local services, the root's epoch and follower flag, the execution client's head, the tunnel
    remote_joiner.py agent | tunnel        the two background processes in the foreground (start runs them)
    remote_joiner.py background-stop       stop the agent and the tunnel (NOT the validator services; after joining, the tunnel is the validator's network)
    remote_joiner.py retire-plan           the retirement sequence, printed (nothing is run)

Ports (remote_entity.PORTS; every listener on the laptop binds 127.0.0.1):
    127.0.0.1:18001-18004  ssh -L to the host relay's root<i>.sock  -> root<i>:8000      (the laptop's peer stub peer<i> forwards root<i>:8000 here)
    127.0.0.1:19001-19004  ssh -L to shard<i>.sock                 -> shard<i>:9000     (peer<i>, alias shard<i>)
    127.0.0.1:18541-18544  ssh -L to ureth<i>.sock                 -> ureth<i>:8545     (peer<i>, alias ureth<i>: the join transactions)
    127.0.0.1:28000        colima publishes pod<J>:8000 (root<J>)   <- ssh -R <sock-dir>/root<J>.sock   (the host relay's alias root<J>:8000)
    127.0.0.1:29000        colima publishes pod<J>:9000 (shard<J>)  <- ssh -R <sock-dir>/shard<J>.sock  (alias shard<J>:9000)
    127.0.0.1:28700        this agent                               <- ssh -R <sock-dir>/agent.sock     (the host's drive, as root, bearer token)
  The laptop's root and shard node announce /dns4/root<J>/tcp/8000 and /dns4/shard<J>/tcp/9000: on the host those names are the relay's aliases.

After the join this machine is one of five validators and the quorum is four: the network then tolerates NO other fault while the laptop is away.
Do not sleep the laptop, do not restart colima or its VM, do not `docker compose down` this project: the signing authority's EVM key exists only in
its memory; a restart loses it, and only a new delegation (the next nonce) plus another handoff could replace it (no tool exists for that yet).
"""
import argparse
import base64
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import handoff            # noqa: E402  install_override
import handoff_ops        # noqa: E402  HELPER (the operator POST made inside the entity's namespace)
import joiner             # noqa: E402  joiner_services (the entity's services, cloned from the last genesis entity's)
import operator_rpc       # noqa: E402
import remote_entity      # noqa: E402  PORTS, the forwards

PORTS = remote_entity.PORTS
NETWORK_FILES = ('genesis.json', 'trust-base.json', 'full-shard-conf.json', 'aggregator-conf.json', 'b1-profile.json', 'pos-deployment.json',
                 'pos-genesis-identities.json', 'utb-genesis.cbor', 'utb-genesis.id', 'pos-plan.json')
VOLUMES = ('root', 'evm', 'auth', 'ureth', 'archive', 'jwt', 'network', 'wallet', 'tools', 'work')
PRIVATE = ('root', 'evm', 'auth', 'ureth', 'archive', 'jwt', 'wallet', 'work')
ROOT_POSTS = ('/api/v1/q3/signers', '/api/v1/q3/status', '/api/v1/handoff/plan', '/api/v1/handoff/intent', '/api/v1/handoff/endorse',
              '/api/v1/handoff/evm-assignment/context')
def subnet(project):
    """The laptop's validators network: 10.231.<n>.0/24 with n from the project name (two generations' joiner projects may exist side by side, one stopped),
    never one of the host's 172.x container networks (their announced addresses are not dialable here)."""
    import hashlib
    return f'10.231.{16 + hashlib.sha256(project.encode()).digest()[0] % 224}.0/24'
OPERATOR = ['--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred']


SEED = r'''
import os, shutil, sys, tarfile
ROOT = sys.argv[1] if len(sys.argv) > 1 else '/a'
t = tarfile.open(fileobj=sys.stdin.buffer, mode='r|')
added = kept = 0
current = None
def finish(rec):
    global added, kept
    if rec is None:
        return
    final, tmp = os.path.join(ROOT, rec), os.path.join(ROOT, '.seed-' + rec)
    if os.path.exists(final):
        shutil.rmtree(tmp, ignore_errors=True); kept += 1
    elif os.path.isdir(tmp):
        try:
            os.rename(tmp, final); added += 1
        except OSError:   # the running node wrote the same record meanwhile: its own copy stays
            shutil.rmtree(tmp, ignore_errors=True); kept += 1
for m in t:
    parts = m.name.split('/')
    if not parts[0].startswith('v2-') or len(parts) > 2:
        continue
    if parts[0] != current:
        finish(current); current = parts[0]
    if os.path.exists(os.path.join(ROOT, current)):
        continue
    tmp = os.path.join(ROOT, '.seed-' + current)
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    if m.isfile() and len(parts) == 2:
        p = os.path.join(tmp, parts[1])
        with open(p, 'wb') as out:
            out.write(t.extractfile(m).read())
        os.chmod(p, 0o600)
finish(current)
print('added', added, 'kept', kept)
'''   # a record directory is placed by rename once complete, and only when missing (the seeding of a running node's archive never touches a record it has)


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def say(text):
    print(f'{time.strftime("%H:%M:%SZ", time.gmtime())} {text}', flush=True)


class Failure(RuntimeError):
    pass


def run(cmd, check=True, input=None, text=True, timeout=None):
    done = subprocess.run(cmd, input=input, capture_output=True, text=text, timeout=timeout)
    if check and done.returncode:
        err = done.stderr if text else done.stderr.decode(errors='replace')
        raise Failure(f'{" ".join(map(str, cmd[:6]))}: exit {done.returncode}: {err.strip()[-600:]}')
    return done


# --- the laptop's compose file ---------------------------------------------------------------------------------------------------
def volume_mount(mount, entity):
    """'./validator<J>/root:/state' -> 'root:/state', './network:/network:ro' -> 'network:/network:ro' (named volumes in the VM, not Mac directories: the
    authority's Unix sockets and the stores need a Linux file system)."""
    src, _, rest = mount.partition(':')
    if src == './network':
        return f'network:{rest}'
    prefix = f'./validator{entity}/'
    if not src.startswith(prefix) or src[len(prefix):] not in VOLUMES:
        raise ValueError(f'unexpected mount {mount!r}')
    return f'{src[len(prefix):]}:{rest}'


def laptop_compose(host_compose, entity, root_id, evm_id, project, mac_host='host.docker.internal', genesis=remote_entity.GENESIS_ENTITIES):
    """The entity's services exactly as joiner.joiner_services writes them for the host, made laptop-local: named volumes, the pod's 8000/9000 published on
    127.0.0.1 (for the ssh -R), the announced addresses set to the host relay's aliases, no metrics relay, and one peer stub per genesis entity."""
    services = joiner.joiner_services(host_compose, entity, root_id, evm_id)
    services.pop(f'metrics{entity}', None)
    for svc in services.values():
        svc['volumes'] = [volume_mount(m, entity) for m in svc.get('volumes', [])]
    services[f'pod{entity}']['ports'] = [f'127.0.0.1:{PORTS["root_remote"]}:8000', f'127.0.0.1:{PORTS["shard_remote"]}:9000']
    for role, port in (('root', 8000), ('shard', 9000)):
        entry = services[f'{role}{entity}']['entrypoint']
        if '--announce-addresses' in entry:
            raise ValueError(f'{role}{entity} already announces addresses')
        at = entry.index('--address') + 2
        entry[at:at] = ['--announce-addresses', f'/dns4/{role}{entity}/tcp/{port}']
    rpc_image = host_compose['services']['rpc']['image']
    for i in genesis:
        services[f'peer{i}'] = {
            'image': rpc_image, 'entrypoint': ['python3', '-u', '/tools/tunnel_relay.py',
                                               '--forward', f'tcp:8000=tcp:{mac_host}:{PORTS["root_local"] + i}',
                                               '--forward', f'tcp:9000=tcp:{mac_host}:{PORTS["shard_local"] + i}',
                                               '--forward', f'tcp:8545=tcp:{mac_host}:{PORTS["ureth_local"] + i}'],
            'volumes': ['tools:/tools:ro'], 'networks': {'validators': {'aliases': [f'root{i}', f'shard{i}', f'ureth{i}']}},
            'restart': 'unless-stopped', 'mem_limit': '64m', 'cpus': 0.2, 'pids_limit': 64, 'read_only': True, 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
    used = sorted({m.split(':')[0] for svc in services.values() for m in svc.get('volumes', [])})
    return {'name': project, 'services': services, 'networks': {'validators': {'ipam': {'config': [{'subnet': subnet(project)}]}}},
            'volumes': {v: {'external': True, 'name': f'{project}_{v}'} for v in used}}


def set_scope(compose, entity, root_epoch, shard_epoch):
    entry = compose['services'][f'authority{entity}']['entrypoint']
    for flag, value in (('--root-epoch', str(root_epoch)), ('--shard-epoch', str(shard_epoch)), ('--trust-base', f'/network/handoff/trust-base-epoch{root_epoch}.json')):
        entry[entry.index(flag) + 1] = value
    return compose


def restore_entry(entry, body_id):
    entry = list(entry)
    entry[entry.index('run')] = 'restore'
    return entry + ['--tip-uc', '/state/tip.uc.cbor', '--tip-tr', '/state/tip.tr.cbor', '--trust-body-id', body_id]


def tunnel_command(host, entity, sock_dir):
    return ['ssh', '-N', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3', '-o', 'ConnectTimeout=15',
            '-o', 'BatchMode=yes', *remote_entity.ssh_forwards(entity, sock_dir), host]


class Laptop:
    def __init__(self, home):
        self.home = Path(home).expanduser().resolve()
        state = self.home / 'state.json'
        if not state.is_file():
            raise Failure(f'{state} is missing: run remote_joiner.py init first')
        self.state = json.loads(state.read_text())
        self.entity, self.project = self.state['entity'], self.state['project']
        self.node_image, self.rpc_image = self.state['images']['node'], self.state['images']['rpc']
        self.lock = threading.Lock()

    def save(self):
        (self.home / 'state.json').write_text(json.dumps(self.state, indent=1, sort_keys=True) + '\n')

    def compose_path(self):
        return self.home / 'compose.json'

    def compose(self):
        return json.loads(self.compose_path().read_text())

    def vol(self, name):
        return f'{self.project}_{name}'

    def files(self, *extra):
        out = ['-f', str(self.compose_path())]
        restore = self.home / 'compose.restore.json'
        if restore.is_file():
            out += ['-f', str(restore)]
        for path in extra:
            out += ['-f', str(path)]
        return out

    def dc(self, *args, extra=(), check=True, timeout=600):
        return run(['docker', 'compose', '-p', self.project, '--project-directory', str(self.home), *self.files(*extra), *args], check=check, timeout=timeout).stdout

    def one(self, image, args, mounts=(), user='10001:10001', network=None, input=None, entrypoint=None, check=True, text=True):
        cmd = ['docker', 'run', '--rm', '-i', '--user', user, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp', '-e', 'HOME=/tmp']
        if user.startswith('0:'):   # only the volume set-up and backups: ownership and modes of uid 10001's files
            cmd += ['--cap-add', 'CHOWN', '--cap-add', 'FOWNER', '--cap-add', 'DAC_OVERRIDE']
        if network:
            cmd += ['--network', network]
        for m in mounts:
            cmd += ['-v', m]
        if entrypoint:
            cmd += ['--entrypoint', entrypoint]
        return run(cmd + [image, *args], check=check, input=input, text=text)

    def ubft(self, args, mounts=(), network=None):
        return self.one(self.node_image, args, mounts, network=network).stdout

    def vol_write(self, volume, rel, data, mode=0o644):
        code = ('import os,sys;p=os.path.join("/v",sys.argv[1]);os.makedirs(os.path.dirname(p),exist_ok=True);t=p+".tmp";'
                'open(t,"wb").write(sys.stdin.buffer.read());os.chmod(t,int(sys.argv[2],8));os.replace(t,p)')
        self.one(self.rpc_image, ['-c', code, rel, oct(mode)[2:]], [f'{self.vol(volume)}:/v'], entrypoint='python3', input=data if isinstance(data, bytes) else data.encode(), text=False)

    def vol_read(self, volume, rel):
        return self.one(self.node_image, [f'/v/{rel}'], [f'{self.vol(volume)}:/v:ro'], entrypoint='cat', text=False).stdout

    def exec(self, service, *command, check=True):
        return run(['docker', 'compose', '-p', self.project, '--project-directory', str(self.home), *self.files(), 'exec', '-T', service, *command], check=check)

    def network(self):
        return f'{self.project}_validators'

    def urls(self):
        return operator_rpc.common_urls(self.compose())

    # --- reads ---
    def services_state(self):
        out = {}
        text = self.dc('ps', '-a', '--format', 'json', check=False)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows = json.loads(line)
            except ValueError:
                continue
            for row in rows if isinstance(rows, list) else [rows]:
                out[row['Service']] = row.get('State', '?')
        return out

    def pod_id(self):
        cid = self.dc('ps', '-q', f'pod{self.entity}').strip()
        if not cid:
            raise Failure(f'pod{self.entity} is not running')
        return cid

    def root_post(self, path, body=b'{}', timeout=10):
        if path not in ROOT_POSTS:
            raise Failure(f'{path}: not an operator path the agent forwards')
        cmd = ['docker', 'run', '--rm', '-i', '--network', f'container:{self.pod_id()}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--user', '10001:10001', '--entrypoint', 'python3', self.rpc_image, '-c', handoff_ops.HELPER, self.urls()[0] + path, str(timeout)]
        done = run(cmd, input=body, text=False, timeout=timeout + 60)
        status, _, payload = done.stdout.partition(b'\n')
        return int(status), payload

    def ureth_head(self):
        code = ('import json,urllib.request as u;r=u.Request("http://ureth%d:8545",json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}).encode(),'
                '{"Content-Type":"application/json"});print(int(json.loads(u.urlopen(r,timeout=5).read())["result"],16))' % self.entity)
        done = self.one(self.rpc_image, ['-c', code], network=self.network(), entrypoint='python3', check=False)
        return int(done.stdout.strip()) if done.returncode == 0 and done.stdout.strip().isdigit() else None

    def shard_rpc_up(self):
        """Whether the shard node's operator listener accepts connections (a restoring node opens it only once its restore is done; its readiness needs it)."""
        host, _, port = self.urls()[1].removeprefix('http://').partition(':')
        code = f'import socket;socket.create_connection(("{host}",{int(port)}),3);print("up")'
        try:
            done = run(['docker', 'run', '--rm', '--network', f'container:{self.pod_id()}', '--read-only', '--cap-drop', 'ALL', '--user', '10001:10001',
                        '--entrypoint', 'python3', self.rpc_image, '-c', code], check=False, timeout=60)
        except (Failure, subprocess.TimeoutExpired):
            return False
        return done.returncode == 0 and 'up' in done.stdout

    def shard_activated_epoch(self):
        """The latest root epoch the shard node logged as activated ("handoff activated"): its verified history's tip, which the join's readiness needs at
        the epoch being left. A restore logs its activations at its start and then thousands of replay lines: the whole log of the running container is
        scanned, and the last epoch found is kept per container start (the json-file log rotates)."""
        cid = self.dc('ps', '-q', f'shard{self.entity}').strip()
        if not cid:
            return None
        started = run(['docker', 'inspect', '--format', '{{.State.StartedAt}}', cid], check=False).stdout.strip()
        logs = run(['docker', 'logs', '--since', started, cid], check=False) if started else None
        found = re.findall(r'"message":"handoff activated","rootEpoch":(\d+)', (logs.stdout + logs.stderr) if logs else '')
        cache = self.state.get('shardActivated') or {}
        if found:
            cache = {'started': started, 'epoch': int(found[-1])}
            self.state['shardActivated'] = cache
            self.save()
            return cache['epoch']
        return cache.get('epoch') if cache.get('started') == started else None

    def note_member(self):
        """Once this root has been a member (it may have voted), its store is never rolled back (op_root_recover refuses)."""
        if not self.state.get('rootEverMember'):
            self.state['rootEverMember'] = now()
            self.save()

    def status(self):
        services = self.services_state()
        out = {'entity': self.entity, 'services': services, 'restoring': (self.home / 'compose.restore.json').is_file(), 'rootNodeId': self.state['rootNodeId'], 'evmNodeId': self.state['evmNodeId'],
               'accounts': self.state['accounts'], 'authorityScope': self.state.get('authorityScope')}
        if services.get(f'root{self.entity}') == 'running':
            for key, path in (('follower', '/api/v1/q3/status'), ('signers', '/api/v1/q3/signers')):
                try:
                    code, body = self.root_post(path)
                    data = json.loads(body) if code == 200 else None
                    if key == 'follower' and data:
                        out['activeEpoch'] = data.get('activeEpoch')
                    out[key] = data.get('follower') if key == 'follower' and data else data
                except (Failure, ValueError, subprocess.TimeoutExpired):
                    out[key] = None
            if out.get('follower') is False or (isinstance(out.get('signers'), dict) and self.state['rootNodeId'] in
                                                [x.get('nodeId') for x in out['signers'].get('signers') or []]):
                self.note_member()
            if isinstance(out.get('signers'), dict):
                out['epoch'], out['round'] = out['signers'].get('epoch'), out['signers'].get('round')
                out['signers'] = len(out['signers'].get('signers') or [])
        if services.get(f'ureth{self.entity}') == 'running':
            out['urethHead'] = self.ureth_head()
        if services.get(f'shard{self.entity}') == 'running':
            out['shardActivatedEpoch'] = self.shard_activated_epoch()
            out['shardRpc'] = self.shard_rpc_up()
        return out

    # --- the agent's operations (the host's drive asks; the outputs are public) ---
    def op_status(self):
        return self.status()

    def op_root_post(self, path, body_b64):
        status, body = self.root_post(path, base64.b64decode(body_b64))
        return {'status': status, 'body_b64': base64.b64encode(body).decode()}

    def op_logs(self, service, since='30m', tail=400):
        if not re.fullmatch(rf'(root|shard|authority|ureth|pod){self.entity}|peer\d', service):
            raise Failure(f'{service}: not a service of this entity')
        return {'text': self.dc('logs', '--no-color', '--since', since, '--tail', str(int(tail)), service, check=False)}

    def op_put_network(self, files):
        for name, data in files.items():
            if not remote_entity.NAME.match(name):
                raise Failure(f'{name}: not a handoff file name')
            self.vol_write('network', name, base64.b64decode(data), 0o644)
        return {'written': sorted(files)}

    def op_trust_base_sign(self, trust_base_b64):
        data = base64.b64decode(trust_base_b64)
        named = {n['nodeId'] for n in json.loads(data)['rootNodes']}
        if self.state['rootNodeId'] not in named:
            raise Failure('the trust base does not name this root: not signed')
        self.vol_write('work', 'tb.json', data, 0o644)
        self.ubft(['trust-base', 'sign', '--home', '/state', '--trust-base', '/work/tb.json'], [f'{self.vol("root")}:/state:ro', f'{self.vol("work")}:/work'])
        return {'trust_base_b64': base64.b64encode(self.vol_read('work', 'tb.json')).decode()}

    def op_evm_pop(self, context_b64, validators_b64, identities_b64):
        for name, data in (('context.json', context_b64), ('validators.json', validators_b64), ('identities.json', identities_b64)):
            self.vol_write('auth', name, base64.b64decode(data), 0o644)
        out = self.exec(f'authority{self.entity}', 'ubft', 'root', 'handoff', 'evm-pop', '--context', '/authority/context.json', '--validators', '/authority/validators.json',
                        '--identities', '/authority/identities.json', '--node-id', self.state['evmNodeId'], '--authority-socket', '/authority/operator.sock',
                        '--authority-credential', '/authority/operator.cred').stdout
        return {'text': out}

    def op_sign_pop(self, candidate_b64, attempt):
        self.vol_write('auth', 'candidate.hex', base64.b64decode(candidate_b64), 0o644)
        self.exec(f'authority{self.entity}', 'ubft', 'pos-relayer', 'sign-pop', '--candidate', '/authority/candidate.hex', '--pos-deployment', '/network/pos-deployment.json',
                  '--attempt', str(int(attempt)), '--authority-socket', '/authority/operator.sock', '--authority-credential', '/authority/operator.cred', '--out', '/authority/evmpop.json')
        return {'text': self.exec(f'authority{self.entity}', 'cat', '/authority/evmpop.json').stdout}

    def op_readiness(self, candidate_b64, genesis_hash, code_hash):
        if not re.fullmatch(r'0x[0-9a-fA-F]{64}', genesis_hash) or not re.fullmatch(r'(0x)?[0-9a-fA-F]{64}', code_hash):
            raise Failure('bad genesis or code hash')
        self.vol_write('network', 'handoff/candidate.cbor', base64.b64decode(candidate_b64), 0o644)
        root_rpc, shard_rpc = self.urls()
        j = self.entity
        self.exec(f'root{j}', 'ubft', 'root', 'handoff', 'q3-readiness', '--candidate', '/network/handoff/candidate.cbor', '--key-conf', '/state/keys.json',
                  '--root-rpc', root_rpc, '--shard-rpc', shard_rpc, '--eth-url', f'http://ureth{j}:8545', '--engine-url', f'http://ureth{j}:8551',
                  '--jwt-secret', '/jwt/jwt.hex', '--execution-genesis-hash', genesis_hash, '--execution-code-hash', code_hash, '--out', '/tmp/receipt.json')
        return {'text': self.exec(f'root{j}', 'cat', '/tmp/receipt.json').stdout}

    def root_epoch(self):
        """The root's epoch: its committed certificate's (q3/signers) or, for a follower that holds none (422), its installed one (q3/status activeEpoch)."""
        try:
            code, body = self.root_post('/api/v1/q3/signers')
            if code == 200:
                return json.loads(body).get('epoch')
            code, body = self.root_post('/api/v1/q3/status')
            return json.loads(body).get('activeEpoch') if code == 200 else None
        except (Failure, ValueError, subprocess.TimeoutExpired):
            return None

    def wait(self, what, probe, seconds, every=3):
        deadline, last = time.monotonic() + seconds, None
        while time.monotonic() < deadline:
            try:
                last = probe()
                if last:
                    return last
            except Exception as error:
                last = error
            time.sleep(every)
        raise Failure(f'{what}: not within {seconds} s (last: {last})')

    def op_install_root(self, epoch):
        """rehearse.pos_install for this root: stop, keep its store in the volume <project>_root-pre-epoch-N (once), recreate with the install flag."""
        epoch, j = int(epoch), self.entity
        if self.root_epoch() == epoch:
            return {'already': True}
        override = self.home / f'compose.install-epoch-{epoch}.json'
        if not override.exists():
            override.write_text(json.dumps(handoff.install_override(self.compose(), epoch), indent=1) + '\n')
        self.dc('stop', f'root{j}')
        backup = self.vol(f'root-pre-epoch-{epoch}')
        if run(['docker', 'volume', 'inspect', backup], check=False).returncode:
            try:
                code, body = self.root_post('/api/v1/q3/status')
                follower = code == 200 and json.loads(body).get('follower') is True and not self.state.get('rootEverMember')
            except (Failure, ValueError, subprocess.TimeoutExpired):
                follower = False   # unknown: counted as a possible member (never recoverable from this backup)
            if not follower:
                self.note_member()
            self.state.setdefault('rootBackups', {})[backup] = {'at': now(), 'neverMember': follower}
            self.save()
            run(['docker', 'volume', 'create', backup])
            self.one(self.node_image, ['-c', 'cp -a /state/. /backup/'], [f'{self.vol("root")}:/state:ro', f'{backup}:/backup'], user='0:0', entrypoint='sh')
        self.dc('up', '-d', '--no-deps', '--force-recreate', f'root{j}', extra=[override])
        # an install of many epochs fetches every activation bundle through the tunnel before the operator listener starts
        self.wait(f'root {j} listens again', lambda: self.root_post('/api/v1/q3/signers')[0] in (200, 400, 409, 422, 503), 900)
        return {'backup': backup}

    def op_root_recover(self, epoch):
        """Issue #1028: after an interrupted install of `epoch` every restart fails in the Q3 recovery (it runs before the record fetcher is installed). The
        store goes back to its pre-install backup (volume <project>_root-pre-epoch-N) and the root runs again without the install flag."""
        j, epoch = self.entity, int(epoch)
        backup = self.vol(f'root-pre-epoch-{epoch}')
        if run(['docker', 'volume', 'inspect', backup], check=False).returncode:
            raise Failure(f'no backup volume {backup}')
        # astra's review of #1029, finding 1: the store holds the safety module's record of what the root key signed; rolling it back could let the key
        # vote twice. Only a root that was never a member (it never signed) is recovered, from a backup taken while it was a follower
        if self.state.get('rootEverMember'):
            raise Failure(f'refused: this root has been a member since {self.state["rootEverMember"]} (it may have voted); its store is never rolled back')
        if not (self.state.get('rootBackups') or {}).get(backup, {}).get('neverMember'):
            raise Failure(f'refused: {backup} is not recorded as taken while this root was a follower that never signed')
        code, body = self.root_post('/api/v1/q3/status') if self.services_state().get(f'root{j}') == 'running' else (0, b'')
        if code == 200 and json.loads(body).get('follower') is False:
            self.note_member()
            raise Failure('refused: the root reports itself a member now')
        self.dc('stop', f'root{j}')
        self.one(self.node_image, ['-c', 'find /state -mindepth 1 -maxdepth 1 -exec rm -rf {} + && cp -a /backup/. /state/'],
                 [f'{self.vol("root")}:/state', f'{backup}:/backup:ro'], user='0:0', entrypoint='sh')
        override = self.home / f'compose.install-epoch-{epoch}.json'
        if override.exists():
            override.rename(self.home / 'run' / f'{override.name}.failed-{int(time.time())}')
        self.dc('up', '-d', '--no-deps', '--force-recreate', f'root{j}')
        self.wait(f'root {j} listens again', lambda: self.root_post('/api/v1/q3/status')[0] == 200, 180)
        return {'recovered': backup, 'epoch': self.root_epoch()}

    def op_authority_status(self):
        return json.loads(self.exec(f'authority{self.entity}', 'ubft', 'signing-authority', 'status', *OPERATOR).stdout)

    def op_authority_step(self, step, epoch, shard_epoch):
        """One order of the entity's switch (handoff_drive.advance_remote runs them as resumable sub-steps, status first). The shard node is stopped before an
        authority order and started only by `shard-start` (a joiner's comes back by its restore). The kept credential is written once, never overwritten."""
        j, epoch, shard_epoch = self.entity, int(epoch), int(shard_epoch)
        auth = f'authority{j}'
        conf = f'/network/handoff/shard-conf-{shard_epoch}.json'
        if step == 'shard-start':
            self.dc('start', f'shard{j}')
            return {'started': True}
        if step not in ('complete-enrollment', 'advance-epoch', 'replace-session'):
            raise Failure(f'{step}: not an authority order')
        self.dc('stop', f'shard{j}')
        if step == 'complete-enrollment':
            command = ['complete-enrollment', *OPERATOR, '--shard-conf', conf]
        elif step == 'advance-epoch':
            kept = f'/authority/client.cred.pre-epoch-{epoch}'
            self.exec(auth, 'sh', '-c', f'test -e {kept} || (cp /authority/client.cred {kept}.tmp && chmod 600 {kept}.tmp && mv {kept}.tmp {kept})')
            command = ['advance-epoch', *OPERATOR, '--trust-base', f'/network/handoff/trust-base-epoch{epoch}.json', '--shard-conf', conf]
        else:
            command = ['replace-session', *OPERATOR, '--out', '/authority/client.cred']
        done = self.exec(auth, 'ubft', 'signing-authority', *command, check=False)
        text = (done.stdout + done.stderr).strip()[-300:]
        if done.returncode:
            raise Failure(f'{step}: exit {done.returncode}: {text}')
        return {'step': step, 'out': text}

    def seed_archive(self):
        """The host survivor's archive records this node lacks, streamed over this machine's own ssh (remote_entity.py archive-tar): its node walks them locally."""
        s = self.state
        source = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', s['host'], f'sudo python3 {s["hostDir"]}/testnet/remote_entity.py archive-tar {s["hostGeneration"]} | gzip -1'],
                                  stdout=subprocess.PIPE)
        gunzip = subprocess.Popen(['gunzip'], stdin=source.stdout, stdout=subprocess.PIPE)
        done = subprocess.run(['docker', 'run', '--rm', '-i', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '-v', f'{self.vol("archive")}:/a',
                               '--entrypoint', 'python3', self.rpc_image, '-c', SEED], stdin=gunzip.stdout, capture_output=True, text=True)
        source.wait()
        gunzip.wait()
        if done.returncode or source.returncode:
            raise Failure(f'seeding the archive: ssh exit {source.returncode}, seed exit {done.returncode}: {done.stderr.strip()[-300:]}')
        return done.stdout.strip()

    def op_seed_archive(self):
        return {'seeded': self.seed_archive()}

    def op_restore_start(self, uc_b64, tr_b64, body_id):
        """rehearse.restore_joiner, the laptop half: the execution client's and the shard node's state emptied (its keys kept), the pin written, `shard-node restore`."""
        if not re.fullmatch(r'0x[0-9a-fA-F]+', body_id):
            raise Failure('bad body id')
        j = self.entity
        self.dc('stop', f'shard{j}', f'ureth{j}')
        wipe = ('find /evm -mindepth 1 -maxdepth 1 ! -name keys.json ! -name node-info.json -exec rm -rf {} + && '
                'find /archive -mindepth 1 -maxdepth 1 -exec rm -rf {} + && find /ureth -mindepth 1 -maxdepth 1 -exec rm -rf {} +')
        self.one(self.node_image, ['-c', wipe], [f'{self.vol("evm")}:/evm', f'{self.vol("archive")}:/archive', f'{self.vol("ureth")}:/ureth'], entrypoint='sh')
        seeded = None   # NOT seeded here: `shard-node restore` refuses an archive directory that is not empty (it fetches every record itself, from peers)
        self.dc('up', '-d', '--no-deps', f'ureth{j}')
        self.wait(f'the execution client {j} answers', lambda: self.ureth_head() is not None, 180)
        self.vol_write('evm', 'tip.uc.cbor', base64.b64decode(uc_b64), 0o600)
        self.vol_write('evm', 'tip.tr.cbor', base64.b64decode(tr_b64), 0o600)
        entry = restore_entry(self.compose()['services'][f'shard{j}']['entrypoint'], body_id)
        (self.home / 'compose.restore.json').write_text(json.dumps({'services': {f'shard{j}': {'entrypoint': entry}}}, indent=1) + '\n')
        self.dc('up', '-d', '--no-deps', '--force-recreate', f'shard{j}')
        time.sleep(10)
        return {'started': True, 'shard': self.services_state().get(f'shard{j}'), 'head': self.ureth_head(), 'seeded': seeded}

    def op_stop_validator(self):
        """After the entity left the committee: its shard node, root and execution client stop, then its signing authority (its key is not needed any
        more: the delegation ended with the retirement). Volumes stay: the wallet holds the withdrawal key for the claim. Never `compose down`."""
        j = self.entity
        for service in (f'shard{j}', f'root{j}', f'ureth{j}', f'authority{j}'):
            self.dc('stop', service)
        return {'stopped': self.services_state()}

    def op_restore_finish(self):
        j = self.entity
        (self.home / 'compose.restore.json').unlink(missing_ok=True)
        self.dc('up', '-d', '--no-deps', '--force-recreate', f'shard{j}')
        time.sleep(20)
        state = self.services_state().get(f'shard{j}')
        return {'running': state == 'running', 'state': state, 'head': self.ureth_head(),
                'tail': self.dc('logs', '--no-color', '--tail', '5', f'shard{j}', check=False)[-800:]}

    def op_start_authority(self, root_epoch, shard_epoch):
        """The signing authority at the scope it will sign in (joiner.set_scope), then the shard node (staging-only until its enrollment). The authority is started
        ONCE: when it runs it is never recreated (its EVM key is only in its memory, and the delegation names that key)."""
        j = self.entity
        scope = {'rootEpoch': int(root_epoch), 'shardEpoch': int(shard_epoch)}
        running = self.services_state().get(f'authority{j}') == 'running'
        if running:
            if self.state.get('authorityScope') != scope:
                raise Failure(f'the authority runs at scope {self.state.get("authorityScope")}, not {scope}: it is never restarted by this tool (its key would be lost)')
            return {'already': True, 'scope': scope}
        self.vol_read('network', f'handoff/trust-base-epoch{int(root_epoch)}.json')   # it must be there
        compose = set_scope(self.compose(), j, root_epoch, shard_epoch)
        self.compose_path().write_text(json.dumps(compose, indent=1, sort_keys=True) + '\n')
        self.dc('up', '-d', '--no-deps', f'authority{j}')
        self.state['authorityScope'], self.state['authorityStarted'] = scope, now()
        self.save()
        self.wait('the signing authority answers', lambda: self.exec(f'authority{j}', 'ubft', 'signing-authority', 'status', *OPERATOR).stdout, 60)
        self.dc('up', '-d', '--no-deps', f'shard{j}')
        return {'started': True, 'scope': scope}

    def op_tx(self, step, id=None, value_wei=None):
        """`pos-relayer tx join` with the keys of this machine: register and bond with the identity file that carries a throwaway EVM key (neither reads it), admit
        with the authority's EVM key (its operator socket)."""
        if step not in ('register', 'bond', 'admit'):
            raise Failure(f'{step}: not a join step')
        urls = ','.join(f'http://ureth{i}:8545' for i in remote_entity.GENESIS_ENTITIES)
        args = ['pos-relayer', 'tx', 'join', step, '--eth-rpc', urls, '--pos-deployment', '/network/pos-deployment.json']
        mounts = [f'{self.vol("wallet")}:/wallet:ro', f'{self.vol("network")}:/network:ro']
        if step == 'admit':
            args += ['--joiner', '/wallet/identity.json', '--evm-authority-socket', '/auth/operator.sock', '--evm-authority-credential', '/auth/operator.cred']
            mounts.append(f'{self.vol("auth")}:/auth')
        else:
            args += ['--joiner', '/wallet/identity-preadmit.json']
        if id is not None:
            args += ['--id', str(int(id))]
        if value_wei is not None:
            args += ['--value-wei', str(int(value_wei))]
        done = self.one(self.node_image, args, mounts, network=self.network(), check=False)
        tail = done.stderr.strip()[-600:]
        if done.returncode:
            raise Failure(f'join {step}: exit {done.returncode}: {tail}')
        out = {'tail': tail}
        if step == 'register':
            found = re.search(r'custody id (\d+)', done.stderr)
            if not found:
                raise Failure(f'register printed no custody id: {tail}')
            out['id'] = int(found.group(1))
            self.state['stakingId'] = out['id']
            self.save()
        return out

    CUSTODY_CALLS = {'requestRetirement(uint64)': 'owner', 'mature(uint256[])': 'owner', 'claim(uint256,address)': 'withdrawal'}

    def op_custody_tx(self, signature, args):
        """A custody call signed HERE with this entity's owner or withdrawal key (cast in the node image, keys from the wallet volume, never printed): only
        requestRetirement, mature and claim, only to the deployment's custody. Sent to every host execution client (their pools do not gossip)."""
        if signature not in self.CUSTODY_CALLS:
            raise Failure(f'{signature}: not a custody call this agent signs')
        if not all(re.fullmatch(r'[0-9]+|0x[0-9a-fA-F]{40}|\[[0-9, ]*\]', str(a)) for a in args):
            raise Failure('bad arguments')
        custody = json.loads(self.vol_read('network', 'pos-deployment.json'))['custody']
        signer = self.CUSTODY_CALLS[signature]
        chain = json.loads(self.vol_read('network', 'genesis.json'))['config']['chainId']
        urls = ' '.join(f'http://ureth{i}:8545' for i in remote_entity.GENESIS_ENTITIES)
        quoted = ' '.join(shlex.quote(str(a)) for a in args)
        script = (f'set -e; '   # cast mktx ignores ETH_PRIVATE_KEY: the key goes as an argument inside this one-shot container only
                  f'raw=$(/tools/cast mktx --legacy --rpc-url http://ureth1:8545 --chain {chain} --private-key "$(cat /wallet/{signer}.key)" {custody} {shlex.quote(signature)} {quoted}); '
                  f'for u in {urls}; do /tools/cast publish --rpc-url $u "$raw" >/dev/null 2>&1 || true; done; '
                  f'h=$(/tools/cast keccak "$raw"); echo "tx $h"; /tools/cast receipt --rpc-url http://ureth1:8545 --confirmations 1 --json "$h" | tr -d "\\n" | grep -oE "\\"(status|blockNumber)\\":\\"0x[0-9a-f]+\\""')
        done = self.one(self.node_image, ['-c', script], [f'{self.vol("wallet")}:/wallet:ro', f'{self.vol("tools")}:/tools:ro', f'{self.vol("network")}:/network:ro'],
                        network=self.network(), entrypoint='sh', check=False)
        out = (done.stdout + done.stderr).strip()
        if done.returncode:
            raise Failure(f'{signature}: exit {done.returncode}: {out[-400:]}')
        return {'out': out[-400:], 'signer': signer, 'address': self.state['accounts'][signer]}

    OPS = {'status': 'op_status', 'root-post': 'op_root_post', 'logs': 'op_logs', 'put-network': 'op_put_network', 'trust-base-sign': 'op_trust_base_sign',
           'evm-pop': 'op_evm_pop', 'sign-pop': 'op_sign_pop', 'readiness': 'op_readiness', 'install-root': 'op_install_root', 'root-recover': 'op_root_recover',
           'authority-status': 'op_authority_status', 'authority-step': 'op_authority_step', 'restore-start': 'op_restore_start', 'seed-archive': 'op_seed_archive', 'restore-finish': 'op_restore_finish', 'start-authority': 'op_start_authority', 'tx': 'op_tx', 'custody-tx': 'op_custody_tx', 'stop-validator': 'op_stop_validator'}
    READS = frozenset(('status', 'root-post', 'logs', 'authority-status'))

    def dispatch(self, name, args):
        if name not in self.OPS:
            raise Failure(f'unknown operation {name}')
        fn = getattr(self, self.OPS[name])
        if name in self.READS:
            return fn(**args)
        with self.lock:   # one changing operation at a time
            return fn(**args)


# --- init ----------------------------------------------------------------------------------------------------------------------
def ssh(host, command, input=None, text=True, check=True):
    return run(['ssh', '-o', 'BatchMode=yes', host, command], input=input, text=text, check=check)


def ensure_images(host, images):
    missing = [i for i in images if run(['docker', 'image', 'inspect', i], check=False).returncode]
    if missing:
        say(f'pulling {len(missing)} image(s) from {host} by ID (docker save | ssh | docker load)')
        sub = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', host, 'sudo docker save ' + ' '.join(map(shlex.quote, missing)) + ' | gzip -1'], stdout=subprocess.PIPE)
        gunzip = subprocess.Popen(['gunzip'], stdin=sub.stdout, stdout=subprocess.PIPE)
        subprocess.run(['docker', 'load'], stdin=gunzip.stdout, check=True)
        sub.wait()
        gunzip.wait()
    for i in images:
        run(['docker', 'image', 'inspect', i])


def source_version(here=HERE):
    """The commit and the cleanliness of the deploy/testnet this laptop copies to the host (where it runs with sudo), and the copy's digest."""
    git = lambda *args: subprocess.run(['git', '-C', str(here), *args], capture_output=True, text=True)
    head = git('rev-parse', 'HEAD')
    status = git('status', '--porcelain', '--', '.')
    return {'commit': head.stdout.strip() if head.returncode == 0 else None, 'dirty': status.returncode != 0 or bool(status.stdout.strip()),
            'digest': remote_entity.tree_digest(here)}


def init(host, generation, home, mac_host, allow_dirty=False):
    home = Path(home).expanduser().resolve()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    (home / 'run').mkdir(mode=0o700, exist_ok=True)
    host_gen = f'/srv/testnet/{generation}'
    host_home = ssh(host, 'echo $HOME').stdout.strip()
    host_dir = f'{host_home}/rjoin/{generation}'
    sock_dir = f'{host_dir}/sock'
    host_compose = json.loads(ssh(host, f'sudo cat {host_gen}/compose.yaml').stdout)
    entities = joiner.entities(host_compose)
    if entities != list(remote_entity.GENESIS_ENTITIES):
        raise Failure(f'the host generation has entities {entities}; this tool joins a fifth to the four genesis entities')
    entity = max(entities) + 1
    project = f'{generation}-joiner{entity}'
    images = {'node': host_compose['services'][f'root{entities[0]}']['image'], 'rpc': host_compose['services']['rpc']['image']}
    ensure_images(host, list(images.values()))
    state_path = home / 'state.json'
    state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    state.update({'host': host, 'generation': generation, 'hostGeneration': host_gen, 'hostDir': host_dir, 'sockDir': sock_dir, 'entity': entity,
                  'project': project, 'images': images, 'macHost': mac_host})
    state.setdefault('created', now())
    state.setdefault('hostUbft', f'{host_home}/track-c/bin/ubft')
    state.setdefault('hostRestorePin', f'{host_home}/track-c/bin/tn-h4pin')
    state.setdefault('hostCast', ssh(host, 'command -v cast || echo $HOME/.foundry/bin/cast').stdout.strip().splitlines()[-1])
    state.setdefault('rootNodeId', '')
    state.setdefault('evmNodeId', '')
    state.setdefault('accounts', {})
    state_path.write_text(json.dumps(state, indent=1, sort_keys=True) + '\n')
    lap = Laptop(home)

    # volumes in the VM: private ones 0700 for uid 10001; network/ and tools/ readable
    for v in VOLUMES:
        if run(['docker', 'volume', 'inspect', lap.vol(v)], check=False).returncode:
            run(['docker', 'volume', 'create', '--label', f'unicity.joiner={project}', lap.vol(v)])
    lap.one(lap.node_image, ['-c', 'for d in /v/*; do chown 10001:10001 $d; done; chmod 700 ' + ' '.join(f'/v/{p}' for p in PRIVATE) + '; chmod 755 /v/network /v/tools'],
            [f'{lap.vol(v)}:/v/{v}' for v in VOLUMES], user='0:0', entrypoint='sh')
    # the public network files (network/ is mounted read-only into every service, as on the host)
    listing = ' '.join(NETWORK_FILES)
    tar = ssh(host, f'sudo sh -c {shlex.quote(f"cd {host_gen}/network && tar -cf - {listing} $(ls handoff/trust-base-epoch*.json handoff/shard-conf-*.json 2>/dev/null)")}', text=False).stdout
    extract = 'import io,sys,tarfile;t=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()));t.extractall("/network",filter="data")'
    lap.one(lap.rpc_image, ['-c', extract], [f'{lap.vol("network")}:/network'], entrypoint='python3', input=tar, text=False)
    lap.one(lap.node_image, ['-c', 'chmod -R a+rX /network'], [f'{lap.vol("network")}:/network'], entrypoint='sh')
    (home / 'network-files.txt').write_text(lap.one(lap.node_image, ['-c', 'cd /network && ls -la . handoff'], [f'{lap.vol("network")}:/network:ro'], entrypoint='sh').stdout)
    # the keys, made where they stay
    have = lambda volume, rel: lap.one(lap.node_image, ['-c', f'test -e /v/{rel}'], [f'{lap.vol(volume)}:/v:ro'], entrypoint='sh', check=False).returncode == 0
    if not have('root', 'keys.json'):
        lap.ubft(['root-node', 'init', '--home', '/state', '--generate'], [f'{lap.vol("root")}:/state'])
    if not have('evm', 'keys.json'):
        lap.ubft(['shard-node', 'init', '--home', '/state', '--generate'], [f'{lap.vol("evm")}:/state'])
    if not have('auth', 'operator.cred'):
        lap.ubft(['signing-authority', 'credential', '--out', '/authority/operator.cred'], [f'{lap.vol("auth")}:/authority'])
    if not have('jwt', 'jwt.hex'):
        lap.one(lap.rpc_image, ['-c', 'import os,secrets;fd=os.open("/jwt/jwt.hex",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,(secrets.token_hex(32)+"\\n").encode())'],
                [f'{lap.vol("jwt")}:/jwt'], entrypoint='python3')
    root_id = lap.ubft(['node-id', '--home', '/state'], [f'{lap.vol("root")}:/state:ro']).strip().splitlines()[-1]
    evm_id = lap.ubft(['node-id', '--home', '/state'], [f'{lap.vol("evm")}:/state:ro']).strip().splitlines()[-1]
    node_info = json.loads(lap.vol_read('root', 'node-info.json'))
    keys_py = (HERE / 'evm_keys.py').read_text()
    accounts = json.loads(lap.one(lap.rpc_image, ['-', 'wallet', '/wallet'], [f'{lap.vol("wallet")}:/wallet'], entrypoint='python3', input=keys_py).stdout)
    for out, extra in (('identity.json', []), ('identity-preadmit.json', ['--throwaway-evm'])):
        lap.one(lap.rpc_image, ['-', 'identity', '/wallet', '/root/keys.json', f'/wallet/{out}', root_id, evm_id, *extra],
                [f'{lap.vol("wallet")}:/wallet', f'{lap.vol("root")}:/root:ro'], entrypoint='python3', input=keys_py)
    lap.vol_write('tools', 'tunnel_relay.py', (HERE / 'tunnel_relay.py').read_bytes(), 0o644)
    if not have('tools', 'cast'):   # Foundry's cast from the host (a public tool, no key): the custody calls (retirement, mature, claim) sign here with it
        lap.vol_write('tools', 'cast', ssh(host, 'cat "$(command -v cast || echo $HOME/.foundry/bin/cast)"', text=False).stdout, 0o755)
    token_file = home / 'agent.token'
    if not token_file.is_file():
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, secrets.token_hex(32).encode())
        os.close(fd)
    compose_file = home / 'compose.json'
    if not compose_file.is_file():   # once: it later carries the authority's scope, and the pod's config must never change while it runs
        compose_file.write_text(json.dumps(laptop_compose(host_compose, entity, root_id, evm_id, project, mac_host), indent=1, sort_keys=True) + '\n')
    lap.state.update({'rootNodeId': root_id, 'evmNodeId': evm_id, 'accounts': accounts, 'nodeInfo': node_info})
    lap.save()
    say(f'entity {entity}: root {root_id}, evm {evm_id}, owner {accounts["owner"]}')
    # the host: this checkout's deploy/testnet, the relay, the public facts
    version = source_version()
    if (version['dirty'] or not version['commit']) and not allow_dirty:
        raise Failure(f'{HERE} is dirty or not a git checkout (commit {version["commit"]}): the host runs this code with sudo; commit it, or pass --allow-dirty')
    sources = sorted(p.name for p in HERE.glob('*.py') if not p.name.startswith('.'))
    tarball = subprocess.run(['tar', '--no-xattrs', '-C', str(HERE), '-cf', '-', *sources], capture_output=True, check=True,
                             env=dict(os.environ, COPYFILE_DISABLE='1')).stdout   # no AppleDouble ._* members (macOS tar)
    ssh(host, f'mkdir -p {host_dir}/testnet && tar -C {host_dir}/testnet -xf -', input=tarball, text=False)
    record = dict(version, deployedAt=now(), deployedFrom=str(HERE))
    ssh(host, f'cat > {host_dir}/testnet/SOURCE.json', input=json.dumps(record, indent=1, sort_keys=True) + '\n')
    say(f'deployed {HERE} to {host}:{host_dir}/testnet: commit {version["commit"]}, dirty {version["dirty"]}, digest {version["digest"][:16]}')
    py = f'sudo python3 {host_dir}/testnet/remote_entity.py'
    say(ssh(host, f'{py} relay-up {host_gen} --entity {entity} --sock-dir {sock_dir} --uid $(id -u)').stdout.strip())
    public = {'rootNodeId': root_id, 'evmNodeId': evm_id, 'nodeInfo': node_info, 'accounts': accounts, 'token': token_file.read_text().strip()}
    say(ssh(host, f'{py} register {host_gen} --entity {entity} --sock-dir {sock_dir}', input=json.dumps(public)).stdout.strip())
    say(f'init done: {home}. Next: remote_joiner.py start --home {home}')
    return lap


# --- agent and tunnel ---------------------------------------------------------------------------------------------------------------
def serve_agent(lap, port=PORTS['agent']):
    token = (lap.home / 'agent.token').read_text().strip()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != '/op' or not hmac.compare_digest(self.headers.get('Authorization', ''), f'Bearer {token}'):
                return self.reply(403, {'ok': False, 'error': 'forbidden'})
            try:
                request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                name, args = request['op'], request.get('args') or {}
            except (ValueError, KeyError):
                return self.reply(400, {'ok': False, 'error': 'bad request'})
            started = time.monotonic()
            try:
                result = lap.dispatch(name, args)
                if name not in ('status', 'root-post'):
                    say(f'agent: {name} ok in {time.monotonic() - started:.1f} s')
                return self.reply(200, {'ok': True, 'result': result})
            except Exception as error:
                say(f'agent: {name} FAILED in {time.monotonic() - started:.1f} s: {str(error)[-400:]}')
                return self.reply(500, {'ok': False, 'error': str(error)[-1500:]})

    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    say(f'agent listening on 127.0.0.1:{port} (the host reaches it through ssh -R {lap.state["sockDir"]}/agent.sock)')
    server.serve_forever()


def tunnel_loop(lap):
    host, sock, j = lap.state['host'], lap.state['sockDir'], lap.entity
    cmd = tunnel_command(host, j, sock)
    while True:
        # sshd has StreamLocalBindUnlink no: the -R sockets of the previous connection must go first, or the forwards fail
        ssh(host, f'rm -f {sock}/root{j}.sock {sock}/shard{j}.sock {sock}/agent.sock', check=False)
        say('tunnel: ' + ' '.join(cmd[:2]) + f' ... {host} ({len(cmd)} args)')
        started = time.monotonic()
        rc = subprocess.run(cmd).returncode
        say(f'tunnel: ssh exited {rc} after {time.monotonic() - started:.0f} s; reconnecting in 3 s')
        time.sleep(3)


def background(lap, name, args):
    pid_file = lap.home / 'run' / f'{name}.pid'
    if pid_file.is_file():
        try:
            os.kill(int(pid_file.read_text()), 0)
            say(f'{name}: running (pid {pid_file.read_text().strip()})')
            return
        except (OSError, ValueError):
            pass
    log = open(lap.home / 'run' / f'{name}.log', 'a')
    wrap = ['caffeinate', '-ims'] if shutil.which('caffeinate') else []   # no idle or system sleep while it runs (a closed lid on battery still sleeps)
    proc = subprocess.Popen([*wrap, sys.executable, '-u', str(Path(__file__).resolve()), name, '--home', str(lap.home)], stdout=log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    pid_file.write_text(str(proc.pid))
    say(f'{name}: started (pid {proc.pid}, log {lap.home / "run" / f"{name}.log"})')


def background_stop(lap):
    for name in ('tunnel', 'agent'):
        pid_file = lap.home / 'run' / f'{name}.pid'
        if pid_file.is_file():
            try:
                os.killpg(int(pid_file.read_text()), 15)
                say(f'{name}: stopped')
            except (OSError, ValueError):
                say(f'{name}: not running')
            pid_file.unlink()


def start(lap):
    j = lap.entity
    services = lap.services_state()
    if services.get(f'pod{j}') != 'running':
        lap.dc('up', '-d', '--no-deps', *[f'peer{i}' for i in remote_entity.GENESIS_ENTITIES], f'pod{j}')
    else:
        lap.dc('up', '-d', '--no-deps', *[f'peer{i}' for i in remote_entity.GENESIS_ENTITIES])
    background(lap, 'agent', [])
    background(lap, 'tunnel', [])
    for s in (f'ureth{j}', f'root{j}'):
        if services.get(s) != 'running':
            lap.dc('up', '-d', '--no-deps', s)
    if lap.state.get('authorityScope') and services.get(f'authority{j}') != 'running':
        say(f'WARNING: authority{j} was started at {lap.state["authorityScope"]} and is not running: its EVM key is lost (a VM restart?). '
            'It is NOT restarted: the delegation names the lost key')
    if lap.state.get('authorityScope') and services.get(f'shard{j}') != 'running' and services.get(f'authority{j}') == 'running':
        lap.dc('start', f'shard{j}')
    lap.wait('the root reports itself a follower or a member', lambda: lap.status().get('follower') is not None or lap.root_epoch(), 180, every=5)
    say(json.dumps(lap.status(), sort_keys=True))


def join(lap, dry_run=False, stop_after=None, allow_dirty=False, funder=None, action='join'):
    """remote_entity.py join on the host, as a transient `systemd-run --user` unit (a dropped ssh session of this laptop must not kill a drive half way), its log
    followed here until it ends. Rerunning resumes: the host's state is in handoff/remote-joiners/<J>.json and the drive's journal."""
    s = lap.state
    version = source_version()
    if (version['dirty'] or not version['commit']) and not allow_dirty:
        raise Failure(f'{HERE} is dirty or not a git checkout (commit {version["commit"]}): commit and redeploy (init), or pass --allow-dirty')
    say(f'laptop checkout {HERE}: commit {version["commit"]}, dirty {version["dirty"]}, digest {version["digest"][:16]} (the host refuses a different deployed copy)')
    cmd = (f'sudo env PATH="$PATH:$(dirname {shlex.quote(s["hostCast"])})" python3 -u {s["hostDir"]}/testnet/remote_entity.py {action} {s["hostGeneration"]} '
           f'--entity {lap.entity} --ubft {s["hostUbft"]} --restore-pin {s["hostRestorePin"]} --cast {s["hostCast"]}' + (' --dry-run' if dry_run else '') + (f' --stop-after {stop_after}' if stop_after else '')
           + f' --source-digest {version["digest"]}' + (' --allow-dirty' if allow_dirty else '') + (f' --funder {shlex.quote(funder)}' if funder else ''))
    unit = f'laptop-{action}-{int(time.time())}'
    log = f'{s["hostDir"]}/{unit}.log'
    script = (f'systemd-run --user --quiet --collect --unit={unit} bash -c {shlex.quote(f"{cmd} > {log} 2>&1; echo EXIT=$? >> {log}")} && '
              f'touch {log} && (tail -n +1 -F {log} 2>/dev/null & t=$!; while systemctl --user is-active -q {unit}; do sleep 2; done; sleep 1; kill $t) && '
              f'tail -n 1 {log} | grep -q "^EXIT=0$"')
    say(f'on {s["host"]}: unit {unit}, log {log}: {cmd}')
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=15', s['host'], script]).returncode


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('action', choices=('init', 'start', 'status', 'join', 'catch-up', 'retire', 'agent', 'tunnel', 'background-stop', 'retire-plan'))
    p.add_argument('--home', help='this entity\'s directory on the laptop (default ~/unicity-joiner/<generation>)')
    p.add_argument('--host')
    p.add_argument('--generation')
    p.add_argument('--mac-host', default='host.docker.internal', help='how a container of the docker VM reaches the Mac\'s loopback (colima: host.docker.internal)')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--allow-dirty', action='store_true', help='init/join: deploy or run a dirty, uncommitted or mismatched copy of deploy/testnet on the host')
    p.add_argument('--stop-after', choices=('bonded',), help='join: stop after the bond')
    p.add_argument('--funder', help='join: a directory ON THE HOST with keystore.json and password, the operator account that pays the owner\'s 100 UCT bond and gas '
                   '(default: the faucet account)')
    a = p.parse_args(argv)
    home = a.home or (f'~/unicity-joiner/{a.generation}' if a.generation else None)
    if home is None:
        found = sorted(Path('~/unicity-joiner').expanduser().glob('*/state.json'))
        if len(found) != 1:
            p.error('--home (or --generation) is needed')
        home = str(found[0].parent)
    try:
        if a.action == 'init':
            if not (a.host and a.generation):
                p.error('init needs --host and --generation')
            init(a.host, a.generation, home, a.mac_host, a.allow_dirty)
            return 0
        lap = Laptop(home)
        if a.action == 'start':
            start(lap)
        elif a.action == 'status':
            print(json.dumps(lap.status(), indent=1, sort_keys=True))
            for name in ('agent', 'tunnel'):
                pid = lap.home / 'run' / f'{name}.pid'
                print(f'{name}: ' + (f'pid {pid.read_text().strip()}' if pid.is_file() else 'not started'))
        elif a.action == 'join':
            return join(lap, a.dry_run, a.stop_after, a.allow_dirty, a.funder)
        elif a.action == 'retire':   # requestRetirement (owner key, here), the handoff that leaves it out, the clean stop
            return join(lap, allow_dirty=a.allow_dirty, action='retire', funder=a.funder)
        elif a.action == 'catch-up':   # the follower to the current epoch (root install restart, shard restore): no chain transaction, the timer keeps driving
            return join(lap, allow_dirty=a.allow_dirty, action='catch-up')
        elif a.action == 'agent':
            serve_agent(lap)
        elif a.action == 'tunnel':
            tunnel_loop(lap)
        elif a.action == 'background-stop':
            background_stop(lap)
        elif a.action == 'retire-plan':
            s = lap.state
            return subprocess.run(['ssh', s['host'], f'sudo python3 {s["hostDir"]}/testnet/remote_entity.py retire-plan {s["hostGeneration"]} --entity {lap.entity}']).returncode
    except Failure as error:
        say(f'FAILED: {error}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
