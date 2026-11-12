#!/usr/bin/env python3
"""The host side of a validator entity that runs on ANOTHER machine (a laptop behind NAT): its per-entity handoff steps run there, through the laptop's
agent (remote_joiner.py agent), and only public material travels: trust bases, proposals, candidates, possession proofs, receipts, shard configurations,
restore pins. The entity's root key, shard key, EVM key (inside its signing authority) and its owner, withdrawal and payee keys never leave the laptop.

Networking (the laptop opens ONE `ssh -N`, remote_joiner.py tunnel; nothing on the host listens on TCP for it, sshd has GatewayPorts no):

  host <generation>-laptop-relay   a container on the generation's internal `validators` network, aliases root<J> and shard<J> (J = the laptop's entity),
                                   the package's rpc image running tunnel_relay.py as the ssh user (uid 1000), socket directory <sock-dir> (mode 0700):
     tcp 8000  (alias root<J>)  -> <sock-dir>/root<J>.sock   (made by the laptop's ssh -R; -> laptop 127.0.0.1:28000 -> its root's 8000)
     tcp 9000  (alias shard<J>) -> <sock-dir>/shard<J>.sock  (ssh -R; -> laptop 127.0.0.1:29000 -> its shard node's 9000)
     <sock-dir>/root<i>.sock    -> root<i>:8000    i = 1..4  (the laptop's ssh -L 127.0.0.1:1800<i>)
     <sock-dir>/shard<i>.sock   -> shard<i>:9000   i = 1..4  (ssh -L 127.0.0.1:1900<i>)
     <sock-dir>/ureth<i>.sock   -> ureth<i>:8545   i = 1..4  (ssh -L 127.0.0.1:1854<i>: the laptop's relayer sends its join transactions to every pool, as the host's does)
  <sock-dir>/agent.sock         (ssh -R; -> laptop 127.0.0.1:28700, the agent): what this module calls, as root, with the agent's bearer token

Every root and shard node of the generation dials root<J>/shard<J> by these aliases (the laptop's nodes announce /dns4/root<J>/tcp/8000 and
/dns4/shard<J>/tcp/9000); the laptop's nodes dial root<i>/shard<i>, which its peer stubs forward to the -L ports. Operator RPCs (8002, 9101) never cross.

    remote_entity.py relay-up     <generation> --entity J --sock-dir DIR --script tunnel_relay.py     (idempotent; the one host container this adds)
    remote_entity.py relay-status <generation>
    remote_entity.py register     <generation> --entity J --sock-dir DIR < public.json               (the laptop's public facts, from remote_joiner.py)
    remote_entity.py status       <generation> --entity J
    remote_entity.py join         <generation> --entity J --ubft UBFT --restore-pin H4PIN [--cast CAST] [--dry-run]
    remote_entity.py retire-plan  <generation> --entity J                                              (prints the retirement sequence; changes nothing)

`join` is the whole act (briefs/laptop-join-runbook.md): fund the laptop's owner from the faucet account (100 UCT bond + gas), register and bond (the
laptop signs), then, right after an acknowledged handoff (driving the open no-change result first if there is one) the trust base of E+1 over the
committee and the joiner, the joiner's signing authority started at that scope, admitDelegation; then the election's next result must name the joiner
and handoff_drive.py drives it with this transport. While the joiner is `prepared`, handoff_drive refuses a result that leaves it out (the epoch would move
and the joiner's authority scope go stale, briefs/handoff-drive-2026-11-12.md gaps 2 and 3) unless --allow-excluding-joiner.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

PORTS = {
    'root_local': 18000,    # Mac 127.0.0.1:18000+i  -ssh -L-> <sock-dir>/root<i>.sock  -> root<i>:8000
    'shard_local': 19000,   # Mac 127.0.0.1:19000+i  -> shard<i>:9000
    'ureth_local': 18540,   # Mac 127.0.0.1:18540+i  -> ureth<i>:8545
    'root_remote': 28000,   # Mac 127.0.0.1:28000 (colima publishes the laptop pod's 8000) <-ssh -R- <sock-dir>/root<J>.sock
    'shard_remote': 29000,  # Mac 127.0.0.1:29000 (pod's 9000)                           <-ssh -R- <sock-dir>/shard<J>.sock
    'agent': 28700,         # Mac 127.0.0.1:28700 (remote_joiner.py agent)               <-ssh -R- <sock-dir>/agent.sock
}
GENESIS_ENTITIES = (1, 2, 3, 4)
STATES = ('registered', 'bonded', 'prepared', 'member', 'retiring')
BOND_UNIT = 100 * 10 ** 18
GAS = 2 * 10 ** 18
NAME = re.compile(r'^handoff/[A-Za-z0-9][A-Za-z0-9._-]*$')


class AgentError(RuntimeError):
    """The laptop's agent did not answer, or refused: the step did not happen there (or its outcome is unknown: retry the drive)."""


def relay_name(generation):
    return f'{Path(generation).name}-laptop-relay'


def relay_forwards(entity, genesis=GENESIS_ENTITIES):
    """tunnel_relay.py --forward arguments of the host relay."""
    out = [f'tcp:8000=unix:/sock/root{entity}.sock', f'tcp:9000=unix:/sock/shard{entity}.sock']
    for i in genesis:
        out += [f'unix:/sock/root{i}.sock=tcp:root{i}:8000', f'unix:/sock/shard{i}.sock=tcp:shard{i}:9000', f'unix:/sock/ureth{i}.sock=tcp:ureth{i}:8545']
    return out


def ssh_forwards(entity, sock_dir, genesis=GENESIS_ENTITIES):
    """The -L and -R arguments of the laptop's one `ssh -N` (ports in PORTS)."""
    out = []
    for i in genesis:
        out += ['-L', f'127.0.0.1:{PORTS["root_local"] + i}:{sock_dir}/root{i}.sock', '-L', f'127.0.0.1:{PORTS["shard_local"] + i}:{sock_dir}/shard{i}.sock',
                '-L', f'127.0.0.1:{PORTS["ureth_local"] + i}:{sock_dir}/ureth{i}.sock']
    out += ['-R', f'{sock_dir}/root{entity}.sock:127.0.0.1:{PORTS["root_remote"]}', '-R', f'{sock_dir}/shard{entity}.sock:127.0.0.1:{PORTS["shard_remote"]}',
            '-R', f'{sock_dir}/agent.sock:127.0.0.1:{PORTS["agent"]}']
    return out


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def unb64(text):
    return base64.b64decode(text, validate=True)


def tb_without_signatures(tb):
    return {k: v for k, v in tb.items() if k != 'signatures'}


def check_signed(sent, returned, node_id):
    """The laptop's trust base back: the same body, every signature it had, and one more, by `node_id`."""
    if tb_without_signatures(sent) != tb_without_signatures(returned):
        raise AgentError('the signed trust base differs from the one sent in more than its signatures')
    before, after = sent.get('signatures') or {}, returned.get('signatures') or {}
    if any(after.get(k) != v for k, v in before.items()):
        raise AgentError('the signed trust base changed a signature it was sent with')
    if set(after) - set(before) != {node_id}:
        raise AgentError(f'the signed trust base adds {sorted(set(after) - set(before))}, not exactly the joiner\'s root {node_id}')
    return returned


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class AgentClient:
    def __init__(self, sock, token, connect=None):
        self.sock, self.token = str(sock), token
        self.connect = connect or (lambda timeout: UnixHTTPConnection(self.sock, timeout))

    def op(self, name, timeout=120, **args):
        body = json.dumps({'op': name, 'args': args}).encode()
        try:
            conn = self.connect(timeout)
            conn.request('POST', '/op', body, {'Content-Type': 'application/json', 'Authorization': f'Bearer {self.token}'})
            response = conn.getresponse()
            text = response.read()
            conn.close()
        except (OSError, http.client.HTTPException) as error:
            raise AgentError(f'the laptop agent at {self.sock} does not answer ({type(error).__name__}: {error}): is the tunnel up (remote_joiner.py start)?') from None
        try:
            reply = json.loads(text)
        except ValueError:
            raise AgentError(f'{name}: the agent answered {response.status} with no JSON') from None
        if response.status != 200 or not reply.get('ok'):
            raise AgentError(f'{name} on the laptop: {reply.get("error") or response.status}')
        return reply.get('result') or {}


class RemoteEntity:
    """Entity J on the laptop, as the drive sees it. `info` is <generation>/handoff/remote-joiners/<J>.json (public facts and the agent's token)."""

    def __init__(self, generation, info, client=None):
        self.gen, self.info = Path(generation), info
        self.entity = int(info['entity'])
        self.client = client or AgentClient(info['agentSocket'], info['token'])

    @property
    def root_node_id(self):
        return self.info['rootNodeId']

    @property
    def evm_node_id(self):
        return self.info['evmNodeId']

    @property
    def state(self):
        return self.info.get('state', 'registered')

    def node_info_path(self):
        return info_dir(self.gen) / f'{self.entity}-node-info.json'

    def services(self):
        return [f'{role}{self.entity}' for role in ('pod', 'root', 'shard', 'authority', 'ureth')]

    # --- reads ---
    def status(self):
        return self.client.op('status', timeout=60)

    def running(self):
        return {name for name, state in self.status().get('services', {}).items() if state == 'running'}

    def post(self, path, body, timeout=10):
        """A POST to the laptop root's operator endpoint (only the reads the drive makes: q3/signers and q3/status)."""
        import handoff_ops
        try:
            out = self.client.op('root-post', timeout=timeout + 40, path=path, body_b64=b64(body))
        except AgentError as error:
            raise handoff_ops.HandoffError(f'entity {self.entity} (laptop): {error}') from None
        return int(out['status']), unb64(out['body_b64'])

    def logs(self, service, since='30m', tail=400):
        return self.client.op('logs', service=service, since=since, tail=tail).get('text', '')

    # --- the per-entity handoff steps ---
    def put(self, files):
        """Public files into the laptop's network/handoff (the joiner's services mount network/ read-only, as on the host)."""
        payload = {}
        for name, path in files.items():
            if not NAME.match(name):
                raise ValueError(f'not a handoff file name: {name}')
            payload[name] = b64(Path(path).read_bytes())
        return self.client.op('put-network', files=payload)

    def sign_trust_base(self, path):
        path = Path(path)
        sent = json.loads(path.read_text())
        out = self.client.op('trust-base-sign', trust_base_b64=b64(path.read_bytes()))
        returned = check_signed(sent, json.loads(unb64(out['trust_base_b64'])), self.root_node_id)
        path.write_text(json.dumps(returned, indent=2) + '\n')
        return returned

    def evm_pop(self, context, validators, identities):
        return self.client.op('evm-pop', context_b64=b64(Path(context).read_bytes()), validators_b64=b64(Path(validators).read_bytes()),
                              identities_b64=b64(Path(identities).read_bytes()))['text']

    def sign_pop(self, candidate, attempt):
        return self.client.op('sign-pop', candidate_b64=b64(Path(candidate).read_bytes()), attempt=str(attempt))['text']

    def readiness(self, candidate, genesis_hash, code_hash):
        return self.client.op('readiness', timeout=300, candidate_b64=b64(Path(candidate).read_bytes()), genesis_hash=genesis_hash, code_hash=code_hash)['text']

    def install_root(self, target):
        return self.client.op('install-root', timeout=300, epoch=int(target))

    def advance(self, target, shard_epoch, joiner):
        return self.client.op('advance', timeout=300, epoch=int(target), shard_epoch=int(shard_epoch), joiner=bool(joiner))

    def restore_start(self, uc, tr, body_id):
        return self.client.op('restore-start', timeout=600, uc_b64=b64(uc), tr_b64=b64(tr), body_id=body_id)

    def restore_finish(self):
        return self.client.op('restore-finish', timeout=300)

    def start_authority(self, root_epoch, shard_epoch):
        return self.client.op('start-authority', timeout=180, root_epoch=int(root_epoch), shard_epoch=int(shard_epoch))

    def tx(self, step, **args):
        return self.client.op('tx', timeout=300, step=step, **args)

    def save(self):
        save_info(self.gen, self.info)


class EntityTransport:
    """handoff_ops.DockerTransport for the host's entities, the laptop agent for a remote one: one `post(i, path, body)` for the drive."""

    def __init__(self, docker, remote):
        self.docker, self.remote = docker, dict(remote)
        self.root_rpc = docker.root_rpc
        self.entities = sorted(set(docker.entities) | set(self.remote))

    def post(self, i, path, body, timeout=10):
        if i in self.remote:
            return self.remote[i].post(path, body, timeout)
        return self.docker.post(i, path, body, timeout)


# --- the registry of remote entities in the generation --------------------------------------------------------------------------
def info_dir(generation):
    return Path(generation) / 'handoff' / 'remote-joiners'


def save_info(generation, info):
    d = info_dir(generation)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = d / f'{int(info["entity"])}.json'
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # it holds the agent's bearer token
    with os.fdopen(fd, 'w') as out:
        json.dump(info, out, indent=1, sort_keys=True)
    os.replace(tmp, path)


def load(generation):
    """{entity: RemoteEntity} of every remote entity registered with the generation."""
    out = {}
    d = info_dir(generation)
    if d.is_dir():
        for path in sorted(d.glob('*.json')):
            if not path.stem.isdigit():   # <J>-node-info.json beside <J>.json
                continue
            info = json.loads(path.read_text())
            out[int(info['entity'])] = RemoteEntity(generation, info)
    return out


def register(generation, entity, sock_dir, public):
    """Record the laptop's public facts. `public`: rootNodeId, evmNodeId, nodeInfo (the root's node-info.json), accounts {owner, withdrawal, payee}, token."""
    for key in ('rootNodeId', 'evmNodeId', 'nodeInfo', 'accounts', 'token'):
        if key not in public:
            raise ValueError(f'the public facts lack {key}')
    if public['nodeInfo'].get('nodeId') != public['rootNodeId']:
        raise ValueError('the node-info names another root than rootNodeId')
    if any(k in json.dumps(public['nodeInfo']) for k in ('privateKey', 'privKey')):
        raise ValueError('the node-info carries a private key: refused')
    d = info_dir(generation)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    (d / f'{entity}-node-info.json').write_text(json.dumps(public['nodeInfo'], indent=2) + '\n')
    path = d / f'{entity}.json'
    old = json.loads(path.read_text()) if path.is_file() else {}
    if old and old.get('rootNodeId') != public['rootNodeId']:
        raise ValueError(f'entity {entity} is registered with root {old.get("rootNodeId")}: another laptop identity (move {path} aside to start over)')
    info = {**old, 'entity': entity, 'rootNodeId': public['rootNodeId'], 'evmNodeId': public['evmNodeId'], 'accounts': public['accounts'],
            'token': public['token'], 'agentSocket': str(Path(sock_dir) / 'agent.sock'), 'sockDir': str(sock_dir)}
    info.setdefault('state', 'registered')
    save_info(generation, info)
    return {k: v for k, v in info.items() if k != 'token'}


def map_joiner(generation, staking_id, entity):
    """handoff/joiners.json, the drive's stakingId -> entity map."""
    path = Path(generation) / 'handoff' / 'joiners.json'
    current = json.loads(path.read_text()) if path.is_file() else {}
    current[str(staking_id)] = int(entity)
    path.write_text(json.dumps(current, indent=1, sort_keys=True) + '\n')


# --- the relay ---------------------------------------------------------------------------------------------------------------------
def docker(*args, check=True):
    return subprocess.run(['docker', *args], check=check, text=True, capture_output=True)


def relay_up(generation, entity, sock_dir, script, uid):
    generation, sock_dir = Path(generation), Path(sock_dir)
    compose = json.loads((generation / 'compose.yaml').read_text())
    name = relay_name(generation)
    state = docker('inspect', '--format', '{{.State.Status}}', name, check=False)
    if state.returncode == 0 and state.stdout.strip() == 'running':
        return {'relay': name, 'already': True}
    if state.returncode == 0:
        docker('rm', name)   # exactly this container (stopped): recreated below
    network = docker('network', 'ls', '-q', '--filter', f'label=com.docker.compose.project={compose["name"]}', '--filter', 'label=com.docker.compose.network=validators').stdout.split()
    if len(network) != 1:
        raise RuntimeError(f'the generation has {len(network)} validators networks')
    if any(f'pod{entity}' == s for s in compose['services']):
        raise RuntimeError(f'entity {entity} is a host entity: the relay alias root{entity} would shadow it')
    sock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(sock_dir, uid, uid)
    tool = sock_dir.parent / 'tunnel_relay.py'
    tool.write_bytes(Path(script).read_bytes())
    os.chmod(tool, 0o644)
    image = compose['services']['rpc']['image']
    args = ['run', '-d', '--name', name, '--network', network[0], '--network-alias', f'root{entity}', '--network-alias', f'shard{entity}',
            '--user', f'{uid}:{uid}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '96m', '--cpus', '0.5',
            '--pids-limit', '64', '--restart', 'unless-stopped', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3', '--label', f'unicity.laptop-relay={generation.name}',
            '-v', f'{sock_dir}:/sock', '-v', f'{tool}:/relay/tunnel_relay.py:ro', '--entrypoint', 'python3', image, '-u', '/relay/tunnel_relay.py']
    for forward in relay_forwards(entity):
        args += ['--forward', forward]
    docker(*args)
    time.sleep(2)
    return {'relay': name, 'started': True, 'logs': docker('logs', name, check=False).stdout.strip()[-400:]}


# --- the orchestrated join ----------------------------------------------------------------------------------------------------------
def say(text):
    print(f'{time.strftime("%H:%M:%SZ", time.gmtime())} {text}', flush=True)


class Join:
    def __init__(self, generation, entity, ubft, restore_pin, cast, dry_run=False, here=None, stop_after=None):
        import handoff_drive
        self.hd = handoff_drive
        self.gen, self.entity, self.ubft, self.restore_pin, self.cast, self.dry = Path(generation).resolve(), entity, ubft, restore_pin, cast, dry_run
        self.here = Path(here or Path(__file__).resolve().parent)
        self.stop_after = stop_after
        self.d = handoff_drive.Drive(self.gen, cast, ubft, restore_pin)
        if entity not in self.d.remote:
            raise RuntimeError(f'entity {entity} is not registered (remote_entity.py register)')
        self.r = self.d.remote[entity]

    def save(self, **change):
        self.r.info.update(change)
        self.r.save()

    def drive(self, result, *extra):
        """handoff_drive.py as a child (its own journal, resumable): returns its exit status."""
        cmd = [sys.executable, str(self.here / 'handoff_drive.py'), str(self.gen), result, '--ubft', str(self.ubft), '--cast', self.cast,
               *(['--restore-pin', str(self.restore_pin)] if self.restore_pin else []), *extra]
        say('$ ' + ' '.join(cmd[1:]))
        return subprocess.run(cmd).returncode

    def custody_lots(self, ident):
        return self.d.view_text(self.d.custody, 'generationLots(uint64,uint64)(uint256[])', str(ident), '1').strip('[]').replace(',', ' ').split()

    def members_of(self, result):
        return self.hd.frozen_ids(self.d.view_text(self.d.election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', result))

    def due(self):
        """(rounds, seconds) until the election's next attempt is due (thresholds() minus the registry clock)."""
        p, t = self.d.view(self.d.election, 'thresholds()(uint256,uint256)')
        return p - self.d.progress(), t - self.d.view(self.d.REGISTRY, 'ucTime()(uint64)')[0]

    def run(self):
        d, r = self.d, self.r
        st = r.status()
        say(f'laptop entity {self.entity}: state {r.state}, services {st.get("services")}, follower {st.get("follower")}')
        if r.state == 'member':
            say('already a member: nothing to do')
            return 0
        if st.get('follower') is not True:
            raise RuntimeError('the laptop root does not report itself a follower: remote_joiner.py up, and check the tunnel')
        owner = r.info['accounts']['owner']
        # 1. funding: the bond unit and the gas of three transactions, from the faucet account (its key stays on the host; the drive's path)
        need = BOND_UNIT + GAS if r.state in ('registered',) else GAS // 2
        have = d.balance(owner)
        say(f'owner {owner}: {have / 1e18:.4f} UCT')
        if have < need and r.state in ('registered', 'bonded'):
            if self.dry:
                say(f'[dry-run] would fund {owner} with {(need - have) / 1e18:.4f} UCT from the faucet account')
            else:
                d.faucet_send(owner, need - have)
        # 2. register and bond, signed on the laptop (any time: an identity without a delegation is not eligible)
        if r.state == 'registered':
            ident = r.info.get('stakingId')
            if not ident:
                if self.dry:
                    say('[dry-run] would register (root-key PoP) and bond 100 UCT')
                    return 0
                out = r.tx('register')
                ident = int(out['id'])
                self.save(stakingId=ident)
                map_joiner(self.gen, ident, self.entity)
                say(f'registered: custody id {ident}')
            if not self.custody_lots(ident):
                r.tx('bond', id=ident, value_wei=str(BOND_UNIT))
            lots = self.custody_lots(ident)
            if len(lots) != 1:
                raise RuntimeError(f'custody id {ident} has lots {lots}, want exactly one')
            self.save(state='bonded')
            say(f'bonded: custody id {ident}, lot {lots[0]}')
        ident = int(r.info['stakingId'])
        if self.stop_after == 'bonded':
            say(f'stopping after the bond (--stop-after bonded): custody id {ident}; the rest is `join` again')
            return 0
        # 3. the quiet point: no open result, and enough time before the next attempt for the prepare (trust base, authority start, admit)
        if r.state == 'bonded':
            while True:
                open_result = d.open_result()
                if open_result:
                    members = self.members_of(open_result)
                    if ident in members:
                        raise RuntimeError(f'result {open_result} names the joiner although its delegation was never admitted by this tool')
                    say(f'result {open_result[:12]}.. is open with {members}: driving it first (no change), the join is prepared right after its acknowledgement')
                    if self.dry:
                        say('[dry-run] would run handoff_drive.py now')
                        return 0
                    rc = self.drive(open_result)
                    if rc != 0:
                        raise RuntimeError(f'the no-change drive stopped (exit {rc}): fix and rerun the same command (it resumes)')
                    continue
                rounds, seconds = self.due()
                say(f'no result open; the next attempt is due in {rounds} rounds / {seconds} s')
                if rounds < 160 or seconds < 90:
                    say('too close to the next attempt for the prepare: waiting for it (its result is driven as a no-change, then the prepare follows)')
                    d.wait('the election reserves its next result', lambda: d.open_result(), 900)
                    continue
                if self.dry:
                    say('[dry-run] would prepare now: trust base, the authority at its scope, admitDelegation')
                    return 0
                self.prepare(ident)
                break
        # 4. the election's next result must name the joiner; then the drive, with this transport
        result = d.wait('the election reserves a result', lambda: d.open_result(), 1200)
        members = self.members_of(result)
        say(f'result {result} elects {members}')
        if ident not in members:
            raise RuntimeError(f'the result leaves the joiner (custody id {ident}) out: not driven (the drive refuses it while the joiner is prepared). '
                               'Look at the election\'s reason (lastAttemptResult) before anything else')
        rc = self.drive(result, '--require-member', str(self.entity))
        if rc != 0:
            raise RuntimeError(f'handoff_drive stopped (exit {rc}): rerun the same command (the drive resumes from handoff/log.jsonl)')
        self.save(state='member', memberSince=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        say(f'DONE: entity {self.entity} (the laptop) is a member')
        return 0

    def prepare(self, ident):
        """The trust base of E+1 over the current committee and the joiner (signed by every member, the joiner on the laptop), the joiner's authority started at
        that scope (and its shard node staging-only), then admitDelegation (the laptop's owner key and the authority's EVM key sign it)."""
        d, r = self.d, self.r
        epochs = {i: d.root_info(i).get('epoch') for i in certifying_entities(d)}
        if len(set(epochs.values())) != 1:
            raise RuntimeError(f'the committee\'s roots are at different epochs {epochs}')
        current = next(iter(epochs.values()))
        target = current + 1
        d.target = target
        d.old = d.committee_of(d.trust_base_file(current))
        d.new = sorted(set(d.old) | {self.entity})
        say(f'prepare: root epoch {current} -> {target}, committee {d.old} -> {d.new}')
        detail = d.ensure_trust_base()
        shard_epoch = d.successor_shard_epoch()
        tb = d.work / f'trust-base-epoch{target}.json'
        r.put({f'handoff/{tb.name}': tb})
        say(f'  trust base {detail}; the joiner\'s authority starts at root epoch {target}, shard epoch {shard_epoch}')
        r.start_authority(target, shard_epoch)
        out = r.tx('admit', id=ident)
        say(f'  admitDelegation: {out.get("tail", "")[-200:]}')
        d.wait('the joiner is in the live index', lambda: d.view_text(d.election, 'isIndexed(uint64)(bool)', str(ident)).strip() == 'true', 120)
        self.save(state='prepared', preparedFor=target, shardEpoch=shard_epoch, preparedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        rounds, seconds = self.due()
        say(f'prepared for epoch {target}: the next attempt is due in {rounds} rounds / {seconds} s')


def certifying_entities(d):
    """The host entities whose roots certify now (every host entity; a remote entity once it is a member)."""
    return sorted([i for i in d.transport.docker.entities] + [i for i, r in d.remote.items() if r.state == 'member'])


def retire_plan(generation, entity):
    """The retirement of the laptop entity, as steps; nothing is run (never rehearsed on the package: the drive refuses a retirement by default)."""
    info = load(generation)[entity].info
    ident = info.get('stakingId')
    return [
        f'1. laptop: remote_joiner.py retire --confirm: the owner ({info["accounts"]["owner"]}) calls custody.requestRetirement({ident}) (its key is on the laptop)',
        '2. the roots import the Retirement control (kind-5 record) by themselves; check custody.positions(id).retirementRequested and recordCursor == recordCount',
        f'3. the next election result excludes custody id {ident}: frozenMembers shows the four genesis identities',
        f'4. host: handoff_drive.py <gen> <result> --allow-unrehearsed-retirement: the trust base and the proofs are made by the ELECTED entities only; '
        f'the install barrier still restarts every root of the committee being left, root{entity} on the laptop included (this transport), and the leaver gets no advance',
        '5. after holdRetirement (2000 rounds) and timeFloor (3600 s): anyone calls custody.mature([lot]); the withdrawal address (its key is on the laptop) calls claim(amount, to)',
        f'6. only once every root certifies the new epoch without root{entity}: stop the laptop services (remote_joiner.py stop), then the tunnel; the host relay may stay',
    ]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='action', required=True)
    for name in ('relay-up', 'relay-status', 'register', 'status', 'join', 'retire-plan'):
        s = sub.add_parser(name)
        s.add_argument('generation', type=Path)
        if name != 'relay-status':
            s.add_argument('--entity', type=int, required=True)
        if name in ('relay-up', 'register'):
            s.add_argument('--sock-dir', type=Path, required=True)
        if name == 'relay-up':
            s.add_argument('--script', type=Path, default=Path(__file__).resolve().parent / 'tunnel_relay.py')
            s.add_argument('--uid', type=int, default=int(os.environ.get('SUDO_UID', os.getuid())))
        if name == 'join':
            s.add_argument('--ubft', type=Path, required=True)
            s.add_argument('--restore-pin', type=Path, required=True)
            s.add_argument('--cast', default='cast')
            s.add_argument('--dry-run', action='store_true')
            s.add_argument('--stop-after', choices=('bonded',), help='fund, register and bond only (ahead of the audience: the timed part is the rest)')
    a = p.parse_args(argv)
    if a.action == 'relay-up':
        print(json.dumps(relay_up(a.generation, a.entity, a.sock_dir, a.script, a.uid), indent=1))
    elif a.action == 'relay-status':
        name = relay_name(a.generation)
        print(docker('inspect', '--format', '{{.State.Status}} {{.State.StartedAt}}', name, check=False).stdout.strip() or f'{name}: absent')
        print(docker('logs', '--tail', '5', name, check=False).stdout.strip())
    elif a.action == 'register':
        print(json.dumps(register(a.generation.resolve(), a.entity, a.sock_dir, json.load(sys.stdin)), indent=1, sort_keys=True))
    elif a.action == 'status':
        r = load(a.generation)[a.entity]
        print(json.dumps({'state': r.state, 'stakingId': r.info.get('stakingId'), 'laptop': r.status()}, indent=1, sort_keys=True))
    elif a.action == 'retire-plan':
        print('\n'.join(retire_plan(a.generation, a.entity)))
    elif a.action == 'join':
        if os.geteuid() != 0:
            p.error('run as root (the generation directory is uid 10001, mode 0700)')
        try:
            return Join(a.generation, a.entity, a.ubft, a.restore_pin, a.cast, a.dry_run, stop_after=a.stop_after).run()
        except Exception as error:
            say(f'STOPPED: {error}')
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
