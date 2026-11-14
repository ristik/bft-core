"""Unit tests of the remote joiner (remote_entity.py, remote_joiner.py, tunnel_relay.py, evm_keys.py, handoff_drive's guard): the forwards, the laptop's compose
file, the trust-base signature check, the agent protocol over a real Unix socket, the forwarder carrying bytes, the drive refusing a result that leaves a
prepared remote joiner out. No Docker, no network."""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
import unittest.mock

import evm_keys
import handoff_drive as hd
import remote_entity as re_
import remote_joiner as rj
import tunnel_relay


def genesis_compose():
    """A four-entity compose file shaped like generate.py's: the parts joiner.joiner_services and laptop_compose read."""
    roots = {i: f'16Uiu2ROOT{i}' for i in range(1, 5)}
    evms = {i: f'16Uiu2EVM{i}' for i in range(1, 5)}
    services = {'rpc': {'image': 'sha256:rpc', 'entrypoint': ['python3', '-u', 'gateway.py']}}
    for i in range(1, 5):
        others = [j for j in range(1, 5) if j != i]
        services[f'pod{i}'] = {'image': 'sha256:node', 'entrypoint': ['sleep', 'infinity'], 'volumes': [],
                               'networks': {'validators': {'aliases': [f'root{i}', f'shard{i}']}}}
        services[f'root{i}'] = {'image': 'sha256:node', 'network_mode': f'service:pod{i}',
                                'entrypoint': ['ubft', 'root-node', 'run', '--home', '/state', '--address', '/ip4/0.0.0.0/tcp/8000', '--bootnodes',
                                               ','.join(f'/dns4/root{j}/tcp/8000/p2p/{roots[j]}' for j in others), '--pos-evm-rpc', f'http://ureth{i}:8545',
                                               '--rpc-server-address', '127.0.0.1:8002', '--trust-base', '/network/trust-base.json'],
                                'volumes': [f'./validator{i}/root:/state', './network:/network:ro', f'./validator{i}/jwt:/jwt:ro']}
        services[f'shard{i}'] = {'image': 'sha256:node', 'network_mode': f'service:pod{i}',
                                 'entrypoint': ['ubft', 'shard-node', 'run', '--home', '/state', '--address', '/ip4/0.0.0.0/tcp/9000', '--bootnodes',
                                                ','.join([f'/dns4/root{j}/tcp/8000/p2p/{roots[j]}' for j in range(1, 5)] + [f'/dns4/shard{j}/tcp/9000/p2p/{evms[j]}' for j in others]),
                                                '--engine-url', f'http://ureth{i}:8551', '--rpc-server-address', '127.0.0.1:9101'],
                                 'volumes': [f'./validator{i}/evm:/state', f'./validator{i}/auth:/authority', './network:/network:ro', f'./validator{i}/jwt:/jwt:ro',
                                             f'./validator{i}/archive:/archive']}
        services[f'authority{i}'] = {'image': 'sha256:node', 'networks': ['validators'], 'restart': 'no',
                                     'entrypoint': ['ubft', 'signing-authority', 'run', '--authority-id', f'paired-evm-{i}', '--node-id', evms[i], '--shard-epoch', '0',
                                                    '--root-epoch', '1', '--trust-base', '/network/trust-base.json'],
                                     'volumes': [f'./validator{i}/auth:/authority', './network:/network:ro']}
        services[f'ureth{i}'] = {'image': 'sha256:node', 'networks': ['validators'], 'entrypoint': ['unicity-reth', 'node'],
                                 'volumes': [f'./validator{i}/ureth:/state', f'./validator{i}/jwt:/jwt:ro', './network:/network:ro']}
        services[f'metrics{i}'] = {'image': 'sha256:rpc', 'network_mode': f'service:pod{i}', 'entrypoint': ['python3', 'metrics_relay.py'], 'volumes': []}
    return {'name': 'tn-test', 'services': services}


class Keys(unittest.TestCase):
    def test_keccak_and_addresses_match_known_vectors(self):
        self.assertEqual(evm_keys.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(evm_keys.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertEqual(evm_keys.address('0x' + '00' * 31 + '01'), '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
        self.assertEqual(evm_keys.address('0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'), '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23')

    def test_wallet_and_identity_files_are_private_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            first = evm_keys.wallet(d)
            self.assertEqual(evm_keys.wallet(d), first, 'a rerun keeps the keys')
            for name in ('owner', 'withdrawal', 'payee'):
                self.assertEqual(os.stat(Path(d) / f'{name}.key').st_mode & 0o777, 0o600)
            root = Path(d) / 'keys.json'
            root.write_text(json.dumps({'sigKey': {'privateKey': '0x' + '11' * 32}}))
            public = evm_keys.identity(d, root, Path(d) / 'id.json', 'R', 'E', throwaway_evm=True)
            body = json.loads((Path(d) / 'id.json').read_text())
            self.assertEqual(os.stat(Path(d) / 'id.json').st_mode & 0o777, 0o600)
            self.assertEqual(public['owner'], first['owner'])
            self.assertEqual((body['rootNodeId'], body['evmNodeId'], body['payee']), ('R', 'E', first['payee']))
            self.assertIn('evmKey', body, 'register and bond get a throwaway EVM key')
            evm_keys.identity(d, root, Path(d) / 'id.json', 'R', 'E')
            self.assertNotIn('evmKey', json.loads((Path(d) / 'id.json').read_text()), 'admit: the authority holds the EVM key')


class Forwards(unittest.TestCase):
    def test_every_peer_port_has_one_forward_each_way(self):
        relay = re_.relay_forwards(5)
        self.assertIn('tcp:8000=unix:/sock/root5.sock', relay)
        self.assertIn('tcp:9000=unix:/sock/shard5.sock', relay)
        for i in range(1, 5):
            self.assertIn(f'unix:/sock/root{i}.sock=tcp:root{i}:8000', relay)
            self.assertIn(f'unix:/sock/shard{i}.sock=tcp:shard{i}:9000', relay)
        ssh = re_.ssh_forwards(5, '/s')
        self.assertEqual(ssh.count('-L'), 12, '4 roots, 4 shards, 4 execution clients')
        self.assertEqual(ssh.count('-R'), 3, 'root, shard node, agent')
        self.assertIn('127.0.0.1:18003:/s/root3.sock', ssh)
        self.assertIn('/s/agent.sock:127.0.0.1:28700', ssh)
        self.assertTrue(all(x.startswith('127.0.0.1:') for x, f in zip(ssh[1::2], ssh[::2]) if f == '-L'), 'every -L binds the Mac\'s loopback')

    def test_relay_arguments_parse(self):
        self.assertEqual(tunnel_relay.parse_forward('tcp:8000=unix:/sock/a.sock'), (('tcp', '0.0.0.0', 8000), ('unix', '/sock/a.sock')))
        self.assertEqual(tunnel_relay.parse_forward('unix:/s=tcp:root1:8000'), (('unix', '/s'), ('tcp', 'root1', 8000)))
        for bad in ('tcp:x=unix:/a', 'unix:rel=tcp:a:1', 'tcp:1'):
            with self.assertRaises(Exception):
                tunnel_relay.parse_forward(bad)

    def test_the_forwarder_carries_bytes_both_ways_from_tcp_to_a_unix_socket(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, 'echo.sock')

            async def scenario():
                async def echo(reader, writer):
                    writer.write(b'echo:' + await reader.read(100))
                    await writer.drain()
                    writer.close()
                server = await asyncio.start_unix_server(echo, target)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                forward = tunnel_relay.Forward(('tcp', '127.0.0.1', port), ('unix', target))
                listener = await forward.start()
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                writer.write(b'hello')
                await writer.drain()
                got = await asyncio.wait_for(reader.read(100), 5)
                writer.close()
                listener.close()
                server.close()
                return got, forward.total
            got, total = asyncio.run(scenario())
            self.assertEqual(got, b'echo:hello')
            self.assertEqual(total, 1)


class LaptopCompose(unittest.TestCase):
    def setUp(self):
        self.out = rj.laptop_compose(genesis_compose(), 5, '16Uiu2ROOT5', '16Uiu2EVM5', 'tn-test-joiner5')

    def test_the_entity_is_the_hosts_joiner_made_laptop_local(self):
        s = self.out['services']
        self.assertEqual(sorted(s), ['authority5', 'peer1', 'peer2', 'peer3', 'peer4', 'pod5', 'root5', 'shard5', 'ureth5'])
        self.assertEqual(s['pod5']['ports'], ['127.0.0.1:28000:8000', '127.0.0.1:29000:9000'], 'published on the VM host\'s loopback only')
        self.assertEqual(s['root5']['volumes'], ['root:/state', 'network:/network:ro', 'jwt:/jwt:ro'])
        root = s['root5']['entrypoint']
        self.assertEqual(root[root.index('--announce-addresses') + 1], '/dns4/root5/tcp/8000', 'the host relay\'s alias')
        shard = s['shard5']['entrypoint']
        self.assertEqual(shard[shard.index('--announce-addresses') + 1], '/dns4/shard5/tcp/9000')
        self.assertIn('/dns4/root5/tcp/8000/p2p/16Uiu2ROOT5', shard[shard.index('--bootnodes') + 1])
        self.assertIn('http://ureth5:8545', root)
        auth = s['authority5']['entrypoint']
        self.assertEqual(auth[auth.index('--node-id') + 1], '16Uiu2EVM5')
        self.assertEqual(s['authority5']['restart'], 'no', 'a restarted authority is a new EVM key')
        self.assertTrue(all(v['external'] for v in self.out['volumes'].values()))
        self.assertEqual(self.out['volumes']['root']['name'], 'tn-test-joiner5_root')

    def test_peer_stubs_forward_to_the_ssh_listeners(self):
        peer = self.out['services']['peer3']
        self.assertEqual(peer['networks']['validators']['aliases'], ['root3', 'shard3', 'ureth3'])
        self.assertIn('tcp:8000=tcp:host.docker.internal:18003', peer['entrypoint'])
        self.assertIn('tcp:9000=tcp:host.docker.internal:19003', peer['entrypoint'])
        self.assertIn('tcp:8545=tcp:host.docker.internal:18543', peer['entrypoint'])

    def test_scope_and_restore_entries(self):
        compose = rj.set_scope(json.loads(json.dumps(self.out)), 5, 5, 4)
        auth = compose['services']['authority5']['entrypoint']
        self.assertEqual([auth[auth.index(f) + 1] for f in ('--root-epoch', '--shard-epoch', '--trust-base')], ['5', '4', '/network/handoff/trust-base-epoch5.json'])
        entry = rj.restore_entry(self.out['services']['shard5']['entrypoint'], '0xab')
        self.assertEqual(entry[2], 'restore')
        self.assertEqual(entry[-2:], ['--trust-body-id', '0xab'])

    def test_only_known_mounts_are_mapped(self):
        self.assertEqual(rj.volume_mount('./validator5/archive:/archive', 5), 'archive:/archive')
        with self.assertRaises(ValueError):
            rj.volume_mount('/etc:/etc', 5)
        with self.assertRaises(ValueError):
            rj.volume_mount('./validator4/root:/state', 5)


class TrustBaseCheck(unittest.TestCase):
    sent = {'epoch': 4, 'rootNodes': [{'nodeId': 'A'}, {'nodeId': 'J'}], 'signatures': {'A': '0x01'}}

    def test_exactly_the_joiners_signature_is_added(self):
        ok = dict(self.sent, signatures={'A': '0x01', 'J': '0x02'})
        self.assertEqual(re_.check_signed(self.sent, ok, 'J'), ok)
        for bad in (dict(ok, epoch=5), dict(ok, signatures={'A': '0x09', 'J': '0x02'}), dict(ok, signatures={'A': '0x01', 'X': '0x02'}),
                    dict(ok, signatures={'A': '0x01'})):
            with self.assertRaises(re_.AgentError):
                re_.check_signed(self.sent, bad, 'J')


class Registry(unittest.TestCase):
    def test_register_load_and_map(self):
        with tempfile.TemporaryDirectory() as d:
            gen = Path(d)
            (gen / 'handoff').mkdir()
            public = {'rootNodeId': 'R5', 'evmNodeId': 'E5', 'nodeInfo': {'nodeId': 'R5', 'sigKey': '0x02', 'stake': 1}, 'accounts': {'owner': '0x1'}, 'token': 't'}
            shown = re_.register(gen, 5, '/s', public)
            self.assertNotIn('token', shown)
            self.assertEqual(os.stat(gen / 'handoff' / 'remote-joiners' / '5.json').st_mode & 0o777, 0o600)
            loaded = re_.load(gen)
            self.assertEqual(list(loaded), [5], 'the node-info file beside it is not an entity')
            self.assertEqual((loaded[5].root_node_id, loaded[5].state, loaded[5].client.sock), ('R5', 'follower', '/s/agent.sock'),
                             'a registered laptop is a follower until its join starts')
            import handoff_auto
            self.assertNotIn('follower', handoff_auto.JOINING, 'the unattended timer keeps driving while the laptop only follows')
            with self.assertRaises(ValueError):
                re_.register(gen, 5, '/s', dict(public, rootNodeId='OTHER', nodeInfo={'nodeId': 'OTHER'}))
            with self.assertRaises(ValueError):
                re_.register(gen, 6, '/s', dict(public, nodeInfo={'nodeId': 'R5', 'privateKey': '0x1'}))
            re_.map_joiner(gen, 7, 5)
            self.assertEqual(json.loads((gen / 'handoff' / 'joiners.json').read_text()), {'7': 5})


class Agent(unittest.TestCase):
    """The agent's HTTP protocol over a real Unix socket (the host side's client), with a fake laptop behind it."""

    def test_ops_round_trip_and_the_token_is_required(self):
        class FakeLaptop:
            home = None
            state = {'sockDir': '/s'}

            def dispatch(self, name, args):
                if name == 'boom':
                    raise RuntimeError('refused there')
                return {'name': name, 'args': args}

        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / 'agent.token').write_text('secret-token')
            lap = FakeLaptop()
            lap.home = home
            import http.server
            servers = []
            original = http.server.ThreadingHTTPServer

            class Capture(original):
                def __init__(self, address, handler):
                    super().__init__(('127.0.0.1', 0), handler)
                    servers.append(self)
            http.server.ThreadingHTTPServer = Capture
            try:
                thread = threading.Thread(target=rj.serve_agent, args=(lap,), daemon=True)
                thread.start()
                while not servers:
                    pass
            finally:
                http.server.ThreadingHTTPServer = original
            port = servers[0].server_address[1]
            sock = home / 'agent.sock'
            unix = socket.socket(socket.AF_UNIX)
            unix.bind(str(sock))
            unix.listen(4)

            def bridge():   # what ssh -R does: the Unix socket on the host to the agent's TCP port on the laptop
                while True:
                    a, _ = unix.accept()
                    b = socket.create_connection(('127.0.0.1', port))
                    for x, y in ((a, b), (b, a)):
                        threading.Thread(target=lambda x=x, y=y: [y.sendall(c) for c in iter(lambda: x.recv(65536), b'')] and None, daemon=True).start()
            threading.Thread(target=bridge, daemon=True).start()
            client = re_.AgentClient(sock, 'secret-token')
            self.assertEqual(client.op('status', x=1), {'name': 'status', 'args': {'x': 1}})
            with self.assertRaises(re_.AgentError) as refused:
                client.op('boom')
            self.assertIn('refused there', str(refused.exception))
            with self.assertRaises(re_.AgentError):
                re_.AgentClient(sock, 'wrong').op('status')
            with self.assertRaises(re_.AgentError):
                re_.AgentClient(home / 'absent.sock', 't').op('status')
            servers[0].shutdown()


class DriveGuard(unittest.TestCase):
    """handoff_drive.Drive.plan refuses a result that leaves out a prepared remote joiner, or an entity --require-member names."""

    def drive(self, state, require=(), allow=False):
        d = hd.Drive.__new__(hd.Drive)

        class Remote:
            def __init__(self):
                self.state, self.root_node_id = state, 'R5'
        d.remote = {5: Remote()}
        d.require, d.allow_excluding = set(require), allow
        d.n = 5
        d.joiner_map = {'5': 5}
        d.election = '0xelection'
        d.net = Path(tempfile.mkdtemp())
        d.gen = d.net
        write_record(d.gen, 5, state)   # the guard reads the registry, not the drive's copy
        (d.net / 'pos-plan.json').write_text(json.dumps({'identities': [{'stakingId': k} for k in range(1, 5)]}))
        d.running = lambda: {f'root{i}' for i in range(1, 6)}
        d.root_info = lambda i: {'epoch': 3 if i < 5 else 1}
        d.open_result = lambda: '0xres'
        d.trust_base_file = lambda e: Path(__file__)
        d.committee_of = lambda tb: [1, 2, 3, 4]
        d.view_text = lambda *a: '[(1, 1, 0, 1, 0xab), (2, 1, 0, 1, 0xab), (3, 1, 0, 1, 0xab), (4, 1, 0, 1, 0xab)]'
        d.say = lambda text: None
        return d.plan(None, hd.Journal(d.net / 'log.jsonl'))

    def test_a_prepared_joiner_left_out_is_refused(self):
        with self.assertRaises(hd.Refused) as refused:
            self.drive('prepared')
        self.assertIn('leaves out entity [5]', str(refused.exception))

    def test_the_follower_root_does_not_count_as_an_epoch(self):
        info = self.drive('bonded')
        self.assertEqual((info['kind'], info['target']), ('no-change', 4), 'the laptop follower (epoch 1) is not one of the committee\'s roots')

    def test_require_member_and_the_override(self):
        with self.assertRaises(hd.Refused):
            self.drive('bonded', require=[5])
        self.assertEqual(self.drive('prepared', allow=True)['kind'], 'no-change')


class RemoteAdvance(unittest.TestCase):
    """handoff_drive.advance_remote: the laptop's switch as the same resumable sub-steps, status first."""

    def setUp(self):
        self.calls = []
        test = self

        class Remote:
            status = {'rootEpoch': 4, 'shardEpoch': 3, 'enrollmentComplete': True, 'generation': 1}

            def put(self, files):
                test.calls.append(('put', sorted(files)))

            def authority_status(self):
                return dict(self.status)

            def authority_step(self, step, target, shard_epoch):
                test.calls.append((step, target, shard_epoch))
                if step == 'advance-epoch':
                    self.status.update(rootEpoch=target, shardEpoch=shard_epoch)
                return {'step': step}
        self.remote = Remote()
        d = hd.Drive.__new__(hd.Drive)
        d.remote, d.target, d.joiners = {5: self.remote}, 5, set()
        d.work = Path(tempfile.mkdtemp())
        d.say = lambda text: None
        d.expect = lambda ok, what, detail='': None if ok else (_ for _ in ()).throw(AssertionError(what))
        d.restore_remote = lambda i: test.calls.append(('restore', i))
        d.follow_joiner = lambda i, epoch, promoted: test.calls.append(('follow', i))
        d.cold_restore = False
        self.d = d
        self.journal = hd.Journal(d.work / 'log.jsonl', echo=lambda line: None)

    def steps(self):
        return [c[0] for c in self.calls if c[0] != 'put']

    def test_an_incumbent_advances_once_and_a_rerun_sends_nothing_again(self):
        self.journal.run('advance', lambda: self.d.advance_entity(5, 4, self.journal), sub='entity5')
        self.assertEqual(self.steps(), ['advance-epoch', 'replace-session', 'shard-start'])
        self.calls.clear()
        self.d.advance_remote(5, 4, self.journal)
        self.assertEqual(self.steps(), [], 'every sub-step is in the journal')

    def test_an_advance_the_journal_missed_is_read_from_the_laptops_status(self):
        self.remote.status.update(rootEpoch=5, shardEpoch=4)
        self.d.advance_remote(5, 4, self.journal)
        self.assertEqual(self.steps(), ['replace-session', 'shard-start'])

    def test_a_joiner_enrolls_takes_its_session_and_follows_without_a_restore(self):
        self.d.joiners = {5}
        self.remote.status.update(enrollmentComplete=False, shardEpoch=4, rootEpoch=5)
        self.d.advance_remote(5, 4, self.journal)
        self.assertEqual(self.steps(), ['complete-enrollment', 'replace-session', 'follow'])

    def test_the_cold_restore_is_only_the_explicit_operation(self):
        self.d.joiners, self.d.cold_restore = {5}, True
        self.remote.status.update(enrollmentComplete=False, shardEpoch=4, rootEpoch=5)
        self.d.advance_remote(5, 4, self.journal)
        self.assertEqual(self.steps(), ['complete-enrollment', 'replace-session', 'restore'])


    def test_a_key_lost_on_the_laptop_stops_the_drive(self):
        self.remote.status.update(keyLost=True)
        with self.assertRaises(hd.Refused):
            self.d.advance_remote(5, 4, self.journal)
        self.assertEqual(self.steps(), [])


EXPECT = {'nodeId': '16Uiu2JOINER', 'bodyId': 'b5', 'sigKey': '0x02aa'}


def incumbent_binding(**over):
    return {'nodeId': '16Uiu2EVM1', 'sigKey': '02bb', 'networkId': 5, 'partitionId': 8, 'shardId': '', 'shardEpoch': 4, 'shardConfHash': 'c4',
            'member': True, 'history': [{'epoch': e, 'bodyId': f'b{e}'} for e in range(1, 6)], **over}


def joiner_binding(**over):
    return {**incumbent_binding(), 'nodeId': '16Uiu2JOINER', 'sigKey': '02aa', **over}


class FollowJoiner(unittest.TestCase):
    """handoff_drive.follow_joiner: the idempotent replacement of the post-election restore: start the retained follower, wait until the node
    itself reports an active role and a certified round at the head."""

    def drive(self, running, reports):
        calls, test = [], self

        class Remote:
            def running(self):
                return set(running)

            def authority_step(self, step, target, shard_epoch):
                calls.append(step)
                running.add('shard5')

            def status(self):
                report = reports.pop(0) if len(reports) > 1 else reports[0]
                return {'shardHealth': report and {'binding': joiner_binding(), **report}}   # about the expected node (#1057)

            def restore_start(self, *a):
                test.fail('the follower path must never empty or restore')

        class Docker:
            def shard_health(self, i):
                return {'role': 'active', 'roleEpoch': 5, 'lastUCRound': 100, 'executionRecovery': 'ready', 'binding': incumbent_binding()}
        d = hd.Drive.__new__(hd.Drive)
        d.remote, d.target, d.docker = {5: Remote()}, 5, Docker()
        d.binding_expectation = lambda i, epoch, promoted, reference: dict(EXPECT)
        d.say = lambda text: None
        d.wait = lambda what, fn, seconds: next(r for r in iter(fn, None) if r)
        return d, calls

    def test_a_stopped_follower_is_started_on_its_state_and_awaited(self):
        follower = {'role': 'follower', 'roleEpoch': 4, 'lastUCRound': 99, 'executionRecovery': 'ready'}
        ready = {'role': 'active', 'roleEpoch': 5, 'lastUCRound': 99, 'executionRecovery': 'ready'}
        d, calls = self.drive(set(), [None, follower, ready])
        d.follow_joiner(5, 5, promoted=True)
        self.assertEqual(calls, ['shard-start'])

    def test_a_running_follower_is_left_alone(self):
        d, calls = self.drive({'shard5'}, [{'role': 'active', 'roleEpoch': 5, 'lastUCRound': 100, 'executionRecovery': 'ready'}])
        d.follow_joiner(5, 5, promoted=True)
        self.assertEqual(calls, [], 'a rerun changes nothing')

    def test_readiness_is_the_nodes_own_role_and_certified_round(self):
        ref = {'lastUCRound': 100}
        active = {'role': 'active', 'roleEpoch': 5, 'lastUCRound': 99, 'executionRecovery': 'ready'}
        self.assertTrue(hd.follower_ready(active, ref, 5, promoted=True))
        self.assertFalse(hd.follower_ready({**active, 'role': 'follower'}, ref, 5, promoted=True), 'not promoted')
        self.assertFalse(hd.follower_ready({**active, 'roleEpoch': 4}, ref, 5, promoted=True), 'promoted for an older epoch')
        self.assertFalse(hd.follower_ready({**active, 'lastUCRound': 90}, ref, 5, promoted=True), 'certified rounds behind')
        self.assertFalse(hd.follower_ready({**active, 'lastUCRound': 150}, ref, 5, promoted=True), 'ahead of the incumbent: divergent, not ready')
        for recovery in ('unready', '', None):
            self.assertFalse(hd.follower_ready({**active, 'executionRecovery': recovery}, ref, 5, promoted=True), f'recovery {recovery!r} is not ready')
        self.assertFalse(hd.follower_ready({k: v for k, v in active.items() if k != 'executionRecovery'}, ref, 5, promoted=True), 'missing recovery')

    def test_before_the_election_a_caught_up_follower_is_ready(self):
        """The pre-election check must not wait for an activation that only the election it precedes can bring."""
        ref = {'lastUCRound': 100}
        follower = {'role': 'follower', 'roleEpoch': 3, 'lastUCRound': 100, 'executionRecovery': 'ready'}
        self.assertTrue(hd.follower_ready(follower, ref, 3, promoted=False), 'caught up in the current epoch as a follower')
        self.assertFalse(hd.follower_ready({**follower, 'roleEpoch': 2}, ref, 3, promoted=False), 'the current epoch is not installed yet')
        self.assertFalse(hd.follower_ready({**follower, 'lastUCRound': 80}, ref, 3, promoted=False), 'behind the incumbents')
        self.assertFalse(hd.follower_ready({**follower, 'executionRecovery': ''}, ref, 3, promoted=False))
        self.assertFalse(hd.follower_ready(follower, ref, 4, promoted=True), 'the same report is not a promotion to epoch 4')

    def test_the_pre_election_catch_up_waits_for_following_not_promotion(self):
        calls = []
        d = hd.Drive.__new__(hd.Drive)
        d.target, d.cold_restore, d.say = 4, False, lambda text: None
        d.follower_epoch = lambda i: 3

        class Remote:
            info = {}

            def save(self):
                pass
        d.remote = {5: Remote()}
        d.follow_joiner = lambda i, epoch, promoted: calls.append((i, epoch, promoted))
        d.catch_up_remote(5)
        self.assertEqual(calls, [(5, 3, False)])


class SourceCheck(unittest.TestCase):
    """The host runs the laptop-copied deploy/testnet with sudo: a copy is run only when it is the recorded clean commit and the laptop's own checkout."""

    def deployed(self, d, **record):
        (Path(d) / 'a.py').write_text('x = 1\n')
        digest = re_.tree_digest(d)
        (Path(d) / 'SOURCE.json').write_text(json.dumps(dict({'commit': 'abc', 'dirty': False, 'digest': digest}, **record)))
        return digest

    def test_the_recorded_clean_copy_runs(self):
        with tempfile.TemporaryDirectory() as d:
            digest = self.deployed(d)
            self.assertIsNone(re_.source_check(d, digest, False))
            self.assertEqual(re_.tree_digest(d), digest, 'SOURCE.json itself is not part of the digest')
            (Path(d) / '._a.py').write_bytes(b'appledouble')
            self.assertEqual(re_.tree_digest(d), digest, 'macOS tar\'s AppleDouble ._*.py files are not part of the digest')

    def test_dirty_edited_mismatched_or_unrecorded_copies_are_refused_unless_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            digest = self.deployed(d, dirty=True)
            self.assertIn('dirty', re_.source_check(d, digest, False))
            self.assertIsNone(re_.source_check(d, digest, True))
        with tempfile.TemporaryDirectory() as d:
            digest = self.deployed(d)
            self.assertIn('laptop', re_.source_check(d, 'f' * 64, False), 'the laptop checkout is another tree')
            (Path(d) / 'a.py').write_text('x = 2\n')
            self.assertIn('not the copy recorded', re_.source_check(d, digest, False), 'edited on the host after the deploy')
            (Path(d) / 'SOURCE.json').unlink()
            self.assertIn('missing', re_.source_check(d, None, False))
            self.assertIsNone(re_.source_check(d, None, True))

    def test_the_laptop_states_its_commit_and_cleanliness(self):
        version = rj.source_version()
        self.assertEqual(set(version), {'commit', 'dirty', 'digest'})
        self.assertEqual(version['digest'], re_.tree_digest(rj.HERE))
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'a.py').write_text('x\n')
            outside = rj.source_version(Path(d))
            self.assertTrue(outside['dirty'] and outside['commit'] is None, 'no git checkout: treated as dirty')



class JoinAndTimer(unittest.TestCase):
    """#1025 review: the join's drives wait for a timer pass holding handoff/drive.lock (exit 5) instead of stopping, for a bounded time, and --funder reaches
    the funding and the child drives."""
    def join(self, funder=None, busy_wait=30):
        j = re_.Join.__new__(re_.Join)
        j.gen, j.ubft, j.restore_pin, j.cast, j.here = Path('/g'), Path('/u'), None, 'cast', Path('/pkg')
        j.funder, j.busy_wait = (Path(funder) if funder else None), busy_wait
        return j

    def test_a_busy_drive_is_retried_then_runs(self):
        j = self.join(funder='/srv/ops')
        codes = iter([5, 5, 0])
        with unittest.mock.patch.object(re_.subprocess, 'run', side_effect=lambda cmd: unittest.mock.Mock(returncode=next(codes))) as run, \
                unittest.mock.patch.object(re_.time, 'sleep') as sleep, unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.drive('0xr', '--require-member', '5'), 0)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index('--funder') + 1], '/srv/ops', 'the drive pays gas from the operator account too')
        self.assertIn('--require-member', cmd)

    def test_a_busy_wait_is_bounded(self):
        j = self.join(busy_wait=0)
        with unittest.mock.patch.object(re_.subprocess, 'run', return_value=unittest.mock.Mock(returncode=5)) as run, \
                unittest.mock.patch.object(re_.time, 'sleep'), unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.drive(None), 5)
        self.assertEqual(run.call_count, 1)

    def test_other_failures_are_not_retried(self):
        j = self.join()
        with unittest.mock.patch.object(re_.subprocess, 'run', return_value=unittest.mock.Mock(returncode=1)) as run, unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.drive(None), 1)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('--funder', run.call_args.args[0], 'no funder: the faucet account, as before')

    def test_the_laptop_passes_the_funder_to_the_host(self):
        lap = unittest.mock.Mock(entity=5, state={'hostCast': '/h/cast', 'hostDir': '/h/rjoin', 'hostGeneration': '/srv/tn-x', 'hostUbft': '/h/ubft',
                                                  'hostRestorePin': '/h/pin', 'host': 'h'})
        with unittest.mock.patch.object(rj, 'source_version', return_value={'dirty': False, 'commit': 'c', 'digest': 'd' * 64}), \
                unittest.mock.patch.object(rj.subprocess, 'run', return_value=unittest.mock.Mock(returncode=0)) as run, unittest.mock.patch.object(rj, 'say'):
            rj.join(lap, funder='/srv/tn-x/operator-secrets')
        self.assertIn('--funder /srv/tn-x/operator-secrets', run.call_args.args[0][-1])


def write_record(gen, entity, state, **extra):
    """A registry record as register() leaves it, written directly (a test fixture, not a registry write)."""
    d = re_.info_dir(gen)
    d.mkdir(parents=True, exist_ok=True)
    (d / f'{entity}.json').write_text(json.dumps({'entity': entity, 'state': state, 'rootNodeId': f'R{entity}', 'evmNodeId': f'E{entity}',
                                                  'agentSocket': '/s/agent.sock', 'token': 't', 'accounts': {}, **extra}))


class LinuxHostAndSubnet(unittest.TestCase):
    """#1043: on a Linux docker host the tunnel's -L listeners bind the --mac-host bridge gateway (a container cannot reach the host's loopback); the
    laptop's validators subnet follows the project name (two generations' joiner projects side by side)."""

    def test_the_listeners_bind_an_ip_mac_host_else_loopback(self):
        self.assertEqual(rj.forward_bind('172.17.0.1'), '172.17.0.1')
        self.assertEqual(rj.forward_bind('host.docker.internal'), '127.0.0.1')
        cmd = rj.tunnel_command('h', 5, '/s', '172.17.0.1')
        listeners = [cmd[k + 1] for k, a in enumerate(cmd) if a == '-L']
        self.assertTrue(listeners and all(x.startswith('172.17.0.1:') for x in listeners))
        remote = [cmd[k + 1] for k, a in enumerate(cmd) if a == '-R']
        self.assertTrue(all(':127.0.0.1:' in x for x in remote), 'the -R targets stay the laptop\'s loopback')

    def test_the_subnet_is_per_project_and_never_a_host_network(self):
        a, b = rj.subnet('tn-a-joiner5'), rj.subnet('tn-b-joiner5')
        self.assertEqual(a, rj.subnet('tn-a-joiner5'))
        self.assertNotEqual(a, b)
        for net in (a, b):
            self.assertRegex(net, r'^10\.231\.\d+\.0/24$')


class ColdRestore(unittest.TestCase):
    """handoff_drive.restore_remote is only the explicit --cold-restore: a restore found running is never kept, it starts over (empties and pins)."""

    def test_a_running_restore_is_not_kept(self):
        d = hd.Drive.__new__(hd.Drive)

        class Started(Exception):
            pass

        class Remote:
            info = {'shardCaughtUp': 29}

            def status(self):
                return {'services': {'shard5': 'running'}, 'urethHead': 998, 'restoring': True}
        d.remote, d.target, d.restore_pin = {5: Remote()}, 30, Path('/bin/true')
        d.say = lambda text: None
        d.expect = lambda ok, what, detail='': None if ok else (_ for _ in ()).throw(AssertionError(what))
        d.ureth = lambda i, method: hex(1000)

        def restore_body_ids():
            raise Started()
        d.restore_body_ids = restore_body_ids
        for follow in (True, False):
            with self.assertRaises(Started, msg=f'follow={follow}: the full cold restore, whatever restore runs already'):
                d.restore_remote(5, follow=follow)


class RegistryWrites(unittest.TestCase):
    """The registry of remote entities (handoff/remote-joiners/<J>.json): every write under handoff/drive.lock, over the CURRENT file, only legal and
    not stale state changes, written to a unique temporary file, fsynced and renamed (#1029 review)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gen = Path(self.tmp.name)
        (self.gen / 'handoff').mkdir()
        write_record(self.gen, 5, 'bonded')

    def tearDown(self):
        self.tmp.cleanup()

    def entity(self):
        return re_.load(self.gen)[5]

    def file(self):
        return json.loads((re_.info_dir(self.gen) / '5.json').read_text())

    def other_holder(self):
        """handoff/drive.lock held by another open file (another process: a drive)."""
        import fcntl
        handle = open(self.gen / 'handoff' / 'drive.lock', 'a')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return handle

    def test_a_write_waits_for_the_lock_and_writes_nothing_without_it(self):
        holder = self.other_holder()
        try:
            with self.assertRaises(re_.RegistryError):
                re_.update_info(self.gen, 5, {'stakingId': 9}, wait=0)
            with unittest.mock.patch.object(re_, 'BUSY_WAIT', 0), self.assertRaises(re_.RegistryError):
                self.entity().save()
            with unittest.mock.patch.object(re_, 'BUSY_WAIT', 0), self.assertRaises(re_.RegistryError):
                re_.register(self.gen, 5, '/s', {'rootNodeId': 'R5', 'evmNodeId': 'E5', 'nodeInfo': {'nodeId': 'R5'}, 'accounts': {}, 'token': 't'})
            with unittest.mock.patch.object(re_, 'BUSY_WAIT', 0), self.assertRaises(re_.RegistryError):
                re_.map_joiner(self.gen, 7, 5)
            with self.assertRaises(re_.RegistryError):
                re_.save_info(self.gen, {'entity': 5, 'state': 'member'})
        finally:
            holder.close()
        self.assertEqual(self.file()['state'], 'bonded')
        self.assertNotIn('stakingId', self.file())
        self.assertFalse((self.gen / 'handoff' / 'joiners.json').exists())
        re_.update_info(self.gen, 5, {'stakingId': 9}, wait=0)
        self.assertEqual(self.file()['stakingId'], 9, 'written once the lock is free')

    def test_the_holder_of_the_lock_writes_without_waiting_for_itself(self):
        lock = hd.hold_lock(self.gen)
        try:
            self.assertTrue(re_.holding(self.gen))
            re_.update_info(self.gen, 5, {'state': 'preparing'}, wait=0)
        finally:
            lock.close()
        self.assertFalse(re_.holding(self.gen))
        self.assertEqual(self.file()['state'], 'preparing')

    def test_a_stale_copy_keeps_the_other_writers_change(self):
        stale = self.entity()   # read at bonded, like a Join made before another process prepared
        re_.update_info(self.gen, 5, {'state': 'preparing', 'preparedFor': 4})
        stale.info['stakingId'] = 9
        stale.save()
        self.assertEqual((self.file()['state'], self.file()['preparedFor'], self.file()['stakingId']), ('preparing', 4, 9),
                         'only the field this writer changed is written over the current file')
        self.assertEqual(stale.state, 'preparing', 'and the writer reloads it')

    def test_a_stale_state_change_is_refused(self):
        stale = self.entity()
        re_.update_info(self.gen, 5, {'state': 'preparing'})
        stale.info['state'] = 'preparing'
        with self.assertRaises(re_.RegistryError):
            stale.save()   # it read bonded: its prepare would be a second one

    def test_no_downgrade_from_preparing_prepared_or_member(self):
        for have, want in (('preparing', 'bonded'), ('prepared', 'bonded'), ('prepared', 'preparing'), ('member', 'prepared'), ('member', 'bonded'),
                           ('retired', 'member'), ('bonded', 'prepared'), ('follower', 'member')):
            write_record(self.gen, 5, have)
            with self.assertRaises(re_.RegistryError, msg=f'{have} -> {want}'):
                re_.update_info(self.gen, 5, {'state': want}, expect_state=have)
            self.assertEqual(self.file()['state'], have)

    def test_the_legal_path_and_a_repeat(self):
        write_record(self.gen, 5, 'follower')
        for want in ('registered', 'bonded', 'preparing', 'prepared', 'member', 'member', 'retiring', 'retired'):
            r = self.entity()
            r.info['state'] = want
            r.save()
            self.assertEqual(self.file()['state'], want)

    def test_the_write_is_atomic_durable_and_private(self):
        synced = []
        real = os.fsync
        with unittest.mock.patch.object(re_.os, 'fsync', side_effect=lambda fd: (synced.append(fd), real(fd))[1]):
            re_.update_info(self.gen, 5, {'stakingId': 9})
        self.assertGreaterEqual(len(synced), 2, 'the file and its directory')
        d = re_.info_dir(self.gen)
        self.assertEqual(os.stat(d / '5.json').st_mode & 0o777, 0o600, 'it holds the agent token')
        self.assertEqual(sorted(p.name for p in d.iterdir()), ['5.json'], 'no temporary file left')
        with unittest.mock.patch.object(re_.os, 'replace', side_effect=OSError('disk full')), self.assertRaises(OSError):
            re_.update_info(self.gen, 5, {'stakingId': 10})
        self.assertEqual(self.file()['stakingId'], 9, 'a failed write leaves the record as it was')
        self.assertEqual(sorted(p.name for p in d.iterdir()), ['5.json'])
        names = set()
        real_mkstemp = tempfile.mkstemp
        with unittest.mock.patch.object(re_.tempfile, 'mkstemp', side_effect=lambda **k: (lambda r: (names.add(r[1]), r)[1])(real_mkstemp(**k))):
            re_.update_info(self.gen, 5, {'a': 1})
            re_.update_info(self.gen, 5, {'b': 2})
        self.assertEqual(len(names), 2, 'a unique temporary file per write')

    def test_an_unreadable_record_is_refused(self):
        (re_.info_dir(self.gen) / '5.json').write_text('{not json')
        with self.assertRaises(re_.RegistryError):
            re_.update_info(self.gen, 5, {'stakingId': 9})
        with self.assertRaises(re_.RegistryError):
            re_.fresh_states(self.gen)


class JoinExclusion(unittest.TestCase):
    """astra #1029 finding 2: a joiner whose authority may run at the successor scope blocks every result that leaves it out. The drive's guard reads
    the registry now, not the copy it loaded at its start, and refuses when a record cannot be read."""

    def drive(self, gen, cached):
        d = hd.Drive.__new__(hd.Drive)

        class R:
            def __init__(self, state):
                self.state = state
        d.gen, d.remote = gen, {i: R(state) for i, state in cached.items()}
        return d

    def test_preparing_and_prepared_are_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            for i, state in {5: 'preparing', 6: 'prepared', 7: 'bonded', 8: 'member', 9: 'follower'}.items():
                write_record(gen, i, state)
            self.assertEqual(self.drive(gen, {}).pending_remote(), {5, 6})
        import handoff_auto
        self.assertIn('preparing', handoff_auto.JOINING, 'the timer stands down too')
        self.assertIn('preparing', re_.STATES)

    def test_the_guard_reads_fresh_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            write_record(gen, 5, 'bonded')
            d = self.drive(gen, {5: 'bonded'})
            write_record(gen, 5, 'prepared')   # a join prepared after this drive loaded the registry
            write_record(gen, 6, 'preparing')  # and one registered after it
            self.assertEqual(d.pending_remote(), {5, 6})

    def test_an_unreadable_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            write_record(gen, 5, 'bonded')
            d = self.drive(gen, {5: 'bonded'})
            for bad in ('', '{"entity": 5', json.dumps({'entity': 6, 'state': 'bonded'}), json.dumps({'entity': 5, 'state': 'weird'})):
                (re_.info_dir(gen) / '5.json').write_text(bad)
                with self.assertRaises(hd.Refused, msg=repr(bad)):
                    d.pending_remote()


class FollowerCatchUp(unittest.TestCase):
    """remote_entity.py catch-up brings a follower's shard node to the current epoch and leaves its root to the join drive (installed after q3-candidate)."""

    def test_the_root_is_left_to_the_join_drive(self):
        calls = []
        d = hd.Drive.__new__(hd.Drive)
        d.target, d.cold_restore, d.say = 4, False, lambda text: None
        d.follower_epoch = lambda i: 1

        class Remote:
            info = {}

            def install_root(self, target):
                calls.append(('install', target))

            def save(self):
                pass
        d.remote = {5: Remote()}
        d.follow_joiner = lambda i, epoch, promoted: calls.append(('follow', i, epoch, promoted))
        d.catch_up_remote(5, root=False)
        self.assertEqual(calls, [('follow', 5, 3, False)], 'no install restart of the follower root; no log-scraped shortcut')


# archivepolicy.Select over real peer IDs, from Go (a one-off run of the archivepolicy package): [writer, validators, replicas]
SELECT_VECTORS = [
    ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe"]],
    ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N"], ["16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
    ["16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
    ["16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
    ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N"]],
    ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM"], ["16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe"]],
    ["16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
    ["16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM"], ["16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
    ["16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM", ["16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt", "16Uiu2HAkxgVhuh497qx4dk9Gvktr3YZRKpgdfQwcemu6v2GJfws5", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmFPCBNky2TuzD2QhMGQdEkYmn6Vvi6DURHLysmRir5RZM"], ["16Uiu2HAmPLKg4VDCzw7tEAgjb7bkSBHe1aKUcwsJ2iBT9g1bmq3N", "16Uiu2HAmPNTKE3UwmteT6mZHE5qkEHZzoSXt1xweTPouujgmkKYe", "16Uiu2HAmSun24qPUv5D6v9ThcBAgSRNPXrekv3sbVGRRvb47c8gt"]],
]


class ArchiveGate(unittest.TestCase):
    """The retire gate before stop-validator (#1043 review; astra, briefs/astra-q-1029-1043-answer.md Q4). A writer still on the old policy, one that
    reports other replicas than its installed assignment derives, one without checkedShardEpoch, or an unavailable report does not pass."""
    R = '16Uiu2RETIREE'
    EXPECTED = ['A', 'B', 'C']

    def policy(self, **over):
        return {'version': 7, 'shardEpoch': 6, 'checkedShardEpoch': 6, 'replicas': list(self.EXPECTED), 'retained': [], 'migrationBacklog': 0,
                'migrationComplete': True, **over}

    def gate(self, policy, activated=6, expected=EXPECTED):
        return re_.archive_gate(policy, self.R, activated, expected)

    def test_the_old_policy_does_not_pass(self):
        self.assertIsNotNone(self.gate(self.policy(shardEpoch=4, checkedShardEpoch=4, replicas=['A', self.R, 'C'])))
        self.assertIsNotNone(self.gate(self.policy(replicas=['A', self.R, 'C'])), 'the retiree still a replica at the new epoch')
        self.assertIsNotNone(self.gate(self.policy(shardEpoch=5, checkedShardEpoch=5)), 'checked before the excluding epoch')

    def test_only_the_checked_epoch_counts(self):
        """#1044: shardEpoch stays at the derivation epoch; checkedShardEpoch follows the installed assignment. No fallback: fail closed."""
        self.assertIsNone(self.gate(self.policy(shardEpoch=2, checkedShardEpoch=6)), 'a kept policy checked at the new epoch')
        legacy = {k: v for k, v in self.policy().items() if k != 'checkedShardEpoch'}
        self.assertIsNotNone(self.gate(legacy), 'a node without checkedShardEpoch: fail closed, even with shardEpoch at the new epoch')
        self.assertIsNotNone(self.gate(self.policy(checkedShardEpoch='6')))

    def test_the_replicas_must_be_the_derived_ones(self):
        self.assertIsNotNone(self.gate(self.policy(replicas=['A', 'B', 'D'])), 'equal epochs are not the right assignment')
        self.assertIsNotNone(self.gate(self.policy(), expected=None), 'not derivable: fail closed')
        self.assertIsNone(self.gate(self.policy(replicas=['C', 'A', 'B'])), 'the order does not matter')

    def test_a_retained_holder_or_an_open_migration_does_not_pass(self):
        self.assertIsNotNone(self.gate(self.policy(retained=[self.R], migrationComplete=False, migrationBacklog=3)))
        self.assertIsNotNone(self.gate(self.policy(retained=[self.R])))
        self.assertIsNotNone(self.gate(self.policy(migrationComplete=False)))
        self.assertIsNotNone(self.gate(self.policy(migrationComplete='true')))

    def test_unavailable_or_unreadable_does_not_pass(self):
        for bad in (None, {}, {'error': 'timeout'}, 'garbage'):
            self.assertIsNotNone(self.gate(bad), repr(bad))

    def test_the_new_policy_passes(self):
        self.assertIsNone(self.gate(self.policy()))
        self.assertIsNone(self.gate(self.policy(shardEpoch=7, checkedShardEpoch=7)))

    def test_select_replicas_is_archivepolicy_select(self):
        for writer, validators, replicas in SELECT_VECTORS:
            self.assertEqual(re_.select_replicas(writer, validators), replicas or None, writer)
        writer, validators, _ = SELECT_VECTORS[0]
        self.assertIsNone(re_.select_replicas(writer, [writer, next(v for v in validators if v != writer)]), 'fewer than K others')

    def test_the_expected_replicas_come_from_the_checked_epochs_configuration(self):
        writer, validators, replicas = SELECT_VECTORS[-1]
        with tempfile.TemporaryDirectory() as tmp:
            j = re_.Join.__new__(re_.Join)
            j.d = unittest.mock.Mock(work=Path(tmp), evm_node_id=lambda i: writer)
            (Path(tmp) / 'shard-conf-6.json').write_text(json.dumps({'validators': [{'nodeId': v} for v in validators]}))
            self.assertEqual(j.expected_replicas(1, {'checkedShardEpoch': 6}), replicas)
            self.assertIsNone(j.expected_replicas(1, {'checkedShardEpoch': 7}), 'no configuration of that epoch: unknown')
            self.assertIsNone(j.expected_replicas(1, {}), 'no checked epoch')
            (Path(tmp) / 'shard-conf-8.json').write_text('{}')
            self.assertIsNone(j.expected_replicas(1, {'checkedShardEpoch': 8}), 'an unreadable configuration')

    def test_the_activated_epoch_is_the_excluding_drives(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            j = hd.Journal(gen / 'handoff' / 'log.jsonl', '0xother', 5, echo=lambda line: None)
            j.write('advance', 'done', shardEpoch=5)
            j = hd.Journal(gen / 'handoff' / 'log.jsonl', '0xexcl', 6, echo=lambda line: None)
            j.write('advance', 'done', sub='shard-conf', shardEpoch=99)
            j.write('advance', 'done', shardEpoch=6)
            self.assertEqual(re_.activated_shard_epoch(gen, '0xexcl'), 6)
            self.assertIsNone(re_.activated_shard_epoch(gen, '0xnone'))

    def test_the_wait_stops_nothing_until_every_writer_passes(self):
        j = re_.Join.__new__(re_.Join)
        j.r = unittest.mock.Mock(evm_node_id=self.R)
        j.expected_replicas = lambda i, p: list(self.EXPECTED)
        views = iter([{1: self.policy(shardEpoch=4, checkedShardEpoch=4, replicas=['A', self.R, 'C']), 2: self.policy()},
                      {1: self.policy(), 2: self.policy()}])
        j.archive_policies = lambda: next(views)
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(re_.time, 'sleep') as sleep:
            j.wait_archive_migration(6)
        self.assertEqual(sleep.call_count, 1, 'one more pass after the old-policy writer')
        j.archive_policies = lambda: {1: self.policy(), 2: {'error': 'unreachable'}}
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(re_.time, 'sleep'), self.assertRaises(RuntimeError):
            j.wait_archive_migration(6, seconds=-1)


class EveryWriter(unittest.TestCase):
    """astra's review of #1055 (P1): the retire gate reads every writer, not only the four host entities: another remote member, or a retired
    remote writer that still runs, may hold the retiree as a current or retained replica. Each must report and pass; an unavailable one fails."""
    R = '16Uiu2RETIREE'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gen = Path(self.tmp.name)
        (self.gen / 'handoff').mkdir()
        write_record(self.gen, 5, 'retired', stakingId=12, retiredShardEpoch=6, evmNodeId=self.R)   # the retiree
        write_record(self.gen, 6, 'member', evmNodeId='E6')                                       # a second remote joiner
        write_record(self.gen, 7, 'retired', evmNodeId='E7', stoppedAt='2026-11-14T00:00:00Z')    # stopped: no writer any more
        write_record(self.gen, 8, 'prepared', evmNodeId='E8')                                     # not a writer yet
        write_record(self.gen, 9, 'retired', evmNodeId='E9')                                      # retired, still running

    def tearDown(self):
        self.tmp.cleanup()

    def join(self, remote_policies, evidence=None):
        j = re_.Join.__new__(re_.Join)
        j.gen, j.entity, j.evidence_retained = self.gen, 5, evidence
        j.d = unittest.mock.Mock()
        j.d.transport.docker.entities = [1, 2]
        j.d.evm_node_id = lambda i: f'E{i}'
        j.r = re_.load(self.gen)[5]
        j.r.client = unittest.mock.Mock()
        j.expected_replicas = lambda i, p: ['A', 'B', 'C']
        real_wait = j.wait_archive_migration
        j.wait_archive_migration = lambda activated: real_wait(activated, seconds=-1)   # one pass, then the timeout
        good = {'checkedShardEpoch': 6, 'replicas': ['A', 'B', 'C'], 'retained': [], 'migrationComplete': True}
        self.good = good

        def remote_read(entity):
            value = remote_policies.get(entity.entity, good)
            if isinstance(value, Exception):
                raise value
            return value
        return j, unittest.mock.patch.multiple(re_, host_archive_policy=lambda gen, i: dict(good)), \
            unittest.mock.patch.object(re_.RemoteEntity, 'archive_policy', autospec=True, side_effect=remote_read)

    def test_the_writers_are_the_hosts_the_remote_members_and_the_running_retired(self):
        j, hosts, remote = self.join({})
        with hosts, remote:
            writers = j.archive_writers()
            self.assertEqual(sorted(writers), [1, 2, 6, 9], 'not the retiree itself, not a stopped or a not yet joined entity')
            self.assertEqual(writers[6][0], 'E6')
            with unittest.mock.patch.object(re_, 'say'):
                j.wait_archive_migration(6)   # every writer passes

    def test_a_second_remote_joiner_that_retains_the_retiree_stops_nothing(self):
        j, hosts, remote = self.join({6: {'checkedShardEpoch': 6, 'replicas': ['A', 'B', 'C'], 'retained': [self.R], 'migrationComplete': False}},
                                     evidence='held by roots 1-4')
        with hosts, remote, unittest.mock.patch.object(re_, 'say'), \
                unittest.mock.patch.object(re_.time, 'sleep'), self.assertRaises(RuntimeError):
            j.retire()
        j.r.client.op.assert_not_called()   # no stop-validator: the evidence note does not replace the archive check
        self.assertNotIn('stoppedAt', json.loads((re_.info_dir(self.gen) / '5.json').read_text()))

    def test_an_unavailable_remote_writer_stops_nothing(self):
        j, hosts, remote = self.join({9: re_.AgentError('the laptop agent does not answer')}, evidence='held')
        with hosts, remote, unittest.mock.patch.object(re_, 'say'), \
                unittest.mock.patch.object(re_.time, 'sleep'), self.assertRaises(RuntimeError):
            j.retire()
        j.r.client.op.assert_not_called()

    def test_when_every_writer_passes_it_stops_and_is_no_writer_any_more(self):
        j, hosts, remote = self.join({}, evidence='held')
        j.r.client.op.return_value = {'stopped': {}}
        with hosts, remote, unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.retire(), 0)
        self.assertEqual(j.r.client.op.call_args.args[0], 'stop-validator')
        self.assertIn('stoppedAt', json.loads((re_.info_dir(self.gen) / '5.json').read_text()))

    def test_an_unreadable_registry_stops_nothing(self):
        j, hosts, remote = self.join({}, evidence='held')
        (re_.info_dir(self.gen) / '6.json').write_text('{broken')
        with hosts, remote, self.assertRaises(RuntimeError):
            j.archive_writers()

    def test_malformed_peer_ids_are_refused_not_ordered(self):
        writer, validators, _ = SELECT_VECTORS[0]
        for bad in ('', 'bafzbeigai3eoy2ccc7ybwjfz5r3rdxqrinwi4rwytly24tdbh6yz7zxs4', '0' + writer[1:], '1' + writer, writer.lower(), 'Qm'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                re_.peer_bytes(bad)
        with self.assertRaises(ValueError):
            re_.select_replicas('', validators)
        with self.assertRaises(ValueError):
            re_.select_replicas(writer, validators + ['not-a-peer-id'])
        self.assertEqual(re_.peer_bytes(writer)[:1], b'\x00', 'an identity multihash (secp256k1 key)')


class Retire(unittest.TestCase):
    """remote_entity Join.retire: the intent is on record before the transaction, the request is sent only when none is on chain, and the retired
    validator is stopped only after the archive gate AND a recorded evidence-availability statement (#1055 review; astra Q4)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gen = Path(self.tmp.name)
        (self.gen / 'handoff').mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def join(self, state, requested=False, evidence=None, **extra):
        write_record(self.gen, 5, state, stakingId=12, **extra)
        j = re_.Join.__new__(re_.Join)
        j.gen, j.entity, j.evidence_retained = self.gen, 5, evidence
        j.d = unittest.mock.Mock()
        j.r = re_.load(self.gen)[5]
        j.r.client = unittest.mock.Mock()
        j.r.client.op.return_value = {'stopped': {}}
        j.r.custody_tx = unittest.mock.Mock(return_value={'address': '0xowner', 'out': 'tx 0x1'})
        self.requested = requested
        j.retirement_requested = lambda ident: self.requested
        j.hd = unittest.mock.Mock()
        j.hd.Journal.return_value.last_drive.return_value = None
        j.d.wait.return_value = '0xexcl'
        j.members_of = lambda result: [1, 2, 3, 4]
        j.drive = unittest.mock.Mock(return_value=0)
        j.wait_archive_migration = unittest.mock.Mock()
        return j

    def file(self):
        return json.loads((re_.info_dir(self.gen) / '5.json').read_text())

    def test_the_intent_is_saved_before_the_transaction(self):
        j = self.join('member')
        order = []
        real_save = j.save
        j.save = lambda **c: (order.append(('save', c.get('state'))), real_save(**c))
        j.r.custody_tx.side_effect = lambda *a: (order.append(('tx', a[0])), {'out': ''})[1]
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(re_, 'activated_shard_epoch', return_value=6):
            self.assertEqual(j.retire(), 0)
        self.assertEqual(order[:2], [('save', 'retiring'), ('tx', 'requestRetirement(uint64)')])
        self.assertEqual(self.file()['state'], 'retired')

    def test_a_lost_save_sends_nothing_and_a_rerun_sends_once(self):
        j = self.join('member')
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(j, 'save', side_effect=re_.RegistryError('lock timeout')), \
                self.assertRaises(re_.RegistryError):
            j.retire()
        j.r.custody_tx.assert_not_called()
        self.assertEqual(self.file()['state'], 'member')

    def test_a_rerun_does_not_send_a_request_that_is_on_chain(self):
        j = self.join('retiring', requested=True)
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(re_, 'activated_shard_epoch', return_value=6):
            self.assertEqual(j.retire(), 0)
        j.r.custody_tx.assert_not_called()
        j = self.join('retiring', requested=False)
        with unittest.mock.patch.object(re_, 'say'), unittest.mock.patch.object(re_, 'activated_shard_epoch', return_value=6):
            j.retire()
        j.r.custody_tx.assert_called_once_with('requestRetirement(uint64)', 12)

    def test_without_the_evidence_statement_the_validator_keeps_running(self):
        j = self.join('retired', retiredShardEpoch=6)
        with unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.retire(), 0)
        j.wait_archive_migration.assert_not_called()
        j.r.client.op.assert_not_called()
        self.assertNotIn('evidencePrerequisite', self.file())

    def test_with_it_the_gate_then_the_record_then_the_stop(self):
        j = self.join('retired', evidence='UTB/Q3 lineage and records held by roots 1-4 (checked 2026-11-14)', retiredShardEpoch=6)
        j.wait_archive_migration.side_effect = lambda e: self.assertNotIn('evidencePrerequisite', self.file(), 'recorded after the gate')
        with unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.retire(), 0)
        j.wait_archive_migration.assert_called_once_with(6)
        self.assertEqual(self.file()['evidencePrerequisite']['shardEpoch'], 6)
        self.assertEqual(j.r.client.op.call_args.args[0], 'stop-validator')

    def test_without_the_epoch_nothing_stops(self):
        j = self.join('retired', evidence='held')
        with unittest.mock.patch.object(re_, 'say'), self.assertRaises(RuntimeError):
            j.retire()
        j.wait_archive_migration.assert_not_called()
        j.r.client.op.assert_not_called()


class Register(unittest.TestCase):
    """remote_entity Join.run: an existing on-chain registration of the laptop's root key is reused, never registered twice (#1055 review)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gen = Path(self.tmp.name)
        (self.gen / 'handoff').mkdir()
        write_record(self.gen, 5, 'registered', accounts={'owner': '0xAbC'})
        (re_.info_dir(self.gen) / '5-node-info.json').write_text(json.dumps({'nodeId': 'R5', 'sigKey': '0x02' + 'ab' * 32}))

    def tearDown(self):
        self.tmp.cleanup()

    def join(self, existing):
        j = re_.Join.__new__(re_.Join)
        j.gen, j.entity, j.dry, j.stop_after, j.funder = self.gen, 5, False, 'bonded', None
        j.d = unittest.mock.Mock()
        j.d.balance.return_value = 10 ** 24
        j.r = re_.load(self.gen)[5]
        j.r.client = unittest.mock.Mock()
        j.r.client.op.return_value = {'follower': True, 'services': {}}
        j.r.tx = unittest.mock.Mock(return_value={'id': 13})
        j.registered_id = lambda: existing
        j.custody_lots = lambda ident: ['1']
        return j

    def test_an_existing_registration_is_reused(self):
        j = self.join(existing=12)
        with unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.run(), 0)
        self.assertNotIn(unittest.mock.call('register'), j.r.tx.call_args_list)
        self.assertEqual(json.loads((re_.info_dir(self.gen) / '5.json').read_text())['stakingId'], 12)
        self.assertEqual(json.loads((self.gen / 'handoff' / 'joiners.json').read_text()), {'12': 5})

    def test_otherwise_it_registers(self):
        j = self.join(existing=None)
        with unittest.mock.patch.object(re_, 'say'):
            self.assertEqual(j.run(), 0)
        j.r.tx.assert_any_call('register')
        self.assertEqual(json.loads((re_.info_dir(self.gen) / '5.json').read_text())['stakingId'], 13)

    def test_the_lookup_is_by_the_root_keys_hash_and_owner(self):
        j = re_.Join.__new__(re_.Join)
        j.r = re_.load(self.gen)[5]
        j.d = unittest.mock.Mock(custody='0xcustody')
        j.d.cast_run.return_value = '0xhash'
        j.d.view.return_value = [12, 1]
        j.d.view_text.return_value = '0xabc\n0xwithdrawal\n0x00\n0x00\n1\n0\n1\n1\nfalse'
        self.assertEqual(j.registered_id(), 12)
        j.d.cast_run.assert_called_with('keccak', '0x02' + 'ab' * 32)
        self.assertEqual(j.d.view.call_args.args[1:], ('keyOwner(bytes32)(uint64,uint8)', '0xhash'))
        j.d.view_text.return_value = '0xother\n0xw\n0x00\n0x00\n1\n0\n1\n1\nfalse'
        with self.assertRaises(RuntimeError):
            j.registered_id()
        j.d.view.return_value = [0, 0]
        self.assertIsNone(j.registered_id())
        j.d.view_text.return_value = '0xabc\n0xw\n0x00\n0x00\n1\n0\n1\n1\ntrue'
        self.assertTrue(j.retirement_requested(12))


class WorkflowAndModule(unittest.TestCase):
    """One join/retire/claim/catch-up command of an entity at a time; and remote_entity run as a script is one module with handoff_drive's
    (the lock tracking is not split between two copies, #1055 review)."""

    def test_one_workflow_of_an_entity_at_a_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = re_.workflow_lock(Path(tmp), 5)
            self.assertIsNotNone(first)
            self.assertIsNone(re_.workflow_lock(Path(tmp), 5), 'a second command of entity 5 is refused')
            other = re_.workflow_lock(Path(tmp), 6)
            self.assertIsNotNone(other, 'another entity is independent')
            first.close()
            again = re_.workflow_lock(Path(tmp), 5)
            self.assertIsNotNone(again)
            for h in (other, again):
                h.close()
            self.assertEqual(sorted(p.name for p in re_.info_dir(Path(tmp)).iterdir()), ['5.workflow', '6.workflow'], 'load() ignores them')

    def test_run_as_a_script_it_is_the_module_handoff_drive_imports(self):
        import sys
        here = Path(re_.__file__).resolve().parent
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp)
            (gen / 'handoff').mkdir()
            write_record(gen, 5, 'member', stakingId=12, accounts={'owner': '0x1'})
            driver = f'''
import runpy, sys
sys.path.insert(0, {str(here)!r})
sys.argv = ['remote_entity.py', 'retire-plan', {str(gen)!r}, '--entity', '5']
try:
    runpy.run_path({str(here / 'remote_entity.py')!r}, run_name='__main__')
except SystemExit as e:
    assert not e.code, e.code
import handoff_drive, remote_entity
assert handoff_drive.remote_entity is remote_entity, 'two copies'
lock = handoff_drive.hold_lock({str(gen)!r})
assert lock and remote_entity.holding({str(gen)!r}), 'the drive lock is seen by the script copy'
remote_entity.update_info({str(gen)!r}, 5, {{'note': 1}}, wait=0)
print('ONE-MODULE-OK')
'''
            done = subprocess.run([sys.executable, '-c', driver], capture_output=True, text=True, cwd=str(here))
            self.assertEqual(done.returncode, 0, done.stderr[-2000:])
            self.assertIn('ONE-MODULE-OK', done.stdout)
            self.assertIn('requestRetirement', done.stdout, 'the script ran its main')


class ColdRestoreScope(unittest.TestCase):
    """The explicit cold restore empties only the selected execution and bootstrap stores, never the signing authority's anti-equivocation and
    session history (astra Q2), and it ends with the node's own runtime readiness, not an execution height."""

    def test_only_the_execution_and_bootstrap_volumes_are_mounted(self):
        self.assertEqual(rj.COLD_RESTORE_VOLUMES, ('evm', 'archive', 'ureth'))
        for kept in ('auth', 'root', 'wallet', 'tools', 'network', 'jwt', 'work'):
            self.assertNotIn(kept, rj.COLD_RESTORE_VOLUMES)
        lap = rj.Laptop.__new__(rj.Laptop)
        lap.entity, lap.node_image, lap.home = 5, 'img', Path(tempfile.mkdtemp())
        mounts = []
        lap.vol = lambda name: f'p_{name}'
        lap.dc = lambda *a, **k: ''
        lap.one = lambda image, cmd, volumes=(), **k: mounts.append(list(volumes))
        lap.wait = lambda *a, **k: None
        lap.ureth_head = lambda: 1
        lap.vol_write = lambda *a: None
        lap.compose = lambda: {'services': {'shard5': {'entrypoint': ['ubft', 'shard-node', 'run']}}}
        lap.services_state = lambda: {}
        with unittest.mock.patch.object(rj.time, 'sleep'):
            lap.op_restore_start('AA==', 'AA==', '0xab')
        self.assertEqual(mounts, [['p_evm:/evm', 'p_archive:/archive', 'p_ureth:/ureth']], 'one wipe, of these three volumes only')

    def test_the_wipe_keeps_the_keys_and_touches_nothing_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('evm', 'archive', 'ureth', 'auth'):
                (root / name).mkdir()
            for rel in ('evm/keys.json', 'evm/node-info.json', 'evm/blocks.db', 'evm/tip.uc.cbor', 'archive/v2-aa', 'ureth/db', 'auth/session.db', 'auth/operator.cred'):
                (root / rel).write_text('x')
            script = rj.COLD_RESTORE_WIPE.replace('/evm', str(root / 'evm')).replace('/archive', str(root / 'archive')).replace('/ureth', str(root / 'ureth'))
            subprocess.run(['sh', '-c', script], check=True)
            left = sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())
            self.assertEqual(left, ['auth/operator.cred', 'auth/session.db', 'evm/keys.json', 'evm/node-info.json'])

    def test_a_cold_restore_ends_with_the_runtime_readiness(self):
        d = hd.Drive.__new__(hd.Drive)
        calls = []

        class Remote:
            def status(self):
                return {'urethHead': 900, 'restoring': True}

            def restore_start(self, uc, tr, body):
                calls.append('start')

            def seed_archive(self):
                calls.append('seed')

            def restore_finish(self):
                calls.append('finish')
                return {'running': True}
        tmp = Path(tempfile.mkdtemp())
        d.remote, d.target, d.restore_pin, d.new, d.gen, d.net = {5: Remote()}, 30, Path('/bin/true'), [1, 5], tmp, tmp
        d.say = lambda text: None
        d.expect = lambda ok, what, detail='': None if ok else (_ for _ in ()).throw(AssertionError(what))
        d.restore_body_ids = lambda: '30=ab'
        d.evh = lambda: tmp
        d.wait = lambda what, fn, seconds: next(r for r in (fn() for _ in range(20)) if r)
        d.wait_ready = lambda i, epoch, promoted, how: calls.append(('ready', epoch, promoted))

        def pin(cmd, **k):
            out = Path(cmd[-1]).parent
            (out / 'tip.uc.cbor').write_bytes(b'u')
            (out / 'tip.tr.cbor').write_bytes(b't')
            return subprocess.CompletedProcess(cmd, 0, 'bodyID=0xab', '')
        for follow in (False, True):
            calls.clear()
            with unittest.mock.patch.object(hd.subprocess, 'run', side_effect=pin):
                d.restore_remote(5, follow=follow)
            self.assertEqual(calls, ['start', 'seed', 'finish', ('ready', 30, follow)], f'follow={follow}: always a full restore, then readiness')



class HealthBinding(unittest.TestCase):
    """bft-core#1057 (astra Q3): follower readiness is evidence about the intended node under the intended assignment, not progress alone."""
    REF = {'lastUCRound': 100}

    def ready(self, binding, epoch=5, promoted=True, expect=EXPECT, reference=None):
        mine = {'role': 'active', 'roleEpoch': epoch, 'lastUCRound': 100, 'executionRecovery': 'ready', 'binding': binding}
        return hd.follower_ready(mine, reference or {**self.REF, 'binding': incumbent_binding()}, epoch, promoted, expect)

    def test_the_expected_node_and_assignment_is_ready(self):
        self.assertTrue(self.ready(joiner_binding()))
        self.assertIsNone(hd.binding_refusal({'binding': joiner_binding()}, {'binding': incumbent_binding()}, 5, True, EXPECT))

    def test_progress_without_a_binding_is_not_ready(self):
        self.assertFalse(self.ready(None))
        self.assertFalse(self.ready(joiner_binding(), reference=dict(self.REF)), 'no incumbent binding to compare with')
        self.assertFalse(self.ready(joiner_binding(), expect={}), 'nothing expected: nothing proven')

    def test_another_node_network_or_shard_is_not_ready(self):
        self.assertFalse(self.ready(joiner_binding(nodeId='16Uiu2OTHER')))
        self.assertFalse(self.ready(joiner_binding(networkId=6)))
        self.assertFalse(self.ready(joiner_binding(partitionId=7)))
        self.assertFalse(self.ready(joiner_binding(shardId='01')))

    def test_the_expected_handoff_must_be_in_the_verified_ancestry(self):
        self.assertFalse(self.ready(joiner_binding(history=[{'epoch': e, 'bodyId': f'b{e}'} for e in range(1, 5)])), 'not activated yet')
        forked = [{'epoch': e, 'bodyId': ('x5' if e == 5 else f'b{e}')} for e in range(1, 6)]
        self.assertFalse(self.ready(joiner_binding(history=forked)), 'another activation at the epoch')
        self.assertFalse(self.ready(joiner_binding(), expect=dict(EXPECT, bodyId=None)), 'the roots\' record could not be read')
        later = [{'epoch': e, 'bodyId': f'b{e}'} for e in range(1, 8)]
        self.assertTrue(self.ready(joiner_binding(history=later), epoch=5), 'a later epoch with the expected handoff in its ancestry')
        diverged = [{'epoch': 3, 'bodyId': 'zz'}, {'epoch': 5, 'bodyId': 'b5'}]
        self.assertFalse(self.ready(joiner_binding(history=diverged)), 'a history the incumbent does not share')
        self.assertTrue(self.ready(joiner_binding(history=[{'epoch': 5, 'bodyId': '0xB5'}])), 'hex is compared normalised')

    def test_after_the_election_the_installed_configuration_must_name_it_with_its_key(self):
        self.assertFalse(self.ready(joiner_binding(member=False)))
        self.assertFalse(self.ready(joiner_binding(sigKey='02cc')))
        self.assertFalse(self.ready(joiner_binding(), expect=dict(EXPECT, sigKey=None)), 'the expected key is unknown')
        self.assertFalse(self.ready(joiner_binding(shardConfHash='c5')), 'another installed configuration than the incumbent\'s')
        self.assertFalse(self.ready(joiner_binding(shardEpoch=3)))
        self.assertFalse(self.ready(joiner_binding(shardConfHash='')))

    def test_before_the_election_it_need_not_be_named(self):
        pre = joiner_binding(member=False, sigKey='', shardEpoch=3, shardConfHash='c3', history=[{'epoch': e, 'bodyId': f'b{e}'} for e in range(1, 5)])
        self.assertTrue(self.ready(pre, epoch=4, promoted=False, expect=dict(EXPECT, bodyId='b4', sigKey=None)))
        self.assertFalse(self.ready(pre, epoch=4, promoted=False, expect=dict(EXPECT, nodeId='16Uiu2OTHER', bodyId='b4')))

    def test_the_expectation_comes_from_the_registry_the_roots_and_the_installed_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = hd.Drive.__new__(hd.Drive)
            d.work, d.evidence = Path(tmp) / 'work', Path(tmp) / 'evidence'
            (d.evidence / 'epoch5').mkdir(parents=True)
            d.work.mkdir()
            (d.evidence / 'epoch5' / 'activation-record-5.json').write_text(json.dumps({'v3BodyId': 'b5'}))
            (d.work / 'shard-conf-4.json').write_text(json.dumps({'validators': [{'nodeId': '16Uiu2EVM1', 'sigKey': '0x02bb'},
                                                                                  {'nodeId': '16Uiu2JOINER', 'sigKey': '0x02aa'}]}))
            d.evm_node_id = lambda i: '16Uiu2JOINER'
            exp = d.binding_expectation(5, 5, True, {'binding': incumbent_binding()})
            self.assertEqual(exp, {'nodeId': '16Uiu2JOINER', 'bodyId': 'b5', 'sigKey': '0x02aa'})
            self.assertIsNone(d.binding_expectation(5, 5, True, {'binding': incumbent_binding(shardEpoch=9)})['sigKey'], 'no such configuration')
            self.assertIsNone(d.binding_expectation(5, 5, False, {'binding': incumbent_binding()})['sigKey'], 'before the election no key')


class RoundBracket(unittest.TestCase):
    """bft-core#1061: the joiner's certified round is compared with the incumbent's read before AND after it (its report comes through its
    agent, seconds late), not with a fixed slack: in step it lies in that bracket, give or take one certificate in delivery."""

    def ready(self, have, before, after=None):
        mine = {'role': 'active', 'roleEpoch': 5, 'lastUCRound': have, 'executionRecovery': 'ready'}
        return hd.follower_ready(mine, {'lastUCRound': before}, 5, True, None, None if after is None else {'lastUCRound': after})

    def test_the_gate_runs_steady_three_behind_is_in_step(self):
        """2026-11-14 gate-1: joiner 1018 read at ~00:24:32, validator 1 at 1021 read at 00:24:37 (the joiner admitted 1021 at 00:24:36.75)."""
        self.assertTrue(self.ready(1018, 1017, 1021))
        self.assertFalse(self.ready(1018, 1021), 'the old reading order alone: three behind, refused (the flapping)')

    def test_behind_or_ahead_of_the_bracket_is_not(self):
        self.assertFalse(self.ready(1012, 1017, 1021), 'behind the earlier reading')
        self.assertFalse(self.ready(1023, 1017, 1021), 'ahead of the later reading')
        self.assertTrue(self.ready(1016, 1017, 1021), 'one certificate in delivery at the edge')
        self.assertTrue(self.ready(1022, 1017, 1021))
        self.assertFalse(self.ready(0, 1017, 1021), 'no certificate yet')
        self.assertTrue(self.ready(100, 100), 'without a later reading: the one reading, give or take one')
        self.assertFalse(self.ready(98, 100))


class ExpectationRetry(unittest.TestCase):
    """astra's review of #1055 (P2): an incomplete expectation (the roots' activation record or the installed configuration not readable yet)
    is derived again on the next poll, never cached: a transient failure followed by success becomes ready."""

    def drive(self, bodies, keys):
        d = hd.Drive.__new__(hd.Drive)
        report = {'role': 'active', 'roleEpoch': 5, 'lastUCRound': 100, 'executionRecovery': 'ready', 'binding': joiner_binding()}

        class Remote:
            def status(self):
                return {'shardHealth': dict(report)}

        class Docker:
            def shard_health(self, i):
                return {'lastUCRound': 100, 'binding': incumbent_binding()}
        d.remote, d.docker, d.say = {5: Remote()}, Docker(), lambda text: None
        self.asked = []

        def expectation(i, epoch, promoted, reference):
            self.asked.append(epoch)
            return {'nodeId': '16Uiu2JOINER', 'bodyId': bodies.pop(0) if bodies else 'b5', 'sigKey': keys.pop(0) if keys else '0x02aa'}
        d.binding_expectation = expectation
        d.wait = lambda what, fn, seconds: next((r for r in (fn() for _ in range(5)) if r), None) or (_ for _ in ()).throw(AssertionError(what))
        return d

    def test_a_transient_activation_lookup_failure_is_retried(self):
        d = self.drive(bodies=[None, None], keys=[])
        d.wait_ready(5, 5, True, 'test')
        self.assertEqual(len(self.asked), 3, 'derived again after each incomplete expectation, then kept')

    def test_a_transient_configuration_failure_is_retried(self):
        d = self.drive(bodies=[], keys=[None])
        d.wait_ready(5, 5, True, 'test')
        self.assertEqual(len(self.asked), 2)

    def test_a_complete_expectation_is_derived_once(self):
        d = self.drive(bodies=[], keys=[])
        d.wait_ready(5, 5, True, 'test')
        self.assertEqual(len(self.asked), 1)
        self.assertFalse(hd.expectation_complete({'nodeId': 'n', 'bodyId': None, 'sigKey': 'k'}, True))
        self.assertFalse(hd.expectation_complete({'nodeId': 'n', 'bodyId': 'b', 'sigKey': None}, True))
        self.assertTrue(hd.expectation_complete({'nodeId': 'n', 'bodyId': 'b', 'sigKey': None}, False))

if __name__ == '__main__':
    unittest.main()
