"""Unit tests of the remote joiner (remote_entity.py, remote_joiner.py, tunnel_relay.py, evm_keys.py, handoff_drive's guard): the forwards, the laptop's compose
file, the trust-base signature check, the agent protocol over a real Unix socket, the forwarder carrying bytes, the drive refusing a result that leaves a
prepared remote joiner out. No Docker, no network."""
import asyncio
import json
import os
from pathlib import Path
import socket
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
            self.assertEqual((loaded[5].root_node_id, loaded[5].state, loaded[5].client.sock), ('R5', 'registered', '/s/agent.sock'))
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
                return {'shardHealth': reports.pop(0) if len(reports) > 1 else reports[0]}

            def restore_start(self, *a):
                test.fail('the follower path must never empty or restore')

        class Docker:
            def shard_health(self, i):
                return {'role': 'active', 'roleEpoch': 5, 'lastUCRound': 100, 'executionRecovery': 'ready'}
        d = hd.Drive.__new__(hd.Drive)
        d.remote, d.target, d.docker = {5: Remote()}, 5, Docker()
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


if __name__ == '__main__':
    unittest.main()
