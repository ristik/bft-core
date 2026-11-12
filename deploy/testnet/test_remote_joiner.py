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


if __name__ == '__main__':
    unittest.main()
