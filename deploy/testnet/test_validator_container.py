import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name):
    path = Path(__file__).parent/'validator-container'/f'{name}.py'
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


validator = module('validator')
p2p = module('p2p')


class ValidatorContainer(unittest.TestCase):
    def test_active_status_omits_the_follower_flag(self):
        self.assertEqual(validator.active_member_epoch({'activeEpoch':2}, 1), 2)
        self.assertIsNone(validator.active_member_epoch({'activeEpoch':2, 'follower':True}, 1))
        self.assertIsNone(validator.active_member_epoch({'activeEpoch':1}, 1))

    def test_authority_scope_uses_a_verified_uc_from_the_selected_epoch(self):
        with patch.object(validator, 'root_status', return_value={'activeEpoch':2, 'follower':True}), patch.object(
                validator, 'command', side_effect=[SimpleNamespace(stdout='{"rootEpoch":1,"shardEpoch":0}'),
                                                    SimpleNamespace(stdout='{"rootEpoch":2,"shardEpoch":1}')]):
            self.assertIsNone(validator.provision_scope({'shardEpoch':None}, 2))
            self.assertEqual(validator.provision_scope({'shardEpoch':None}, 2), {'rootEpoch':2, 'shardEpoch':2})

    def test_unpinned_release_checksum_stops_before_native_import(self):
        settings = SimpleNamespace(release_url='https://example.invalid/release')
        with patch.object(validator, 'download', return_value=b'changed'), patch.object(validator, 'ubft') as tool:
            with self.assertRaisesRegex(ValueError, 'authenticated image pin'):
                validator.bootstrap(settings, {'sha256sums':hashlib.sha256(b'expected').hexdigest()})
            tool.assert_not_called()

    def test_lost_authority_lifetime_cannot_generate_a_replacement(self):
        with tempfile.TemporaryDirectory() as path:
            home = Path(path)
            auth = home/'authority'
            auth.mkdir()
            (auth/'lifetime').write_text('fail-stop\n')
            with patch.object(validator, 'HOME', home), patch.object(validator, 'AUTH', auth), patch.object(validator, 'ubft') as tool:
                with self.assertRaisesRegex(ValueError, 'validator rotate'):
                    validator.authority_process(None, None)
                tool.assert_not_called()

    def test_port_plan_forwards_only_p2p_and_keeps_operator_listeners(self):
        nodes = {}
        for i in range(1, 5):
            for role, (port, _) in p2p.ROLES.items():
                nodes[f'{role}{i}'] = {'entrypoint':['ubft','--address',f'/ip4/0.0.0.0/tcp/{port}',
                                                     '--rpc-server-address','127.0.0.1:8002']}
        nodes['ureth1'] = {'entrypoint':['--http.addr','127.0.0.1']}
        routes = p2p.plan({'services':nodes}, '192.0.2.1', ['172.18.0.'+str(i) for i in range(2,6)], 1000)
        self.assertEqual({outer for _, outer, _, _ in routes}, set(range(27662,27666)) | set(range(29111,29115)))
        self.assertEqual({inner for _, _, _, inner in routes}, {8000,9000})
        self.assertEqual(nodes['ureth1']['entrypoint'], ['--http.addr','127.0.0.1'])
        self.assertIn('127.0.0.1:8002', nodes['root1']['entrypoint'])
        rules = p2p.commands('192.0.2.1', routes, 'REHEARSAL', '172.31.251.0/24')
        self.assertIn('-s 172.31.251.0/24 -j REHEARSAL', rules)
        self.assertNotIn('--dport 8002', rules)
