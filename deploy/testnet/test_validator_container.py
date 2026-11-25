import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import generate
import handoff_ops
import vr_recover
import vr_release


def module(name):
    path = Path(__file__).parent/'validator-container'/f'{name}.py'
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


validator = module('validator')
loader = module('load')


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
            with patch.object(validator, 'HOME', home), patch.object(validator, 'ubft') as tool:
                with self.assertRaisesRegex(ValueError, 'Preserve the volume and fail-stop marker.*bonded.*recover --yes'):
                    validator.authority_process(None, None)
                tool.assert_not_called()
                self.assertEqual((auth/'lifetime').read_text(), 'fail-stop\n')

    # --- #1286: recover a bonded identity whose authority is lost --------------------------------------------------------------
    def volume(self, path, marker=True):
        home = Path(path)
        (home/'authority').mkdir()
        (home/'evm').mkdir()
        if marker:
            (home/'authority/lifetime').write_text('fail-stop\n')
        (home/'validator.json').write_text(json.dumps({'id':3, 'payee':'0x' + '11'*20,
            'evmAuthority':{'socket':'authority/operator.sock', 'credential':'authority/operator.cred', 'nodeInfo':'authority/node-info.json'}}))
        return home

    def patched(self, home, calls, **extra):
        def tool(*args, **_):
            calls.append([str(a) for a in args])
            if args[:2] == ('shard-node', 'init'):
                Path(args[3]).mkdir()
            return SimpleNamespace(stdout='{}', returncode=0)
        settings = dict(HOME=home, CONFIG=home/'validator.json', ubft=tool,
                        recovery_scope=lambda: {'rootEpoch':2, 'shardEpoch':2}, **extra)
        return [patch.object(validator, k, v) for k, v in settings.items()]

    def run_patched(self, patches, fn, *args):
        for p in patches:
            p.start()
        try:
            return fn(*args)
        finally:
            for p in reversed(patches):
                p.stop()

    def settings(self):
        return SimpleNamespace(yes=True, release_url='https://example.invalid/release', shard_epoch=None)

    def test_recover_refuses_without_a_fail_stop_marker(self):
        with tempfile.TemporaryDirectory() as path:
            home, calls = self.volume(path, marker=False), []
            lost = patch.object(validator, 'authority_status', side_effect=OSError('no socket'))
            with self.assertRaisesRegex(ValueError, 'fail-stop marker'):
                self.run_patched([*self.patched(home, calls), lost], validator.recover, self.settings(), {'utb_genesis_id':'0x01'})
            self.assertEqual(calls, [])
            self.assertEqual(sorted(p.name for p in home.iterdir() if not p.name.startswith('.')), ['authority', 'evm', 'validator.json'])

    def test_recover_refuses_an_authority_that_still_holds_its_key(self):
        with tempfile.TemporaryDirectory() as path:
            home, calls = self.volume(path), []
            alive = patch.object(validator, 'authority_status', return_value={'keyLost':False, 'faulted':False})
            with self.assertRaisesRegex(ValueError, 'still answers and holds its key'):
                self.run_patched([*self.patched(home, calls), alive], validator.recover, self.settings(), {'utb_genesis_id':'0x01'})
            self.assertEqual(calls, [])

    def test_recover_prepares_a_fresh_slot_and_keeps_the_marked_one(self):
        with tempfile.TemporaryDirectory() as path:
            home, calls = self.volume(path), []
            (home/'authority/fingerprint').write_text('old')
            before = sorted(p.name for p in (home/'authority').iterdir())
            lost = patch.object(validator, 'authority_status', side_effect=OSError('no socket'))
            patches = [*self.patched(home, calls), lost]
            self.assertEqual(self.run_patched(patches, validator.recover, self.settings(), {'utb_genesis_id':'0x01'}), 0)
            rec = json.loads((home/'recover.json').read_text())
            self.assertEqual((rec['phase'], rec['old'], rec['new'], rec['id']), ('authority', 1, 2, 3))
            self.assertEqual(rec['scope'], {'rootEpoch':2, 'shardEpoch':2})
            # a fresh shard node key in an empty shard home, its UTB store from the verified seed; nothing in the marked slot
            self.assertIn(['shard-node', 'init', '--home', str(home/'evm-2'), '--generate'], calls)
            seed, = [c for c in calls if c[:2] == ['seed', 'import']]
            self.assertEqual(seed[seed.index('--shard-utb-db') + 1], 'evm-2/shard-utb-entries.db')
            self.assertNotIn('--root-utb-db', seed)
            self.assertEqual((home/'authority/lifetime').read_text(), 'fail-stop\n')
            self.assertEqual(sorted(p.name for p in (home/'authority').iterdir()), before)
            self.assertFalse((home/'node-slot').exists())
            # the authority container now starts only in the fresh directory, once
            with patch.object(validator, 'HOME', home):
                k, d, pending = validator.authority_target()
                self.assertEqual((k, d.name, pending['new']), (2, 'authority-2', 2))
                self.assertNotEqual(d, home/'authority')
                (d).mkdir()
                (d/'lifetime').write_text('fail-stop\n')
                with self.assertRaisesRegex(ValueError, 'lifetime has already started'):
                    validator.authority_target()
            # a second loss before linking never reuses a marked slot
            patches = [*self.patched(home, calls), patch.object(validator, 'authority_status', side_effect=OSError('gone'))]
            self.run_patched(patches, validator.recover, self.settings(), {'utb_genesis_id':'0x01'})
            rec = json.loads((home/'recover.json').read_text())
            self.assertEqual((rec['old'], rec['new']), (1, 3))
            self.assertEqual((home/'authority-2/lifetime').read_text(), 'fail-stop\n')

    def test_recover_switches_the_node_to_the_fresh_authority(self):
        with tempfile.TemporaryDirectory() as path:
            home, calls = self.volume(path), []
            (home/'authority-2').mkdir()
            (home/'evm-2').mkdir()
            (home/'network.json').write_text(json.dumps({'ports':[1, 2, 3]}))
            (home/'recover.json').write_text(json.dumps({'phase':'authority', 'id':3, 'old':1, 'new':2,
                                                          'scope':{'rootEpoch':2, 'shardEpoch':2}}))
            info = {'nodeId':'16Uiu2new', 'sigKey':'0x02AB'}
            def tool(*args, **_):
                calls.append([str(a) for a in args])
                if 'node-info' in args:
                    (home/'authority-2/node-info.json').write_text(json.dumps(info))
                if args[:2] == ('q3', 'shard-conf'):
                    Path(args[args.index('--out') + 1]).write_text(json.dumps({'epoch':2, 'validators':[{'nodeId':'16Uiu2new', 'sigKey':'0x02ab'}]}))
                return SimpleNamespace(stdout='{}', returncode=0)
            status = {'signingKeyFingerprint':'new', 'enrollmentComplete':False}
            advanced = []
            patches = [*self.patched(home, calls), patch.object(validator, 'ubft', tool),
                       patch.object(validator, 'RELEASE', home/'release'),
                       patch.object(validator, 'authority_status', return_value=status),
                       patch.object(validator, 'root_status', return_value={'activeEpoch':3}),
                       patch.object(validator, 'advance', side_effect=lambda target: advanced.append((target, validator.auth_dir().name))),
                       patch.object(validator, 'local_status', return_value=SimpleNamespace(stdout='{"member":true}')),
                       patch.object(validator, 'show_status')]
            (home/'release').mkdir()
            for name, doc in (('manifest.json', {'chain_id':7}), ('vr-deployment.json', {'networkWord':'0x' + '00'*32}),
                              ('deployment.json', {'election':'0x' + '22'*20})):
                (home/'release'/name).write_text(json.dumps(doc))
            self.assertEqual(self.run_patched(patches, validator.recover, self.settings(), {}), 0)
            order = [c[:2] for c in calls if c[0] == 'validator']
            self.assertEqual(order, [['validator', 'recover'], ['validator', 'init']])   # the transactions before the relink
            rec, = [c for c in calls if c[:2] == ['validator', 'recover']]
            self.assertEqual(rec[rec.index('--old-authority-home') + 1], 'authority')
            self.assertEqual(rec[rec.index('--new-evm-authority-socket') + 1], 'authority-2/operator.sock')
            init, = [c for c in calls if c[:2] == ['validator', 'init']]
            self.assertEqual(init[init.index('--evm-authority-socket') + 1], 'authority-2/operator.sock')
            self.assertEqual(init[init.index('--id') + 1], '3')
            self.assertIn(['signing-authority', 'complete-enrollment', '--shard-conf', str(home/'authority-2/activated-shard.json'),
                           '--operator-socket', str(home/'authority-2/operator.sock'), '--operator-credential', str(home/'authority-2/operator.cred')], calls)
            self.assertEqual(advanced, [(3, 'authority-2')])
            self.assertEqual((home/'authority-2/fingerprint').read_text(), 'new')
            self.assertEqual(json.loads((home/'recover.json').read_text())['phase'], 'activated')
            self.assertEqual((home/'authority/lifetime').read_text(), 'fail-stop\n')
            with patch.object(validator, 'HOME', home), patch.object(validator, 'RELEASE', home/'release'):
                self.assertEqual((validator.slot(), validator.auth_dir().name, validator.evm_dir().name, validator.active_file().name),
                                 (2, 'authority-2', 'evm-2', 'shard-active-2.json'))
                (home/'release/fee-collector.txt').write_text('0x' + '33'*20)
                (home/'bootstrap.json').write_text('{"body":"0x01"}')
                with patch.object(validator, 'peers', return_value=['/ip4/1/tcp/1/p2p/a', '/ip4/1/tcp/2/p2p/b']):
                    shard = [str(x) for x in validator.shard_command({'ports':[1, 2, 3], 'announce':None}, {'utb_genesis_id':'0x01'}, 2)]
                self.assertEqual(shard[1:3], ['shard-node', 'restore'])   # the fresh node joins from the seed, staging-only
                self.assertEqual(shard[shard.index('--home') + 1], str(home/'evm-2'))
                self.assertEqual(shard[shard.index('--signing-authority-socket') + 1], str(home/'authority-2/client.sock'))
                self.assertEqual(shard[shard.index('--archive-store') + 1], str(home/'evm-2/archive'))

    def test_an_activation_that_does_not_name_the_fresh_key_is_refused(self):
        info = {'nodeId':'16Uiu2new', 'sigKey':'0x02ab'}
        validator.check_activated_conf({'validators':[{'nodeId':'16Uiu2new', 'sigKey':'0x02AB'}]}, info)
        for conf in ({'validators':[{'nodeId':'16Uiu2old', 'sigKey':'0x02ab'}]}, {'validators':[{'nodeId':'16Uiu2new', 'sigKey':'0x03ab'}]}):
            with self.assertRaisesRegex(ValueError, 'another election activated first'):
                validator.check_activated_conf(conf, info)

    def test_compose_publishes_only_the_announced_p2p_ports(self):
        images = {role:'sha256:' + '0'*64 for role in ('node', 'rpc', 'signer', 'guard')}
        ids = {'root':['r']*4, 'evm':['s']*4}
        address = '192.0.2.10'
        options = dict(vr_pos=True, port_offset=1000, public_p2p_ip=address)
        boot = generate.topology(Path('test'), 4, ids, images, '', **options)
        final = generate.topology(Path('test'), 4, ids, images, '', ureth_flags=['--final'], **options)
        generate.check_authorities_unchanged(boot, final, 4)
        self.assertTrue(final['networks']['validators']['internal'])
        for compose in (boot, final):
            services = compose['services']
            self.assertEqual({name:svc['ports'] for name, svc in services.items() if 'ports' in svc}, {
                'rpc':['127.0.0.1:9545:8545'],
                'faucet':['127.0.0.1:9088:8080'],
                'prometheus':['127.0.0.1:10090:9090'],
                **{f'pod{i}':[f'{address}:{27661+i}:8000/tcp', f'{address}:{29110+i}:9000/tcp']
                   for i in range(1,5)},
            })
            for i in range(1,5):
                self.assertEqual(services[f'authority{i}']['restart'], 'no')
                self.assertEqual(services[f'authority{i}']['network_mode'], f'service:pod{i}')
                self.assertIn('127.0.0.1', services[f'ureth{i}']['entrypoint'])
                for role, port in (('root',27661+i), ('shard',29110+i)):
                    args = services[f'{role}{i}']['entrypoint']
                    bind = args[args.index('--rpc-server-address')+1]
                    self.assertTrue(bind.startswith('127.0.0.1:'))
                    binding = [{'HostIp':address, 'HostPort':str(port)}]
                    self.assertEqual(vr_release.published_peer(args, binding), f'/ip4/{address}/tcp/{port}')
                    with self.assertRaisesRegex(ValueError, 'differs'):
                        vr_release.published_peer(args, [{'HostIp':'0.0.0.0', 'HostPort':str(port)}])
        private = generate.topology(Path('test'), 4, ids, images, '', vr_pos=True)
        self.assertNotIn('p2p', private['networks'])
        self.assertNotIn('ports', private['services']['pod1'])
        self.assertNotIn('--announce-addresses', private['services']['root1']['entrypoint'])
        with self.assertRaisesRegex(RuntimeError, 'owns the authority namespace'):
            generate.check_authorities_unchanged(private, final, 4)

    def test_mismatched_oci_manifest_refuses_before_docker_load(self):
        def payload(value):
            return json.dumps(value).encode()

        def descriptor(data):
            return {'digest':'sha256:' + hashlib.sha256(data).hexdigest(), 'size':len(data)}

        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            config = payload({'os':'linux', 'architecture':'amd64'})
            cfg = descriptor(config)
            image = payload({'config':cfg, 'layers':[]})
            entry = {**descriptor(image), 'mediaType':loader.IMAGE_MANIFEST}
            config_name = loader.blob_path(cfg['digest'])
            archive_path = bundle/loader.ARCHIVE
            with tarfile.open(archive_path, 'w:gz') as archive:
                for name, data in {
                    'index.json':payload({'manifests':[entry]}),
                    loader.blob_path(entry['digest']):image,
                    config_name:config,
                    'manifest.json':payload([{'Config':config_name, 'Layers':[]}]),
                }.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            archive_digest = loader.digest(archive_path)

            def pin(image_id):
                manifest = bundle/'manifest.json'
                manifest.write_bytes(payload({'imageId':image_id, 'platform':'linux/amd64',
                                              'archive':loader.ARCHIVE, 'archiveSha256':archive_digest}))
                sums = bundle/'SHA256SUMS'
                sums.write_text(f'{loader.digest(manifest)}  manifest.json\n{archive_digest}  {loader.ARCHIVE}\n')
                return loader.digest(sums)

            with patch.object(loader.subprocess, 'run') as docker:
                with self.assertRaisesRegex(ValueError, 'does not match the pinned image ID'):
                    loader.load_bundle(bundle, pin('sha256:' + '0'*64))
                docker.assert_not_called()
                self.assertEqual(loader.load_bundle(bundle, pin(entry['digest'])), entry['digest'])
                docker.assert_called_once()


class VRRecoverStage(unittest.TestCase):
    """vr-pos-recover (#1286): the fresh node slot of a recovered Compose entity."""

    def compose(self):
        images = {role:'sha256:' + '0'*64 for role in ('node', 'rpc', 'signer', 'guard')}
        ids = {'root':[f'16Uiu2root{i}' for i in range(1, 5)], 'evm':[f'16Uiu2evm{i}' for i in range(1, 5)]}
        return generate.topology(Path('test'), 4, ids, images, '', vr_pos=True, vr_authority_follow='http://127.0.0.1:8002')

    def test_the_recovered_entity_runs_on_a_fresh_slot_only(self):
        compose = self.compose()
        services = vr_recover.recover_services(compose, 4, 2, '16Uiu2fresh', 2, 3, '/authority/current-trust.json', '0x' + 'ab'*32)
        self.assertEqual(sorted(services), ['authority4', 'root4', 'shard4'])
        entry = services['authority4']['entrypoint']
        value = lambda flag: entry[entry.index(flag) + 1]
        self.assertEqual((value('--node-id'), value('--root-epoch'), value('--shard-epoch'), value('--trust-base')),
                         ('16Uiu2fresh', '2', '3', '/authority/current-trust.json'))
        self.assertEqual(value('--registration-policy'), '/authority/registration.json')
        self.assertEqual(value('--execution-genesis-hash'), '0x' + 'ab'*32)
        for gone in ('--fence-provision-file', '--follow-root-activations', '--follow-client-credential'):
            self.assertNotIn(gone, entry)
        self.assertIn('--require-pos-policy', entry)
        self.assertEqual(services['authority4']['restart'], 'no')
        self.assertEqual(services['authority4']['network_mode'], 'service:pod4')
        self.assertIn('./validator4/recover-2/auth:/authority', services['authority4']['volumes'])
        self.assertIn('./validator4/recover-2/auth/pop:/pop:ro', services['root4']['volumes'])
        shard = services['shard4']
        self.assertEqual({v.split(':')[1]: v.split(':')[0] for v in shard['volumes']}['/state'], './validator4/recover-2/evm')
        self.assertIn('./validator4/recover-2/auth:/authority', shard['volumes'])
        self.assertIn('./validator4/recover-2/archive:/archive', shard['volumes'])
        follow = shard['entrypoint'][shard['entrypoint'].index('--follow-source') + 1].split(',')
        self.assertEqual(follow, [f'/dns4/shard{j}/tcp/9000/p2p/16Uiu2evm{j}' for j in (1, 2, 3)])
        # nothing of the old slot is mounted any more, and the other entities are untouched
        for svc in services.values():
            for volume in svc['volumes']:
                self.assertFalse(volume.startswith(('./validator4/auth', './validator4/evm', './validator4/archive')), volume)
        self.assertEqual(compose['services']['authority4']['volumes'][0], './validator4/auth:/authority')

    def test_the_override_is_part_of_every_compose_operation(self):
        compose = self.compose()
        with tempfile.TemporaryDirectory() as path:
            gen = Path(path)
            (gen/'compose.yaml').write_text(json.dumps(compose))
            self.assertEqual(vr_recover.authority_dir(gen, handoff_ops.load_compose(gen), 4), (gen/'validator4/auth').resolve())
            services = vr_recover.recover_services(compose, 4, 2, '16Uiu2fresh', 2, 3, '/network/trust-base.json', '0x00')
            (gen/handoff_ops.RECOVER_OVERRIDE).write_text(json.dumps({'services':services}))
            self.assertEqual(handoff_ops.compose_files(gen)[-2:], ['-f', str(gen/handoff_ops.RECOVER_OVERRIDE)])
            loaded = handoff_ops.load_compose(gen)
            self.assertEqual(vr_recover.authority_dir(gen, loaded, 4), (gen/'validator4/recover-2/auth').resolve())
            self.assertEqual(vr_recover.authority_dir(gen, loaded, 3), (gen/'validator3/auth').resolve())
            (gen/'validator4/recover-2').mkdir(parents=True)
            self.assertEqual(vr_recover.next_slot(gen, 4), 3)

    def test_genesis_identity_and_owner_key(self):
        import base64
        with tempfile.TemporaryDirectory() as path:
            gen = Path(path)
            (gen/'validator2/root').mkdir(parents=True)
            (gen/'network').mkdir()
            (gen/'vr-owner-keys').mkdir()
            (gen/'validator2/root/node-info.json').write_text(json.dumps({'nodeId':'16Uiu2root2'}))
            payee = bytes.fromhex('11'*20)
            rows = [{'stakingId':base64.b64encode((n).to_bytes(8, 'big')).decode(), 'rootNodeId':f'16Uiu2root{n}', 'evmNodeId':f'16Uiu2evm{n}',
                     'operatorPayee':base64.b64encode(payee if n == 2 else bytes(20)).decode()} for n in (1, 2)]
            (gen/'network/genesis-identities.json').write_text(json.dumps(rows))
            (gen/'vr-owner-keys/keys.json').write_text(json.dumps({'owners':[{'address':'0x' + '11'*20, 'privateKey':'0xkey'}]}))
            self.assertEqual(vr_recover.genesis_identity(gen, 2), (2, '0x' + '11'*20, '16Uiu2root2', '16Uiu2evm2'))
            self.assertEqual(vr_recover.owner_key(gen, {'pos':{'owner_keys':'vr-owner-keys'}}, '0x' + '11'*20), '0xkey')

    def test_the_stage_runs_after_vr_pos_advance(self):
        import rehearse
        names = [n for n, _ in rehearse.VR_STAGES]
        self.assertEqual(names[:2], ['vr-pos-advance', 'vr-pos-recover'])
        self.assertTrue(hasattr(rehearse.Rehearsal, 'vr_pos_recover'))
