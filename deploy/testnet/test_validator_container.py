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

    def test_the_release_ships_the_retired_root_keys_to_the_home_apply_reads(self):
        """#1297/#1309: a release that lists retired-root-keys.json gets it into /data/release, where `ubft validator apply` and `rotate`
        read it by default (release/retired-root-keys.json under the validator home), as on a host install; a volume bootstrapped
        without it fetches the same authenticated file on its next start; a release without the list still bootstraps."""
        def release(with_list):
            files = {name: f'{name} bytes'.encode() for name in validator.FILES}
            files['seed/manifest.json'] = b'{}'
            if with_list:
                files['retired-root-keys.json'] = b'{"format":"unicity-retired-root-keys/1","keyHashes":[]}'
            files['utb-genesis.id'] = b'0xpin\n'
            return files

        def run(files, home, bins):
            served = dict(files)
            sums = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name, data in sorted({**served, **bins}.items())).encode()
            served['SHA256SUMS'] = sums

            def download(url, _limit):
                return served[url.split('/release/', 1)[1]]

            def tool(*args, **_):
                if args[:2] == ('seed', 'restore-pin'):
                    prefix = Path(args[args.index('--out') + 1])
                    for name in ('seed-pin.uc.cbor', 'seed-pin.tr.cbor'):
                        (prefix.parent/name).write_bytes(b'pin')
                    return SimpleNamespace(stdout='epoch=1 bodyID=0x' + 'ab'*32)
                return SimpleNamespace(stdout='')

            paths = {}
            for name, data in bins.items():
                paths[name] = home.parent/name
                paths[name].write_bytes(data)
            with patch.object(validator, 'HOME', home), patch.object(validator, 'RELEASE', home/'release'), \
                    patch.object(validator, 'BINARIES', {k: str(v) for k, v in paths.items()}), \
                    patch.object(validator, 'download', side_effect=download), patch.object(validator, 'ubft', side_effect=tool):
                validator.bootstrap(SimpleNamespace(release_url='http://127.0.0.1:1/release'),
                                    {'sha256sums': hashlib.sha256(sums).hexdigest(), 'utb_genesis_id': '0xpin'})

        bins = {'ubft': b'ubft', 'unicity-reth': b'reth'}
        with tempfile.TemporaryDirectory() as path:
            home = Path(path)/'data'
            home.mkdir()
            files = release(True)
            run(files, home, bins)
            self.assertEqual((home/'release'/'retired-root-keys.json').read_bytes(), files['retired-root-keys.json'])
            (home/'release'/'retired-root-keys.json').unlink()   # a volume from an image that did not fetch it
            run(files, home, bins)
            self.assertEqual((home/'release'/'retired-root-keys.json').read_bytes(), files['retired-root-keys.json'])
        with tempfile.TemporaryDirectory() as path:
            home = Path(path)/'data'
            home.mkdir()
            run(release(False), home, bins)
            self.assertFalse((home/'release'/'retired-root-keys.json').exists())
            self.assertTrue((home/'bootstrap.json').exists())

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
                self.assertEqual((validator.slot(), validator.auth_dir().name, validator.evm_dir().name, validator.ureth_dir().name,
                                  validator.active_file().name), (2, 'authority-2', 'evm-2', 'ureth-2', 'shard-active-2.json'))
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
        self.assertEqual(sorted(services), ['authority4', 'root4', 'shard4', 'ureth4'])
        self.assertIn('./validator4/recover-2/ureth:/state', services['ureth4']['volumes'])
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
                self.assertFalse(volume.startswith(('./validator4/auth', './validator4/evm', './validator4/archive', './validator4/ureth:')), volume)
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
        self.assertEqual(names[:3], ['vr-pos-publish', 'vr-pos-advance', 'vr-pos-recover'])
        self.assertTrue(hasattr(rehearse.Rehearsal, 'vr_pos_recover'))

    def test_the_late_joiner_runs_after_two_handoffs_with_the_containers_shard_command(self):
        """#1309: vr-late-joiner follows vr-pos-recover (root epoch 3) and starts the joiner as the validator container does: `restore` from
        the pin, without --follow-source and without a paired root."""
        import rehearse
        import vr_late_joiner
        names = [n for n, _ in rehearse.VR_STAGES]
        self.assertEqual(names[names.index('vr-pos-recover') + 1], 'vr-late-joiner')
        self.assertTrue(hasattr(rehearse.Rehearsal, 'vr_late_joiner'))
        entry = ['ubft', 'shard-node', 'run', '--home', '/state', '--follow-source', '/dns4/shard1/tcp/9000/p2p/x',
                 '--paired-activation-rpc', 'http://127.0.0.1:1', '--q3-lane']
        out = vr_late_joiner.restore_entry(entry, '0x' + 'ab'*32)
        self.assertEqual(out[:3], ['ubft', 'shard-node', 'restore'])
        self.assertNotIn('--follow-source', out)
        self.assertNotIn('--paired-activation-rpc', out)
        self.assertEqual(out[-6:], ['--tip-uc', '/state/tip.uc.cbor', '--tip-tr', '/state/tip.tr.cbor', '--trust-body-id', '0x' + 'ab'*32])
        self.assertIn('--q3-lane', out)
        self.assertEqual(entry[2], 'run', 'the cloned entry is not changed in place')

    def test_the_late_joiner_runs_the_release_ureth_vector_and_its_exit_follows(self):
        """#1321/#1316: the joiner's execution client is the container's (its own arguments, then ureth-flags.txt unchanged), and vr-joiner-exit
        follows vr-late-joiner."""
        import rehearse
        import vr_late_joiner
        names = [n for n, _ in rehearse.VR_STAGES]
        self.assertEqual(names[names.index('vr-late-joiner') + 1], 'vr-joiner-exit')
        self.assertTrue(hasattr(rehearse.Rehearsal, 'vr_joiner_exit'))
        clone = ['/bin/sh', '-c', 'x', 'ureth', 'unicity-reth', 'node', '--datadir', '/state', '--log.file.max-files', '0',
                 '--engine.persistence-threshold', '64', '--builder.gaslimit', '30000000', '--unicity.fee-collector', '0xfe', '--unicity.max-gas=9']
        shipped = ['--unicity.max-gas=9', '--unicity.fee-collector=0xfe']
        self.assertEqual(vr_late_joiner.release_ureth_entry(clone, shipped), clone[:10] + shipped,
                         'a release without the builder gas limit makes the joiner run without it, as the container would')
        self.assertEqual(vr_late_joiner.max_gap({10: 100, 11: 110, 12: 150, 13: 160}), (40, 11))
        self.assertEqual(vr_late_joiner.max_gap({10: 100}), (0, None))


    def test_the_finalizer_stage_follows_the_join_and_counts_the_race(self):
        """#1323: vr-finalizer runs after the joiner's stages; its summary counts each kind, the reverts and the gas of every transaction but
        the first successful one of its kind."""
        import rehearse
        import vr_late_joiner
        names = [n for n, _ in rehearse.VR_STAGES]
        self.assertEqual(names[names.index('vr-joiner-exit') + 1], 'vr-finalizer')
        self.assertTrue(hasattr(rehearse.Rehearsal, 'vr_finalizer'))
        tx = lambda kind, status, gas: {'result': '0xr', 'kind': kind, 'status': status, 'gasUsed': gas}
        out = vr_late_joiner.publication_summary([tx('finalizeCandidate', '0x1', 100), tx('finalizeCandidate', '0x0', 30),
                                                  tx('finalizeCandidate', '0x0', 31), tx('VR.publish', '0x1', 900), tx('VR.publish', '0x1', 890)])
        self.assertEqual(out['0xr'], {'finalizeCandidate': 3, 'finalizeReverted': 2, 'VR.publish': 2, 'publishReverted': 0,
                                      'gas': 1951, 'wastedGas': 951})

# The execution client's arguments that are the node's own: its data directory, key, JWT and listeners, and the local RPC surface. Every
# other argument binds it to the chain and must be the genesis ureths' (#1321).
LOCAL_URETH_FLAGS = frozenset({'--chain', '--datadir', '--p2p-secret-key', '--authrpc.jwtsecret', '--authrpc.addr', '--authrpc.port',
                               '--http.addr', '--http.port', '--http.api', '--addr', '--port'})
URETH_SWITCHES = frozenset({'--http', '--ipcdisable', '--disable-discovery', '--unicity.archive-state-proofs', '--unicity.no-proof-source'})


def ureth_flags(entry):
    """{flag: value} of a `unicity-reth node ...` argument vector in either spelling (a switch maps to None)."""
    args = [str(x) for x in entry]
    args = args[args.index('node') + 1:]
    out, i = {}, 0
    while i < len(args):
        name, eq, value = args[i].partition('=')
        if not name.startswith('--'):
            raise ValueError(f'stray ureth argument {args[i]!r}')
        if name in out:
            raise ValueError(f'ureth {name} given twice')
        if eq or name in URETH_SWITCHES:
            out[name] = value if eq else None
        else:
            out[name], i = args[i + 1], i + 1
        i += 1
    return out


class JoinerUrethFlags(unittest.TestCase):
    """#1321: the validator container's ureth runs the genesis ureths' vector, from the same source (vr_genesis.ureth_runtime_flags)."""
    PROFILE = ['--unicity.network-id=3', '--unicity.chain-id=496562270', '--unicity.max-gas=180944254', '--txpool.max-tx-gas=60000000',
               '--unicity.genesis-commitment=0x' + '4e'*32]
    MAX_GAS = 180944254

    def joiner_and_genesis(self, shipped):
        import vr_genesis
        images = {role:'sha256:' + '0'*64 for role in ('node', 'rpc', 'signer', 'guard')}
        compose = generate.topology(Path('test'), 4, {'root':['r']*4, 'evm':['s']*4}, images, '', ureth_flags=self.PROFILE,
                                    max_gas=self.MAX_GAS, vr_pos=True)
        with tempfile.TemporaryDirectory() as d:
            release = Path(d)
            (release/'ureth-flags.txt').write_text(shipped(vr_genesis) + '\n')
            with patch.object(validator, 'RELEASE', release), patch.object(validator, 'HOME', Path('/data')):
                joiner = validator.ureth_command({'ports':[27652, 29252, 31452]}, 1)
        return ureth_flags(joiner), {i: ureth_flags(compose['services'][f'ureth{i}']['entrypoint']) for i in range(1, 5)}

    def test_the_joiner_runs_the_genesis_ureth_vector(self):
        joiner, genesis = self.joiner_and_genesis(lambda g: ' '.join(g.ureth_runtime_flags(self.PROFILE, self.MAX_GAS)))
        self.assertEqual(joiner['--builder.gaslimit'], str(self.MAX_GAS))
        for i, flags in genesis.items():
            self.assertEqual({k: v for k, v in joiner.items() if k not in LOCAL_URETH_FLAGS},
                             {k: v for k, v in flags.items() if k not in LOCAL_URETH_FLAGS}, f'ureth{i}')
            self.assertEqual(flags['--builder.gaslimit'], str(self.MAX_GAS))

    def test_a_release_without_the_builder_gas_limit_differs(self):
        """The release of tn-public-20261127b: the certified vector and the fee collector only. The comparison names the missing flags."""
        joiner, genesis = self.joiner_and_genesis(lambda g: ' '.join(self.PROFILE) + f' --unicity.fee-collector={g.FEE_COLLECTOR}')
        missing = {k for k in genesis[1].keys() - joiner.keys() if k not in LOCAL_URETH_FLAGS}
        self.assertEqual(missing, {'--builder.gaslimit', '--engine.persistence-threshold'})

    def test_verify_certifies_the_vector_without_the_runtime_flags(self):
        """The pinned ubft's vr-genesis verify knows the --unicity.* and --txpool.* flags only: the shipped line minus the two runtime flags."""
        import vr_genesis
        shipped = ' '.join(vr_genesis.ureth_runtime_flags(self.PROFILE, self.MAX_GAS))
        self.assertEqual(vr_genesis.certified_vector(shipped), ' '.join(self.PROFILE) + f' --unicity.fee-collector={vr_genesis.FEE_COLLECTOR}')
        self.assertEqual(vr_genesis.certified_vector('--a=1 --builder.gaslimit 5 --engine.persistence-threshold=64 --b 2'), '--a=1 --b 2')

    def test_the_generator_refuses_a_compose_that_does_not_run_the_shipped_vector(self):
        import vr_genesis
        images = {role:'sha256:' + '0'*64 for role in ('node', 'rpc', 'signer', 'guard')}
        compose = generate.topology(Path('test'), 4, {'root':['r']*4, 'evm':['s']*4}, images, '', ureth_flags=self.PROFILE,
                                    max_gas=self.MAX_GAS, vr_pos=True)
        with tempfile.TemporaryDirectory() as d:
            shipped = Path(d)/'ureth-flags.txt'
            shipped.write_text(' '.join(vr_genesis.ureth_runtime_flags(self.PROFILE, self.MAX_GAS)) + '\n')
            generate.check_shipped_ureth_flags(compose, shipped, 4)
            shipped.write_text(' '.join(vr_genesis.ureth_runtime_flags(self.PROFILE, self.MAX_GAS + 1)) + '\n')
            with self.assertRaisesRegex(RuntimeError, 'does not run the shipped ureth-flags.txt vector'):
                generate.check_shipped_ureth_flags(compose, shipped, 4)


class LeavingValidator(unittest.TestCase):
    """#1316: once the identity left, the node container sends no election transactions and stops advancing its retired authority."""

    def run_participate(self, *, status, publish_out, rounds=3):
        halted = SimpleNamespace(n=0)

        def wait(_):
            halted.n += 1
            return halted.n > rounds
        calls = []

        def command(*args, **kw):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout=publish_out, stderr='')

        def rpc(url, method, params, evm=True):
            if method == 'eth_getBlockByNumber':
                return {'hash': '0xgen' if params[0] == '0x0' else '0xfin'}
            if method == 'eth_call':
                return '0x' + '11'*32
            return {'activeEpoch': 5, 'switch': None}
        with tempfile.TemporaryDirectory() as d, patch.object(validator, 'HOME', Path(d)), \
                patch.object(validator, 'RELEASE', Path(d)), patch.object(validator, 'command', command), \
                patch.object(validator, 'rpc', rpc), patch.object(validator, 'authority_status', return_value=status), \
                patch.object(validator, 'advance') as advance, patch('builtins.print') as printed:
            (Path(d)/'deployment.json').write_text(json.dumps({'election': '0xe1'}))
            (Path(d)/'manifest.json').write_text(json.dumps({'genesis_hash': '0xgen'}))
            (Path(d)/'join.json').write_text(json.dumps({'phase': 'activated'}))
            (Path(d)/'shard-active.json').write_text(json.dumps({'rootEpoch': 4}))
            validator.participate(SimpleNamespace(wait=wait))
        return calls, advance, [c.args[0] for c in printed.call_args_list if c.args]

    def test_a_retired_authority_is_not_advanced_again_and_said_once(self):
        retired = {'retired': True, 'lineageEpoch': 5, 'rootEpoch': 4, 'sessionIssued': False}
        gate = 'no election transactions: identity 5 requested retirement: it leaves at the next election'
        calls, advance, said = self.run_participate(status=retired, publish_out=gate + '\n')
        advance.assert_not_called()
        self.assertEqual(len(calls), 3, 'pos-publish still runs each round (the gate is the chain state, read at the certified block)')
        self.assertEqual(said.count(gate), 1, 'an unchanged gate is reported once')
        self.assertEqual(sum('retired this authority' in s for s in said), 1, said)

    def test_a_new_epoch_is_verified_once_more(self):
        calls, advance, _ = self.run_participate(status={'retired': True, 'lineageEpoch': 4, 'rootEpoch': 4, 'sessionIssued': False},
                                                 publish_out='', rounds=1)
        advance.assert_called_once_with(5, root=validator.ROOT, member=None, retired_ok=True)

    def test_a_member_still_advances(self):
        calls, advance, _ = self.run_participate(status={'retired': False, 'lineageEpoch': 4, 'rootEpoch': 4, 'sessionIssued': True},
                                                 publish_out='', rounds=1)
        advance.assert_called_once()

    def test_the_claim_waits_for_the_election_lock_keeps_its_log_and_says_the_containers_can_stop(self):
        locks = []

        @validator.contextlib.contextmanager
        def lock(name, wait=False, waiting=None):
            locks.append((name, wait, bool(waiting)))
            yield

        def stream(args, path, timeout):
            Path(path).write_text(f'attempt rc {rc}\nrc={rc}\n')
            return rc
        for rc in (0, 1, 'timeout'):
            with tempfile.TemporaryDirectory() as d, patch.object(validator, 'HOME', Path(d)), patch.object(validator, 'lock', lock), \
                    patch.object(validator, 'stream', side_effect=stream) as streamed, patch('builtins.print') as printed:
                a = SimpleNamespace(yes=True, claim=True)
                if rc:
                    with self.assertRaises(RuntimeError) as raised:
                        validator.leave(a, {})
                    self.assertIn('exit-logs', str(raised.exception), 'a failed or timed-out claim names its log')
                    if rc == 'timeout':
                        self.assertIn('timed out', str(raised.exception))
                else:
                    validator.leave(a, {})
                self.assertEqual(streamed.call_args.args[0], ['ubft', 'validator', 'claim'])
                logs = list((Path(d)/'exit-logs').iterdir())
                self.assertEqual(len(logs), 1)
                stop = any(validator.STOP_CONTAINERS in str(c.args[0]) for c in printed.call_args_list if c.args)
                self.assertEqual(stop, rc == 0, 'only a successful claim says the containers can be stopped')
        self.assertIn(('.tx.lock', True, True), locks, 'the claim waits for an election transaction in flight, and says so')

    def test_the_claim_output_streams_into_its_log_and_a_timeout_is_logged(self):
        """#1323: each line is printed and logged as it comes; a timeout kills the run and still leaves the log, ending rc=timeout."""
        with tempfile.TemporaryDirectory() as d, patch.object(validator, 'HOME', Path(d)), patch('builtins.print') as printed:
            log = Path(d)/'claim.log'
            self.assertEqual(validator.stream(['sh', '-c', 'echo previewing; echo claimed 100 UCT >&2; exit 0'], log, timeout=30), 0)
            self.assertEqual(log.read_text(), 'previewing\nclaimed 100 UCT\nrc=0\n')
            self.assertEqual([c.args[0] for c in printed.call_args_list], ['previewing\n', 'claimed 100 UCT\n'])
            self.assertEqual(validator.stream(['sh', '-c', 'exit 3'], log, timeout=30), 3)
            self.assertEqual(log.read_text(), 'rc=3\n')
            self.assertEqual(validator.stream(['sh', '-c', 'echo waiting for maturity; exec sleep 30'], log, timeout=0.5), 'timeout')
            self.assertEqual(log.read_text(), 'waiting for maturity\nrc=timeout\n')

    def test_a_claim_holding_the_lock_is_reported_once_not_as_errno_11(self):
        """#1323: while `exit --claim` holds .tx.lock the participation loop skips the election step quietly (one line), and still advances."""
        @validator.contextlib.contextmanager
        def held(name, wait=False, waiting=None):
            raise BlockingIOError(11, 'Resource temporarily unavailable')
            yield
        with patch.object(validator, 'lock', held):
            calls, advance, said = self.run_participate(status={'retired': False, 'lineageEpoch': 4, 'rootEpoch': 4, 'sessionIssued': True},
                                                        publish_out='', rounds=4)
        self.assertEqual(calls, [], 'nothing is sent while the claim holds the lock')
        self.assertFalse(any('Errno' in s for s in said), said)
        self.assertEqual(sum('holds the transaction lock' in s for s in said), 1, said)
        self.assertEqual(advance.call_count, 4, 'the authority is still advanced')

    def test_an_unchanged_finalizer_turn_is_reported_once(self):
        turn = 'result 11 is ready: identity 3 is finalizer rank 2 and finalizes from chain time 2026-11-27T10:00:00Z if no lower rank has by then'
        _, _, said = self.run_participate(status={'retired': False, 'lineageEpoch': 5, 'rootEpoch': 5, 'sessionIssued': True},
                                          publish_out=turn + '\n', rounds=4)
        self.assertEqual(said.count(turn), 1, said)


class JoinInOneRun(unittest.TestCase):
    """Join applies once and refreshes a pending authority if an earlier result excluded it."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.patches = [patch.object(validator, 'HOME', d), patch.object(validator, 'RELEASE', d/'release'),
                        patch.object(validator, 'CONFIG', d/'validator.json')]
        for x in self.patches:
            x.start()
        (d/'release').mkdir()
        (d/'release'/'vr-deployment.json').write_text(json.dumps({'networkWord': '0x' + 'aa'*32}))
        (d/'release'/'manifest.json').write_text(json.dumps({'chain_id': 3}))
        (d/'release'/'deployment.json').write_text(json.dumps({'election': '0xe1'}))
        (d/'authority').mkdir()
        (d/'authority'/'node-info.json').write_text(json.dumps({'nodeId': 'evm-node', 'sigKey': '0xab'}))
        (d/'node-slot').write_text('1\n')
        (d/'validator.json').write_text(json.dumps({'evmAuthority': {'socket': 'x'}, 'payee': '0xpay'}))
        (d/'authority-scope.json').write_text(json.dumps({'rootEpoch': 3, 'shardEpoch': 4}))
        (d/'join.json').write_text(json.dumps({'phase': 'applying'}))
        self.home = d

    def tearDown(self):
        for x in self.patches:
            x.stop()
        self.dir.cleanup()

    def test_apply_runs_once_with_the_pin_template(self):
        calls = []

        def ubft(*args, **kw):
            calls.append(args)
            if args[:2] == ('validator', 'apply'):
                template = json.loads(Path(args[args.index('--pin-pos-policy') + 1]).read_text())
                self.assertEqual(template, {'network': '0x' + 'aa'*32, 'chainId': 3, 'election': '0xe1'}, 'the template names no id')
                cfg = json.loads((self.home/'validator.json').read_text())
                (self.home/'validator.json').write_text(json.dumps({**cfg, 'id': 5}))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        class Stop(Exception):
            pass
        with patch.object(validator, 'ubft', ubft), patch.object(validator, 'authority_status', return_value={'enrollmentComplete': False}), \
                patch.object(validator, 'wait_for', side_effect=Stop):
            with self.assertRaises(Stop):
                validator.join(SimpleNamespace(yes=True), {})
        applies = [c for c in calls if c[:2] == ('validator', 'apply')]
        self.assertEqual(len(applies), 1, 'register, bond and delegation in one run')
        self.assertEqual(json.loads((self.home/'join.json').read_text()), {'phase': 'electing', 'id': 5})
        self.assertFalse(any(c[:2] == ('signing-authority', 'pos-policy') for c in calls), 'apply pins the policy itself')

    def test_join_refreshes_the_same_authority_after_a_missed_activation(self):
        path = self.home/'join.json'
        path.write_text(json.dumps({'phase': 'electing', 'id': 5}))
        config = self.home/'validator.json'
        config.write_text(json.dumps({**json.loads(config.read_text()), 'id': 5}))
        state = {'rootEpoch': 3, 'shardEpoch': 4, 'lineageEpoch': 3, 'enrollmentComplete': False}
        calls = []

        def ubft(*args, **kw):
            calls.append(args)
            out = Path(args[args.index('--out') + 1])
            epoch = args[args.index('--epoch') + 1]
            if args[:2] == ('q3', 'proof-envelope'):
                self.assertEqual(epoch, 4)
                out.write_bytes(b'activation four')
            else:
                names = [{'nodeId': 'other', 'sigKey': '0xcd'}]
                if epoch == 5:
                    names.append({'nodeId': 'evm-node', 'sigKey': '0xAB'})
                out.write_text(json.dumps({'epoch': epoch, 'validators': names}))
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        def authority(*args, **kw):
            calls.append(args)
            if args[0] == 'advance-with-proof':
                self.assertEqual(args[1:3], ('--scope-only', '--proof'))
                self.assertEqual(args[3].read_bytes(), b'activation four')
                state.update(rootEpoch=4, shardEpoch=5, lineageEpoch=4)
                return SimpleNamespace(returncode=0, stdout=json.dumps(state), stderr='')
            self.assertEqual(args[0], 'complete-enrollment')
            self.assertEqual(json.loads(args[2].read_text())['epoch'], 5)
            state['enrollmentComplete'] = True

        def wait_for(description, probe, **kw):
            if description == 'activated root epoch naming this authority':
                self.assertIsNone(probe(), 'the previously expected shard epoch names only incumbents')
                return probe()
            self.assertEqual(description, 'committee membership')
            return probe()

        with patch.object(validator, 'ubft', ubft), patch.object(validator, 'authority', authority), \
                patch.object(validator, 'authority_status', side_effect=lambda: dict(state)), \
                patch.object(validator, 'root_status', side_effect=[{'activeEpoch': 4, 'follower': True},
                                                                    {'activeEpoch': 5, 'follower': False}]), \
                patch.object(validator, 'wait_for', wait_for), patch.object(validator, 'advance') as advance, \
                patch.object(validator, 'local_status', return_value=SimpleNamespace(stdout='{"member":true}')), \
                patch.object(validator, 'show_status'):
            self.assertEqual(validator.join(SimpleNamespace(yes=True), {}), 0)
        advance.assert_called_once_with(5)
        self.assertEqual(json.loads(path.read_text()), {'phase': 'activated', 'id': 5, 'rootEpoch': 5})
        self.assertEqual([c[0] for c in calls], ['q3', 'q3', 'advance-with-proof', 'q3', 'complete-enrollment'])
