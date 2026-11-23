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
            with patch.object(validator, 'HOME', home), patch.object(validator, 'AUTH', auth), patch.object(validator, 'ubft') as tool:
                with self.assertRaisesRegex(ValueError, 'Preserve the volume and fail-stop marker.*bonded.*Foundation'):
                    validator.authority_process(None, None)
                tool.assert_not_called()
                self.assertEqual((auth/'lifetime').read_text(), 'fail-stop\n')

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
