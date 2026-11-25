#!/usr/bin/env python3
"""Offline ceremony/Compose checks with fixture IDs, explicitly NOT a live cluster."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import ubft_flags   # noqa: E402  every flag a generated compose file passes ubft must be one the pinned ubft accepts (bft-core#1075)

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--ubft',required=True,type=Path)
p.add_argument('--keygen',required=True,type=Path)
p.add_argument('--b1genesis',required=True,type=Path)
p.add_argument('--check-prometheus',action='store_true')
p.add_argument('--pos-contracts',type=Path,help='a clean unicity-pos-contracts checkout at the pin (forge on PATH): also generate and probe the proof-of-stake profile')
p.add_argument('--vr-fresh-measurement',type=Path,help='independently recorded sixteen-seat hook measurement')
p.add_argument('--aggregator',type=Path,help='CI native nonempty-batch certification probe')
p.add_argument('--generation',type=Path,help='check the shipped files and Compose of an existing VR generation')
a=p.parse_args()
if (a.pos_contracts is None) != (a.vr_fresh_measurement is None):
    p.error('--pos-contracts and --vr-fresh-measurement are required together')
def flags_ok(generation):
    errors=ubft_flags.check(a.ubft.resolve(),[json.loads((generation/'compose.yaml').read_text())])
    assert not errors,'; '.join(errors)
if a.generation:
    import importlib.util
    g = a.generation.resolve()
    spec = importlib.util.spec_from_file_location('pos_probe', HERE / 'validate-pos.py')
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    manifest = json.loads((g / 'manifest.json').read_text())
    network = json.loads((g / 'network/network.json').read_text())
    assert network['chain_id'] == manifest['chain_id'] and network['genesis_hash'] == manifest['genesis_hash']
    assert network['funding_address'] == manifest['faucet_address']
    for name, digest in manifest['config_sha256'].items():
        assert hashlib.sha256((g / 'network' / name).read_bytes()).hexdigest() == digest, name
    flags_ok(g)
    print(json.dumps(probe.validate_vr(g, a.ubft.resolve(), manifest), indent=2))
    sys.exit()
with tempfile.TemporaryDirectory(prefix='tnops-validation-',dir='/tmp') as tmp:
    base=Path(tmp)
    images=base/'images.json'
    images.write_text(json.dumps({'sources':json.loads((HERE/'pins.json').read_text()),'binary_sha256':{},
        'images':{k:'sha256:'+'0'*64 for k in ['node','rpc','guard','signer']}}))
    (base/'captcha').write_text('offline-fixture')
    generations=[]
    # --block-interval-ms 0: the CI lanes' fast cadence, and a command line the pinned ubft accepts whether or not it has --block-interval (bft-core#1167)
    for i in range(2):
        generation=base/f'tn-ceremony-{i}'
        subprocess.run([sys.executable,str(HERE/'generate.py'),'--out',str(generation),'--validators','3',
            '--ubft',str(a.ubft.resolve()),'--keygen',str(a.keygen.resolve()),'--b1genesis',str(a.b1genesis.resolve()),'--images',str(images),
            '--offline-validation','--first-generation','--captcha-sitekey','fixture','--captcha-secret-file',str(base/'captcha'),'--block-interval-ms','0','--no-utb'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','compose','-f',str(generation/'compose.yaml'),'--profile','OFFLINE-VALIDATION-DO-NOT-START','config','--quiet'],check=True)
        flags_ok(generation)
        if a.check_prometheus:
            subprocess.run(['docker','run','--rm','--user','0','--entrypoint','/bin/promtool',
                '-v',str(generation/'monitoring')+':/etc/prometheus:ro',
                'prom/prometheus:v3.2.1@sha256:6927e0919a144aa7616fd0137d4816816d42f6b816de3af269ab065250859a62',
                'check','config','/etc/prometheus/prometheus.json'],check=True)
        manifest=json.loads((generation/'manifest.json').read_text())
        network=json.loads((generation/'network/network.json').read_text())
        assert manifest['genesis_hash']==network['genesis_hash']
        assert network['funding_address']==manifest['faucet_address']
        assert len(network['validator_rpc_urls'])==3
        genesis=json.loads((generation/'network/genesis.json').read_text())
        assert 'f39fd6e51aad88f6f4ce6ab8827279cfffb92266' not in str(genesis['alloc']).lower()
        # The deployed registry is the single B1 layout: an independent regeneration agrees with the shipped files, and refuses a changed storage word.
        verify=[str(a.b1genesis.resolve()),'--verify',None,'--profile',str(generation/'network/b1-profile.json'),
            '--root-genesis',str(generation/'network/trust-base.json'),'--shard-conf',str(generation/'network/full-shard-conf.json')]
        verify[2]=str(generation/'network/genesis.json')
        ok=subprocess.run(verify,text=True,capture_output=True)
        assert ok.returncode==0 and 'the deployed registry account matches the regeneration' in ok.stdout, ok.stdout+ok.stderr
        # the roots take the committee's identity RECORDS (an array), not the B1 identity document (an object)
        records=json.loads((generation/'network/genesis-identities.json').read_text())
        assert isinstance(records,list) and len(records)==3, records
        assert isinstance(json.loads((generation/'network/b1-identities.json').read_text()),dict)
        registry=[k for k,v in genesis['alloc'].items() if v.get('storage')]
        assert len(registry)==1, registry
        word=next(iter(genesis['alloc'][registry[0]]['storage']))
        genesis['alloc'][registry[0]]['storage'][word]='0x'+'ff'*32
        (base/f'tampered-{i}.json').write_text(json.dumps(genesis))
        verify[2]=str(base/f'tampered-{i}.json')
        bad=subprocess.run(verify,text=True,capture_output=True)
        assert bad.returncode!=0 and 'matches the regeneration' not in bad.stdout, 'a changed registry word was accepted'
        keys=[]
        for val in range(1,4):
            for kind in ('root','evm'):
                key=generation/f'validator{val}'/kind/'keys.json'
                assert key.stat().st_mode & 0o077==0
                keys.append(hashlib.sha256(key.read_bytes()).hexdigest())
            assert (generation/f'validator{val}/auth/client.cred').is_file()
        assert len(keys)==len(set(keys)), 'validator key material reused'
        if a.aggregator and i==0:
            import importlib.util
            spec=importlib.util.spec_from_file_location('aggregator_probe',HERE/'validate-aggregator.py')
            probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
            probe.validate(generation,a.ubft.resolve(),a.aggregator.resolve())
        generations.append(manifest)
    if a.pos_contracts:
        import importlib.util
        generation=base/'tn-ceremony-pos'
        subprocess.run([sys.executable,str(HERE/'generate.py'),'--out',str(generation),'--validators','4',
            '--ubft',str(a.ubft.resolve()),'--keygen',str(a.keygen.resolve()),'--b1genesis',str(a.b1genesis.resolve()),'--images',str(images),
            '--offline-validation','--first-generation','--captcha-sitekey','fixture','--captcha-secret-file',str(base/'captcha'),'--block-interval-ms','10000',
            '--vr-pos','--utb','--pos-contracts',str(a.pos_contracts.resolve()),'--vr-fresh-measurement',str(a.vr_fresh_measurement.resolve())],
            check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','compose','-f',str(generation/'compose.yaml'),'--profile','OFFLINE-VALIDATION-DO-NOT-START','config','--quiet'],check=True)
        flags_ok(generation)
        spec=importlib.util.spec_from_file_location('pos_probe',HERE/'validate-pos.py')
        probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
        print(json.dumps(probe.validate(generation,a.ubft.resolve(),a.keygen.resolve()),indent=2))
        import vr_release
        release = base/'vr-public'
        release.mkdir()
        document = json.loads((generation/'manifest.json').read_text())
        vr_release.stage_network_files(generation/'network', release, document)
        # #1297: plus the retired root key list, which every generation made now pins (an empty one for --first-generation)
        assert set(file.name for file in release.iterdir()) == {*vr_release.NETWORK_FILES, vr_release.root_keys.FILE}
        print(json.dumps({'vr_release_genesis_files':'PASS', 'utb_genesis_id':document['utb']['genesis_id']}))
    assert generations[0]['genesis_hash']!=generations[1]['genesis_hash']
    assert generations[0]['faucet_address']!=generations[1]['faucet_address']
    print(json.dumps({'validation':'offline fixtures; optional native aggregator probe; no deployable cluster',
        'generations':[{'genesis_hash':g['genesis_hash'],'faucet_address':g['faucet_address']} for g in generations],
        'result':'PASS'},indent=2))
