#!/usr/bin/env python3
"""Offline ceremony/Compose checks with fixture IDs, explicitly NOT a live cluster."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--ubft',required=True,type=Path)
p.add_argument('--keygen',required=True,type=Path)
p.add_argument('--check-prometheus',action='store_true')
p.add_argument('--aggregator',type=Path,help='CI native nonempty-batch certification probe')
a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='tnops-validation-',dir='/tmp') as tmp:
    base=Path(tmp)
    images=base/'images.json'
    images.write_text(json.dumps({'sources':json.loads((HERE/'pins.json').read_text()),'binary_sha256':{},
        'images':{k:'sha256:'+'0'*64 for k in ['node','rpc','guard','signer']}}))
    (base/'captcha').write_text('offline-fixture')
    generations=[]
    for i in range(2):
        generation=base/f'tn-ceremony-{i}'
        subprocess.run([sys.executable,str(HERE/'generate.py'),'--out',str(generation),'--validators','3',
            '--ubft',str(a.ubft.resolve()),'--keygen',str(a.keygen.resolve()),'--images',str(images),
            '--offline-validation','--captcha-sitekey','fixture','--captcha-secret-file',str(base/'captcha')],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','compose','-f',str(generation/'compose.yaml'),'--profile','OFFLINE-VALIDATION-DO-NOT-START','config','--quiet'],check=True)
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
    assert generations[0]['genesis_hash']!=generations[1]['genesis_hash']
    assert generations[0]['faucet_address']!=generations[1]['faucet_address']
    print(json.dumps({'validation':'offline fixtures; optional native aggregator probe; no deployable cluster',
        'generations':[{'genesis_hash':g['genesis_hash'],'faucet_address':g['faucet_address']} for g in generations],
        'result':'PASS'},indent=2))
