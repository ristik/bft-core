#!/usr/bin/env python3
"""Fresh disposable genesis and N-validator Compose package; never reuses a home."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PINS = json.loads((HERE / 'pins.json').read_text())
FEE = '0x00000000000000000000000000000000000000fe'

def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')

def topology(out, n, ids, images, captcha):
    """JSON is a YAML subset, accepted directly by Docker Compose."""
    services = {}
    def service(name, image, command, mounts=(), memory='256m', cpu=0.5, networks=None, **extra):
        services[name] = dict(image=image, entrypoint=command, volumes=list(mounts),
            networks=networks or ['validators'], restart='unless-stopped',
            mem_limit=memory, cpus=cpu, pids_limit=128, read_only=True,
            cap_drop=['ALL'], security_opt=['no-new-privileges:true'],
            stop_grace_period='60s', tmpfs=['/tmp:size=64m,mode=1777'], logging={'driver': 'json-file', 'options': {'max-size':'10m', 'max-file':'3'}}, **extra)
    node = images['node']
    network = './network:/network:ro'
    root_boot = ','.join('/dns4/root%d/tcp/8000/p2p/%s' % (i, ids['root'][i-1]) for i in range(1,n+1))
    for i in range(1, n+1):
        auth = './validator%d/auth:/authority' % i
        evm = './validator%d/evm:/state' % i
        common = ['--trust-base', '/network/trust-base.json']
        service('root%d'%i, node, ['ubft','root-node','run','--home','/state','--address','/ip4/0.0.0.0/tcp/8000',
            '--bootnodes', ','.join('/dns4/root%d/tcp/8000/p2p/%s' % (j,ids['root'][j-1]) for j in range(1,n+1) if j!=i),
            '--profile-2','--shard-conf','/network/full-shard-conf.json','--shard-conf','/network/aggregator-conf.json',
            '--rpc-server-address','0.0.0.0:8002','--metrics','prometheus'] + common,
            ['./validator%d/root:/state'%i,network], memory='384m')
        service('authority%d'%i, node, ['ubft','signing-authority','run','--home','/authority',
            '--client-socket','/authority/client.sock','--operator-socket','/authority/operator.sock',
            '--operator-credential','/authority/operator.cred','--authority-id','paired-evm-%d'%i,
            '--node-id',ids['evm'][i-1],'--network-id','3','--partition-id','8','--shard-id','0x80',
            '--shard-epoch','0','--root-epoch','1'] + common, [auth,network])
        # A new authority process has a new key. Never auto-restart this lifetime.
        services['authority%d'%i]['restart']='no'
        service('ureth%d'%i, node, ['unicity-reth','node','--chain','/network/genesis.json','--datadir','/state',
            '--authrpc.jwtsecret','/jwt/jwt.hex','--authrpc.addr','0.0.0.0','--authrpc.port','8551',
            '--http','--http.addr','0.0.0.0','--http.port','8545','--http.api','eth,net,web3',
            '--rpc.eth-proof-window','64','--disable-discovery','--ipcdisable',
            '--engine.persistence-threshold','64','--builder.gaslimit','30000000','--unicity.fee-collector',FEE],
            ['./validator%d/ureth:/state'%i,'./validator%d/jwt:/jwt:ro'%i,network], memory='1536m',cpu=1.0)
        peers = root_boot + ''.join(',/dns4/shard%d/tcp/9000/p2p/%s'%(j,ids['evm'][j-1]) for j in range(1,n+1) if j!=i)
        replicas = [x for j,x in enumerate(ids['evm'],1) if j!=i][:2]
        service('shard%d'%i, node, ['ubft','shard-node','run','--home','/state','--executor','engine-api',
            '--address','/ip4/0.0.0.0/tcp/9000','--bootnodes',peers,
            '--full-shard-conf','/network/full-shard-conf.json','--genesis','/network/genesis.json',
            '--engine-url','http://ureth%d:8551'%i,'--eth-url','http://ureth%d:8545'%i,
            '--jwt-secret','/jwt/jwt.hex','--engine-fee-collector',FEE,'--registry-layout','2',
            '--execution-journal','/state/execution-journal.db','--archive-store','/archive',
            '--archive-prune','--journal-candidates','32','--trust-history-profile-2','--rpc-server-address','0.0.0.0:9101','--metrics','prometheus',
            '--signing-authority-socket','/authority/client.sock','--signing-authority-credential','/authority/client.cred']
            + common + sum((['--archive-replica',x] for x in replicas), []),
            [evm,auth,network,'./validator%d/jwt:/jwt:ro'%i,'./validator%d/archive:/archive'%i],memory='512m',cpu=0.75)
    keys = json.loads((out/'aggregator/keys.json').read_text())
    # Runtime secrets are supplied through a private env file, not Compose's public manifest.
    env = {'AGGREGATOR_LISTEN':'0.0.0.0:8080','AGGREGATOR_BFT_MODE':'live','AGGREGATOR_PARTITION_ID':'9',
        'AGGREGATOR_SHARD_ID':'0x80','AGGREGATOR_BFT_PEER_ID':ids['root'][0],
        'AGGREGATOR_BFT_ADDR':'/dns4/root1/tcp/8000','AGGREGATOR_P2P_ADDR':'/ip4/0.0.0.0/tcp/0',
        'AGGREGATOR_DB_PATH':'/state/db','AGGREGATOR_SMT_BACKEND':'disk',
        'AGGREGATOR_ROUND_DURATION_MS':'1000','AGGREGATOR_FAKE_STATE_TRANSITIONS':'false',
        'AGGREGATOR_UC_TIMEOUT_MS':'30000','AGGREGATOR_BATCH_LIMIT':'1000','AGGREGATOR_CONSISTENCY_PROOF_MODE':'rsmt'}
    (out/'aggregator/secrets.env').write_text('AGGREGATOR_AUTH_KEY='+keys['authKey']['privateKey'].removeprefix('0x')+'\nAGGREGATOR_SIG_KEY='+keys['sigKey']['privateKey'].removeprefix('0x')+'\n')
    service('aggregator',node,['rugregator'],['./aggregator:/state',network],memory='512m',cpu=0.75,environment=env,env_file=['./aggregator/secrets.env'])
    service('rpc',images['rpc'],['python3','-u','gateway.py'],[network],memory='128m',networks=['validators','edge'],environment={'TRUSTED_PROXY_IP':'172.30.89.1'},
        ports=['127.0.0.1:8545:8545'],healthcheck={'test':['CMD','python3','-c',"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8545/healthz', timeout=10)"],'interval':'30s','timeout':'12s','retries':3})
    service('relay',images['guard'],['python3','-u','relay.py'],['./network/network.json:/config/network.json:ro'],memory='128m',networks=['validators','faucet'])
    service('signer',images['signer'],['/bin/sh','/app/backend-entrypoint.sh'],memory='512m',networks=['faucet'],
        environment={'WEB3_PROVIDER':'http://relay:8545','HCAPTCHA_SITEKEY':captcha},secrets=['faucet_keystore','faucet_password','hcaptcha_secret'])
    service('faucet',images['guard'],['python3','-u','gateway.py'],['./network/network.json:/config/network.json:ro','./claims:/state'],
        memory='128m',networks=['faucet'],ports=['127.0.0.1:8088:8080'],depends_on=['signer'])
    service('prometheus','prom/prometheus:v3.2.1@sha256:6927e0919a144aa7616fd0137d4816816d42f6b816de3af269ab065250859a62',
        ['/bin/prometheus','--config.file=/etc/prometheus/prometheus.json','--storage.tsdb.path=/prometheus','--storage.tsdb.retention.time=7d','--storage.tsdb.retention.size=1GB'],
        ['./monitoring/prometheus.json:/etc/prometheus/prometheus.json:ro','./monitoring/alerts.json:/etc/prometheus/alerts.json:ro','./metrics:/prometheus'],
        memory='256m',networks=['validators','faucet'],user='10001:10001',ports=['127.0.0.1:9090:9090'])
    return {'name':out.name,'services':services,
        'networks':{'validators':{'internal':True},'faucet':{'ipam':{'config':[{'subnet':'172.30.88.0/24','gateway':'172.30.88.1'}]}},'edge':{'ipam':{'config':[{'subnet':'172.30.89.0/24','gateway':'172.30.89.1'}]}}},
        'secrets':{'faucet_keystore':{'file':'./faucet-secrets/keystore.json'},'faucet_password':{'file':'./faucet-secrets/password'},
                   'hcaptcha_secret':{'file':'./faucet-secrets/hcaptcha-secret'}}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    p.add_argument('--validators',type=int,default=4)
    p.add_argument('--chain-id',type=int,default=31337)
    p.add_argument('--ubft',type=Path,default=REPO/'build/ubft')
    p.add_argument('--keygen',type=Path,default=REPO/'build/tn-keygen')
    p.add_argument('--images',type=Path,default=HERE/'artifacts/images.json')
    p.add_argument('--offline-validation',action='store_true',help='native ceremony with fixture images; output CANNOT be deployed')
    p.add_argument('--captcha-sitekey',required=True)
    p.add_argument('--captcha-secret-file',required=True,type=Path)
    a=p.parse_args()
    if not 3 <= a.validators <= 32 or not 0 < a.chain_id < 2**53:
        p.error('validators must be 3..32; chain ID must be 1..2^53-1')
    out=a.out.resolve()
    if not re.fullmatch(r'tn-[a-z0-9][a-z0-9_-]*',out.name): p.error('generation directory name must be tn- followed by lowercase letters/digits/dashes')
    if out.exists(): p.error('output exists: choose a new generation directory')
    records=json.loads(a.images.read_text())
    if records['sources'] != PINS: p.error('image source pins differ')
    if any(not re.fullmatch(r'sha256:[0-9a-f]{64}',records['images'].get(k,'')) for k in ('node','guard','signer','rpc')):
        p.error('images must be immutable local image IDs from build-images.py')
    ubft=str(a.ubft.resolve())
    version=subprocess.check_output(['go','version','-m',ubft],text=True)
    if 'vcs.revision='+PINS['bft'] not in version or 'vcs.modified=true' in version:
        p.error('ubft must be built from clean pinned BFT source')
    if not a.offline_validation:
        if os.geteuid()!=0: p.error('live generation must run as root on Linux to assign UID 10001 ownership')
        subprocess.run(['docker','info'],check=True,stdout=subprocess.DEVNULL)
        for image in records['images'].values():
            subprocess.run(['docker','image','inspect',image],check=True,stdout=subprocess.DEVNULL)
    os.umask(0o077)
    processes=[]
    with tempfile.TemporaryDirectory(prefix='tn-',dir='/tmp') as tmp:
        home=Path(tmp)
        def cli(*args):
            return subprocess.check_output([ubft,*map(str,args)],text=True)
        try:
            roots=[]; evms=[]
            for i in range(1,a.validators+1):
                for kind in ('root','evm'):
                    cli('root-node' if kind=='root' else 'shard-node','init','--home',home/f'{kind}{i}','--generate')
                roots += [cli('node-id','--home',home/f'root{i}').strip().splitlines()[-1]]
                evms += [cli('node-id','--home',home/f'evm{i}').strip().splitlines()[-1]]
            cli('trust-base','generate','--home',home,'--epoch','1','--epoch-start','1','--network-id','3',
                *sum((['--node-info',home/f'root{i}/node-info.json'] for i in range(1,a.validators+1)),[]))
            for i in range(1,a.validators+1):
                cli('trust-base','sign','--home',home/f'root{i}','--trust-base',home/'trust-base.json')
            out.mkdir(parents=True)
            (out/'network').mkdir()
            shutil.copy2(home/'trust-base.json',out/'network/trust-base.json')
            cli('shard-node','init','--home',out/'aggregator','--generate')
            for i in range(1,a.validators+1):
                (out/f'validator{i}').mkdir()
                auth=out/f'validator{i}/auth'; auth.mkdir()
                cli('signing-authority','credential','--out',auth/'operator.cred')
            write(out/'compose.yaml',topology(out,a.validators,{'root':roots,'evm':evms},records['images'],a.captcha_sitekey))
            def authority(i,*args):
                auth=out/f'validator{i}/auth'
                if a.offline_validation:
                    return cli('signing-authority',*args)
                translated=[str(x).replace(str(auth),'/authority').replace(str(home/'full-shard-conf.json'),'/network/full-shard-conf.json') for x in args]
                return subprocess.check_output(['docker','compose','-f',str(out/'compose.yaml'),'exec','-T',f'authority{i}',
                    'ubft','signing-authority',*translated],text=True,stderr=subprocess.STDOUT)
            if not a.offline_validation:
                # Host-generated private files must be readable by the image's UID.
                # Run generator as root on Linux, then all containers remain unprivileged.
                for path in [out,*out.rglob('*')]: os.chown(path,10001,10001)
                subprocess.run(['docker','compose','-f',str(out/'compose.yaml'),'up','-d',
                    *[f'authority{i}' for i in range(1,a.validators+1)]],check=True)
            for i in range(1,a.validators+1):
                auth=out/f'validator{i}/auth'
                if a.offline_validation:
                    log=open(auth/'enrollment.log','w')
                    proc=subprocess.Popen([ubft,'signing-authority','run','--home',str(auth),
                        '--client-socket',str(auth/'client.sock'),'--operator-socket',str(auth/'operator.sock'),
                        '--operator-credential',str(auth/'operator.cred'),'--authority-id',f'paired-evm-{i}',
                        '--node-id',evms[i-1],'--network-id','3','--partition-id','8','--shard-id','0x80',
                        '--shard-epoch','0','--root-epoch','1','--trust-base',str(home/'trust-base.json')],stdout=log,stderr=log)
                    processes.append((proc,log))
                for _ in range(100):
                    try:
                        authority(i,'node-info','--operator-socket',auth/'operator.sock',
                            '--operator-credential',auth/'operator.cred','--out',auth/'node-info.json')
                        break
                    except subprocess.CalledProcessError:
                        time.sleep(.1)
                else: raise RuntimeError('authority startup timeout')
            cli('shard-conf','generate','--home',home,'--network-id','3','--partition-id','8','--partition-type-id','8',
                '--shard-id','0x80','--epoch-start','1','--t2-timeout','5000','--partition-params',f'proof_type=exec,chain_id={a.chain_id}',
                *sum((['--node-info',out/f'validator{i}/auth/node-info.json'] for i in range(1,a.validators+1)),[]))
            # Build a standard template with ubft, then finalize funding + unique generation entropy.
            cli('engine-api','genesis','--shard-conf',home/'shard-conf-8_0.json','--registry-layout','2','--out',home/'template.json')
            template=json.loads((home/'template.json').read_text())
            alloc=json.loads(subprocess.check_output([str(a.keygen.resolve()),str(home/'faucet-secrets')],text=True))
            template['alloc']=alloc
            template['extraData']='0x'+secrets.token_hex(32)
            write(home/'funded.json',template)
            identity=cli('engine-api','genesis','--shard-conf',home/'shard-conf-8_0.json','--registry-layout','2',
                '--alloc-source',home/'funded.json','--out',home/'genesis.json','--full-shard-conf',home/'full-shard-conf.json')
            print(identity)
            block=re.search(r'block hash:\s+(?:0x)?([a-fA-F0-9]{64})',identity).group(1)
            shutil.copy2(home/'full-shard-conf.json',out/'network/full-shard-conf.json')
            if not a.offline_validation: os.chown(out/'network/full-shard-conf.json',10001,10001)
            for i in range(1,a.validators+1):
                auth=out/f'validator{i}/auth'
                authority(i,'complete-enrollment','--operator-socket',auth/'operator.sock','--operator-credential',auth/'operator.cred','--shard-conf',home/'full-shard-conf.json')
                authority(i,'replace-session','--operator-socket',auth/'operator.sock','--operator-credential',auth/'operator.cred','--out',auth/'client.cred')
        finally:
            for proc,log in processes:
                proc.terminate()
            for proc,log in processes:
                try: proc.wait(timeout=15)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                log.close()
        (home/'agg-conf').mkdir()
        cli('shard-conf','generate','--home',home/'agg-conf','--network-id','3','--partition-id','9','--partition-type-id','9',
            '--shard-id','0x80','--epoch','0','--epoch-start','1','--t2-timeout','5000',
            '--partition-params','proof_type=aggregator_rsmt_v1','--node-info',out/'aggregator/node-info.json')
        for name in ('trust-base.json','full-shard-conf.json','genesis.json'):
            shutil.copy2(home/name,out/'network'/name)
        shutil.copy2(home/'agg-conf/shard-conf-9_0.json',out/'network/aggregator-conf.json')
        for i in range(1,a.validators+1):
            val=out/f'validator{i}'
            for kind in ('root','evm'):
                src=home/f'{kind}{i}'
                for sock in src.glob('*.sock'): sock.unlink()
                shutil.move(str(src),val/kind)
            for kind in ('ureth','archive','jwt'): (val/kind).mkdir()
            (val/'jwt/jwt.hex').write_text(secrets.token_hex(32)+'\n')
        shutil.move(str(home/'faucet-secrets'),out/'faucet-secrets')
        shutil.copy2(a.captcha_secret_file,out/'faucet-secrets/hcaptcha-secret')
        (out/'claims').mkdir()
        (out/'metrics').mkdir()
        (out/'monitoring').mkdir()
        write(out/'monitoring/prometheus.json', {'global':{'scrape_interval':'15s'},'rule_files':['/etc/prometheus/alerts.json'],
            'scrape_configs':[{'job_name':'root','metrics_path':'/api/v1/metrics',
                'static_configs':[{'targets':[f'root{i}:8002' for i in range(1,a.validators+1)]}]},
                {'job_name':'shard','metrics_path':'/api/v1/metrics','static_configs':[{'targets':[f'shard{i}:9101' for i in range(1,a.validators+1)]}]},
                {'job_name':'rpc','static_configs':[{'targets':['rpc:9090']}]}]})
        write(out/'monitoring/alerts.json', {'groups':[{'name':'testnet','rules':[
            {'alert':'TestnetTargetDown','expr':'up == 0','for':'1m','labels':{'severity':'page'},'annotations':{'summary':'Testnet target unavailable; contact duty operator'}},
            {'alert':'TestnetRPCFailures','expr':'increase(tn_rpc_upstream_errors_total[5m]) > 0','labels':{'severity':'warning'},'annotations':{'summary':'RPC identity or upstream failures'}}]}]})
        network=json.loads((HERE/'faucet/network.example.json').read_text())
        network.update(chain_id=a.chain_id,genesis_hash='0x'+block,funding_address=next(iter(alloc)),
            validator_rpc_urls=[f'http://ureth{i}:8545' for i in range(1,a.validators+1)],captcha_sitekey=a.captcha_sitekey)
        write(out/'network/network.json',network)
        write(out/'compose.yaml',topology(out,a.validators,{'root':roots,'evm':evms},records['images'],a.captcha_sitekey))
        manifest={'offline_validation_only':a.offline_validation,'generation':out.name,'chain_id':a.chain_id,'genesis_hash':'0x'+block,'validators':a.validators,
            'faucet_address':next(iter(alloc)), 'artifacts':records,
            'authority_status':{str(i):json.loads(authority(i,'status','--operator-socket',out/f'validator{i}/auth/operator.sock','--operator-credential',out/f'validator{i}/auth/operator.cred')) for i in range(1,a.validators+1)} if not a.offline_validation else {},
            'config_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in (out/'network').glob('*.json')}}
        write(out/'manifest.json',manifest)
        print(json.dumps(manifest,indent=2))
        if a.offline_validation:
            # Refuse accidental up: this ceremony's in-memory keys have been destroyed.
            compose=json.loads((out/'compose.yaml').read_text())
            for svc in compose['services'].values(): svc['profiles']=['OFFLINE-VALIDATION-DO-NOT-START']
            write(out/'compose.yaml',compose)
            print('OFFLINE VALIDATION ONLY: authority keys destroyed; cannot deploy these artifacts.')
        else:
            for path in [out,*out.rglob('*')]:
                if not path.is_socket(): os.chown(path,10001,10001)
            print('Authorities are live and enrolled. Do NOT restart them. Start remaining services with docker compose up -d.')

if __name__=='__main__': main()
