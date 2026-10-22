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

import operator_rpc
import pos

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PINS = json.loads((HERE / 'pins.json').read_text())
FEE = '0x00000000000000000000000000000000000000fe'

# The testnet profile's churn budget (owner decision 19, briefs/p85-churn-bound-note.md): D <= 1/2, the full normalized weight distance between consecutive
# committees. A small committee needs it: replacing one of four equal-weight validators is D = 1/2 (the DEV default, 1/4, admits none). The strict-third turnover
# and the two-thirds overlap gates still apply, so two of four are refused. It is committed in the EVM shard configuration at genesis
# (rootchain/consensus/storage ContinuityPolicy reads continuity_max_distance as "num/den").
EVM_CONTINUITY_MAX_DISTANCE = '1/2'

# The one B1 profile (`ubft engine-api b1-profile`) is the source of the registry genesis (permanent layout, format 2), the ureth --unicity.* bindings and the shard
# nodes' Update admission, exactly as scripts/dnb-devnet.sh and the Q3 lanes use it. W_cert is the lanes' value.
# B (epochs one block may install) and the P85 evidence/hold windows; certificate age no longer expires, so there is no W_cert.
MAX_EPOCHS, DELTA_EV, DELTA_HOLD = 2, 16, 17

def ureth_flags_of(profile_output):
    """The `ureth flags:` line `engine-api b1-profile` prints: the bindings that pin the paired client to the profile."""
    lines = [l.split(':', 1)[1].split() for l in profile_output.splitlines() if l.startswith('ureth flags:')]
    if len(lines) != 1 or not lines[0]: raise ValueError('b1-profile printed no single "ureth flags:" line')
    return lines[0]

def genesis_commitment(genesis):
    """The registry's genesisCommitment word of a finalized EVM genesis: alloc[registry].storage[keccak256("unicity.seal-registry/genesisCommitment")]. The paired
    client needs it as --unicity.genesis-commitment (the lanes pass it the same way, scripts/lib/reth-pin.sh urethB1GenesisCommitment): `b1-profile` does not print it."""
    slot = subprocess.run(['cast', 'keccak', 'unicity.seal-registry/genesisCommitment'], check=True, text=True, capture_output=True).stdout.strip().lower()
    alloc = {k.lower().removeprefix('0x'): v for k, v in genesis['alloc'].items()}
    storage = {k.lower(): v for k, v in alloc[pos.REGISTRY.lower().removeprefix('0x')]['storage'].items()}
    word = storage.get(slot)
    if not word or int(word, 16) == 0:
        raise ValueError('genesisCommitment is not set in the registry storage of the finalized genesis')
    return '0x' + word.lower().removeprefix('0x').rjust(64, '0')

def funded_base_genesis(chain_id, max_gas, alloc, entropy):
    """The standard genesis the registry is allocated into: the lanes' chain configuration, the profile's block gas limit and the package's funding."""
    return {'config': {'chainId': chain_id, 'homesteadBlock': 0, 'eip150Block': 0, 'eip155Block': 0, 'eip158Block': 0, 'byzantiumBlock': 0,
        'constantinopleBlock': 0, 'petersburgBlock': 0, 'istanbulBlock': 0, 'berlinBlock': 0, 'londonBlock': 0, 'mergeNetsplitBlock': 0,
        'shanghaiTime': 0, 'cancunTime': 0, 'terminalTotalDifficulty': 0, 'terminalTotalDifficultyPassed': True},
        'nonce': '0x0', 'timestamp': '0x0', 'extraData': '0x' + entropy, 'gasLimit': hex(max_gas), 'difficulty': '0x0',
        'mixHash': '0x' + '00' * 32, 'coinbase': '0x' + '00' * 20, 'baseFeePerGas': '0x3b9aca00', 'alloc': alloc}

def evm_partition_params(chain_id):
    return f'proof_type=exec,chain_id={chain_id},continuity_max_distance={EVM_CONTINUITY_MAX_DISTANCE}'

# The one aggregator (owner decision 40): aggregator-go, partition 7 (the protocol constant every aggregator-go verifier requires) as one full-range shard, a single instance without high availability, its state in MongoDB.
AGGREGATOR_PORT, AGGREGATOR_BFT_PORT = 8080, 9200   # in validator 1's namespace beside its root (8000, 8002), shard node (9000, 9101) and metrics relay (9102)
# aggregator-go needs MongoDB as a replica set (transactions and change streams): one member, initiated by the healthcheck on its first run.
MONGO_REPLICA_SET = "try { quit(rs.status().myState === 1 ? 0 : 1) } catch (e) { rs.initiate({_id: 'rs0', members: [{_id: 0, host: 'mongo:27017'}]}); quit(1) }"

def aggregator_environment(root_boot, rpc_bind):
    """aggregator-go reads its configuration from the environment. One full-range shard runs SHARDING_MODE=standalone with BFT (aggregator-go refuses
    bft-shard mode for the empty shard ID, scripts/lib/agg-lib.sh). Its signing key is the shard-node key file; BFT_RPC_ADDRESS is root 1's operator
    endpoint, which serves the trust bases of later root epochs and is loopback-only: hence the aggregator shares validator 1's namespace."""
    return {'PORT':str(AGGREGATOR_PORT),'HOST':'0.0.0.0','ENABLE_DOCS':'false','ENABLE_CORS':'false',
        'MONGODB_URI':'mongodb://mongo:27017/?replicaSet=rs0','MONGODB_DATABASE':'aggregator','MONGODB_MAX_POOL_SIZE':'20',
        'DISABLE_HIGH_AVAILABILITY':'true','USE_REDIS_FOR_COMMITMENTS':'false','SMT_BACKEND':'memory','SHARDING_MODE':'standalone',
        'LOG_LEVEL':'info','LOG_FORMAT':'json','SIGNING_KEY_FILE':'/state/keys.json',
        'BFT_ENABLED':'true','BFT_ADDRESS':'/ip4/0.0.0.0/tcp/%d'%AGGREGATOR_BFT_PORT,'BFT_ANNOUNCE_ADDRESSES':'/dns4/aggregator/tcp/%d'%AGGREGATOR_BFT_PORT,
        'BFT_BOOTSTRAP_ADDRESSES':root_boot,'BFT_RPC_ADDRESS':'http://'+operator_rpc.listen(rpc_bind,operator_rpc.ROOT_PORT),
        'BFT_SHARD_CONF_FILE':'/network/aggregator-conf.json','BFT_TRUST_BASE_FILES':'/network/trust-base.json'}

def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')

def topology(out, n, ids, images, captcha, ureth_flags=(), max_gas=30000000, with_pos=False, rpc_bind=operator_rpc.DEFAULT_BIND):
    """JSON is a YAML subset, accepted directly by Docker Compose."""
    services = {}
    def service(name, image, command, mounts=(), memory='256m', cpu=0.5, networks=None, pod=None, **extra):
        # `pod`: the service joins the network namespace of that holder (network_mode), so it has no networks or DNS name of its own
        attach = {'network_mode':'service:'+pod} if pod else {'networks':networks or ['validators']}
        services[name] = dict(image=image, entrypoint=command, volumes=list(mounts), **attach, restart='unless-stopped',
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
        # One network namespace per validator ENTITY for its root and its shard node: the operator endpoints of both accept loopback peers only, so the existing
        # q3-readiness (which needs both) runs inside the entity's namespace. The holder owns the namespace and the DNS names, so recreating a root (the install
        # restart) or restarting the shard does not take the namespace down. Different entities stay in different namespaces; the authority (unix sockets), the
        # execution client and every other service keep their own.
        holder = {'validators':{'aliases':['root%d'%i,'shard%d'%i]}}
        if i == 1: holder = {'validators':{'aliases':['root1','shard1','aggregator']},'aggregator':{}}   # the aggregator's namespace, the only way to its MongoDB
        service('pod%d'%i, node, ['sleep','infinity'], memory='16m', cpu=0.05, networks=holder, init=True)   # sleep as PID 1 would ignore SIGTERM
        service('metrics%d'%i, images['rpc'], ['python3','-u','metrics_relay.py'], memory='64m', cpu=0.1, pod='pod%d'%i,
            environment={'ROOT_RPC':operator_rpc.listen(rpc_bind,operator_rpc.ROOT_PORT),'SHARD_RPC':operator_rpc.listen(rpc_bind,operator_rpc.SHARD_PORT)})
        service('root%d'%i, node, ['ubft','root-node','run','--home','/state','--address','/ip4/0.0.0.0/tcp/8000',
            '--bootnodes', ','.join('/dns4/root%d/tcp/8000/p2p/%s' % (j,ids['root'][j-1]) for j in range(1,n+1) if j!=i),
            '--profile-3','--q3-lane'] + (pos.root_flags(i) if with_pos else ['--genesis-identities','/network/genesis-identities.json']) + [
            '--shard-conf','/network/full-shard-conf.json','--shard-conf','/network/aggregator-conf.json',
            '--rpc-server-address',operator_rpc.listen(rpc_bind,operator_rpc.ROOT_PORT),'--metrics','prometheus'] + common,
            ['./validator%d/root:/state'%i,network,'./validator%d/jwt:/jwt:ro'%i], memory='384m', pod='pod%d'%i)   # the entity's Engine JWT, read-only: q3-readiness runs in the root (it holds the entity's keys.json) and checks its own Engine endpoint
        service('authority%d'%i, node, ['ubft','signing-authority','run','--home','/authority',
            '--client-socket','/authority/client.sock','--operator-socket','/authority/operator.sock',
            '--operator-credential','/authority/operator.cred','--authority-id','paired-evm-%d'%i,
            '--node-id',ids['evm'][i-1],'--network-id','3','--partition-id','8','--shard-id','0x80',
            '--shard-epoch','0','--root-epoch','1'] + common, [auth,network])
        # A new authority process has a new key. Never auto-restart this lifetime.
        services['authority%d'%i]['restart']='no'
        service('ureth%d'%i, node, ['unicity-reth','node','--chain','/network/genesis.json','--datadir','/state',
            '--authrpc.jwtsecret','/jwt/jwt.hex','--authrpc.addr','0.0.0.0','--authrpc.port','8551',
            '--http','--http.addr','0.0.0.0','--http.port','8545','--http.api','eth,net,web3,debug',   # debug: the paired shard node reads debug_getRawHeader for the parent registry witness (without it no validator can lead a round after the first); the validator network is internal and the public gateway allow-lists methods
            '--rpc.eth-proof-window','64','--disable-discovery','--ipcdisable',
            '--log.file.max-files','0',   # no log file: the root filesystem is read-only (reth wants $HOME/.cache/reth/logs) and Docker's json-file driver already rotates stdout
            '--engine.persistence-threshold','64','--builder.gaslimit',str(max_gas),'--unicity.fee-collector',FEE,*ureth_flags],
            ['./validator%d/ureth:/state'%i,'./validator%d/jwt:/jwt:ro'%i,network], memory='1536m',cpu=1.0)
        peers = root_boot + ''.join(',/dns4/shard%d/tcp/9000/p2p/%s'%(j,ids['evm'][j-1]) for j in range(1,n+1) if j!=i)
        service('shard%d'%i, node, ['ubft','shard-node','run','--home','/state','--executor','engine-api',
            '--address','/ip4/0.0.0.0/tcp/9000','--bootnodes',peers,
            '--full-shard-conf','/network/full-shard-conf.json','--genesis','/network/genesis.json',
            '--engine-url','http://ureth%d:8551'%i,'--eth-url','http://ureth%d:8545'%i,
            '--jwt-secret','/jwt/jwt.hex','--engine-fee-collector',FEE,'--b1-profile','/network/b1-profile.json','--q3-lane',
            '--execution-journal','/state/execution-journal.db','--archive-store','/archive',
            '--archive-prune','--journal-candidates','32','--trust-history-profile-2','--rpc-server-address',operator_rpc.listen(rpc_bind,operator_rpc.SHARD_PORT),'--metrics','prometheus',
            '--signing-authority-socket','/authority/client.sock','--signing-authority-credential','/authority/client.cred']
            + common,   # no --archive-replica: the node derives its replicas from the shard's validators (the next three in peer-ID order, any two make a block durable)
            [evm,auth,network,'./validator%d/jwt:/jwt:ro'%i,'./validator%d/archive:/archive'%i],memory='512m',cpu=0.75,pod='pod%d'%i)
    # The aggregator's signing key stays in its private key file (aggregator/keys.json, read-only mount): nothing secret is in its environment or this manifest.
    # mongod runs directly as the package UID (the image's entrypoint would switch users, which cap_drop ALL forbids); /tmp is the writable HOME of mongosh.
    # It has no authentication: it is reachable only on its own internal network, which only validator 1's namespace (the aggregator's) joins.
    service('mongo',PINS['mongo'],['mongod','--replSet','rs0','--bind_ip_all','--port','27017','--dbpath','/data/db','--wiredTigerCacheSizeGB','0.25'],
        ['./mongo:/data/db'],memory='768m',cpu=0.5,networks=['aggregator'],user='10001:10001',environment={'HOME':'/tmp'},
        healthcheck={'test':['CMD','mongosh','--quiet','--eval',MONGO_REPLICA_SET],'interval':'10s','timeout':'10s','retries':12,'start_period':'20s'})
    services['mongo']['pids_limit']=256   # mongod runs ~85 threads idle, plus one per connection (the aggregator's pool is 20)
    services['mongo']['tmpfs'].append('/data/configdb:size=1m,mode=1777')   # the image declares it a volume: unused here, and no anonymous volume per recreate
    services['mongo']['stop_grace_period']='30s'   # a clean mongod shutdown before backup.py archives the stopped generation
    service('aggregator',node,['aggregator'],['./aggregator:/state:ro',network],memory='512m',cpu=0.75,pod='pod1',
        environment=aggregator_environment(root_boot,rpc_bind),depends_on={'mongo':{'condition':'service_healthy'}})
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
        'networks':{'validators':{'internal':True},'aggregator':{'internal':True},'faucet':{'ipam':{'config':[{'subnet':'172.30.88.0/24','gateway':'172.30.88.1'}]}},'edge':{'ipam':{'config':[{'subnet':'172.30.89.0/24','gateway':'172.30.89.1'}]}}},
        'secrets':{'faucet_keystore':{'file':'./faucet-secrets/keystore.json'},'faucet_password':{'file':'./faucet-secrets/password'},
                   'hcaptcha_secret':{'file':'./faucet-secrets/hcaptcha-secret'}}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    p.add_argument('--validators',type=int,default=4)
    p.add_argument('--chain-id',type=int,default=31337)
    p.add_argument('--ubft',type=Path,default=REPO/'build/ubft')
    p.add_argument('--b1genesis',type=Path,default=REPO/'build/b1genesis',help='scripts/b1genesis built from the pinned BFT source: independent regeneration of the genesis registry')
    p.add_argument('--keygen',type=Path,default=REPO/'build/tn-keygen')
    p.add_argument('--images',type=Path,default=HERE/'artifacts/images.json')
    p.add_argument('--offline-validation',action='store_true',help='native ceremony with fixture images; output CANNOT be deployed')
    p.add_argument('--pos',action='store_true',help='the proof-of-stake profile: the contracts genesis (custody, election, evidence) in the EVM genesis, the roots on the P85 flags')
    p.add_argument('--pos-contracts',type=Path,help='a clean unicity-pos-contracts checkout at the pinned commit (needs forge on PATH)')
    p.add_argument('--rpc-bind',default=operator_rpc.DEFAULT_BIND,help='bind address of the root and shard operator RPC listeners; loopback only (default 127.0.0.1): they have no authentication')
    p.add_argument('--pos-weights',default=None,help='proof-of-stake genesis weights, comma separated, one per validator (default all 1; the genesis rules accept only 1, see pos.genesis_weights)')
    p.add_argument('--pos-cadence-rounds',type=int,default=pos.CADENCE_ROUNDS,help='election cadence: ordinary root rounds after the last acknowledged rotation')
    p.add_argument('--pos-cadence-seconds',type=int,default=pos.CADENCE_SECONDS,help='election cadence: UC seconds after the last acknowledged rotation')
    p.add_argument('--captcha-sitekey',required=True)
    p.add_argument('--captcha-secret-file',required=True,type=Path)
    a=p.parse_args()
    if a.pos and a.pos_contracts is None: p.error('--pos needs --pos-contracts')
    try: operator_rpc.check_bind(a.rpc_bind)
    except operator_rpc.BindError as e: p.error(str(e))
    if a.pos_weights is not None and not a.pos: p.error('--pos-weights needs --pos')
    weights=None
    if a.pos:
        try: weights=pos.genesis_weights(a.validators,None if a.pos_weights is None else a.pos_weights.split(','))   # refused before any key is generated
        except (pos.PosError,ValueError) as e: p.error(str(e))
    if a.pos and a.validators > pos.CAPS[2]:   # the hook gas and the election were measured for at most nMax members: more genesis identities are outside what the guard checked
        p.error(f'--pos with {a.validators} validators: the caps (vMax,lMax,nMax = {",".join(map(str,pos.CAPS))}) cover at most {pos.CAPS[2]} genesis identities; the hook-gas guard measured nothing above that')
    if not 3 <= a.validators <= 16:
        p.error(f'validators must be 3..16, got {a.validators}: the registry admits at most 16 committee members and a genesis with more fails')
    if not 0 < a.chain_id < 2**53:
        p.error('chain ID must be 1..2^53-1')
    out=a.out.resolve()
    if not re.fullmatch(r'tn-[a-z0-9][a-z0-9_-]*',out.name): p.error('generation directory name must be tn- followed by lowercase letters/digits/dashes')
    if out.exists(): p.error('output exists: choose a new generation directory')
    records=json.loads(a.images.read_text())
    if records['sources'] != PINS: p.error('image source pins differ')
    if any(not re.fullmatch(r'sha256:[0-9a-f]{64}',records['images'].get(k,'')) for k in ('node','guard','signer','rpc')):
        p.error('images must be immutable local image IDs from build-images.py')
    ubft=str(a.ubft.resolve())
    for tool in (ubft,str(a.b1genesis.resolve())):
        version=subprocess.check_output(['go','version','-m',tool],text=True)
        if 'vcs.revision='+PINS['bft'] not in version or 'vcs.modified=true' in version:
            p.error(f'{Path(tool).name} must be built from clean pinned BFT source')
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
                '--shard-id','0x80','--epoch-start','1','--t2-timeout','5000','--partition-params',evm_partition_params(a.chain_id),
                *sum((['--node-info',out/f'validator{i}/auth/node-info.json'] for i in range(1,a.validators+1)),[]))
            # One B1 profile, then a genesis allocated from it (permanent registry layout), funded with the package's random faucet and unique entropy.
            trust=home/'trust-base.json'
            genesis=None
            if a.pos:
                # The first pass runs on the base configuration (the full one does not exist yet): provisional, its id is replaced after the reconciling finalization.
                genesis=pos.Genesis(home,ubft,a.pos_contracts.resolve(),REPO,out.name,a.chain_id,tuple(map(int,EVM_CONTINUITY_MAX_DISTANCE.split('/'))),(a.pos_cadence_rounds,a.pos_cadence_seconds))
                genesis.check_tools(PINS['contracts'])
                # Owner, withdrawal and payee keys for every genesis identity, generated here and never shipped in network/ (the addresses are in pos-plan.json).
                owners=json.loads(subprocess.check_output([str(a.keygen.resolve()),'owners',str(home/'pos-owner-keys'),str(a.validators)],text=True))
                genesis.plan(trust,home/'shard-conf-8_0.json',owners,weights)
                genesis.prepare(home/'shard-conf-8_0.json',provisional=True)
            profile_out=cli('engine-api','b1-profile','--shard-conf',home/'shard-conf-8_0.json','--trust-base',trust,'--max-epochs-per-update',MAX_EPOCHS,'--delta-ev',DELTA_EV,'--delta-hold',DELTA_HOLD,'--out',home/'b1-profile.json',
                *(pos.profile_args(genesis.deployment,{'election':genesis.dir/'elect-measurement.json','hook':genesis.dir/'hook-measurement.jsonl'}) if genesis else []))
            if genesis: print(genesis.check_hook_gas(home/'b1-profile.json'))
            flags=ureth_flags_of(profile_out)
            max_gas=int(json.loads((home/'b1-profile.json').read_text())['maxGas'])
            alloc=json.loads(subprocess.check_output([str(a.keygen.resolve()),str(home/'faucet-secrets')],text=True))
            write(home/'funded.json',funded_base_genesis(a.chain_id,max_gas,alloc,secrets.token_hex(32)))
            if genesis:
                # The id of the custody genesis is the FULL configuration's: finalize once without the PoS accounts, take the id from that configuration, then add the accounts.
                cli('engine-api','genesis','--shard-conf',home/'shard-conf-8_0.json','--trust-base',trust,'--b1-profile',home/'b1-profile.json',
                    '--alloc-source',home/'funded.json','--out',genesis.dir/'reconcile-genesis.json','--full-shard-conf',genesis.dir/'reconcile-full-shard-conf.json',
                    '--identities-out',genesis.dir/'reconcile-b1-identities.json')
                genesis.reconcile(genesis.dir/'reconcile-full-shard-conf.json')
                funded=json.loads((home/'funded.json').read_text())
                write(home/'funded.json',pos.merge_alloc(funded,json.loads((genesis.dir/'genesis/alloc.json').read_text())))
            identity=cli('engine-api','genesis','--shard-conf',home/'shard-conf-8_0.json','--trust-base',trust,'--b1-profile',home/'b1-profile.json',
                '--alloc-source',home/'funded.json','--out',home/'genesis.json','--full-shard-conf',home/'full-shard-conf.json',
                '--identities-out',home/'b1-identities.json')
            print(identity)
            # The roots' committee identity records (a JSON array, what `root-node run --genesis-identities` takes): the PoA genesis committee, root i delegated
            # to EVM validator i, as scripts/lib/h3-lib.sh makes them. b1-identities.json is the B1 identity document (an object) the bridge deployment is checked against.
            if genesis:
                genesis.verify(home/'full-shard-conf.json',genesis.dir/'reconcile-full-shard-conf.json')
            write(home/'genesis-bindings.json',[{'rootNodeId':roots[i],'evmNodeId':evms[i]} for i in range(a.validators)])
            cli('genesis-identities','generate','--trust-base',trust,'--shard-conf',home/'full-shard-conf.json','--bindings',home/'genesis-bindings.json',
                '--out',home/'genesis-identities.json')
            # The deployed registry must be exactly what the pinned source regenerates from the profile, the trust base and the base shard configuration.
            verified=subprocess.run([str(a.b1genesis.resolve()),'--verify',str(home/'genesis.json'),'--profile',str(home/'b1-profile.json'),
                '--root-genesis',str(trust),'--shard-conf',str(home/'full-shard-conf.json')],text=True,capture_output=True)
            if verified.returncode!=0 or 'the deployed registry account matches the regeneration' not in verified.stdout:
                raise RuntimeError('b1genesis --verify: the genesis registry differs from its regeneration\n'+verified.stdout+verified.stderr)
            print(verified.stdout)
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
        # No proof_type: aggregator-go sends no SMT consistency proof, and the root's aggregator_rsmt_v1 verifier would refuse every nonempty request
        # (docs/operations/dnb/stage2-live-round-trip.md finding 2). The root checks the aggregator's signature only, as in the DN-B lanes (README).
        cli('shard-conf','generate','--home',home/'agg-conf','--network-id','3','--partition-id','7','--partition-type-id','7',
            '--shard-id','0x80','--epoch','0','--epoch-start','1','--t2-timeout','5000','--node-info',out/'aggregator/node-info.json')
        # The PoS roots take pos-genesis-identities.json instead (the two flags exclude each other): the PoA records are not shipped beside them.
        for name in ('trust-base.json','full-shard-conf.json','genesis.json','b1-profile.json','b1-identities.json')+(() if genesis else ('genesis-identities.json',)):
            shutil.copy2(home/name,out/'network'/name)
        if genesis:
            # What the roots start with, and what an operator needs to run `pos-relayer verify-genesis` again on the shipped files.
            write(out/'network/pos-deployment.json',pos.deployment_of(genesis.deployment,json.loads((home/'b1-profile.json').read_text())))
            for name,src in (('pos-genesis-identities.json','genesis-identities.json'),('pos-plan.json','plan.json'),('pos-contracts-genesis.json','contracts-genesis.json')):
                shutil.copy2(genesis.dir/src,out/'network'/name)
            (out/'network/pos-genesis-assignment.txt').write_text(genesis.assignment+'\n')
            genesis.alloc_code_hashes(json.loads((home/'genesis.json').read_text()))
        shutil.copy2(home/'agg-conf/shard-conf-7_0.json',out/'network/aggregator-conf.json')
        for i in range(1,a.validators+1):
            val=out/f'validator{i}'
            for kind in ('root','evm'):
                src=home/f'{kind}{i}'
                for sock in src.glob('*.sock'): sock.unlink()
                shutil.move(str(src),val/kind)
            for kind in ('ureth','archive','jwt'): (val/kind).mkdir()
            (val/'jwt/jwt.hex').write_text(secrets.token_hex(32)+'\n')
        shutil.move(str(home/'faucet-secrets'),out/'faucet-secrets')
        if genesis: shutil.move(str(home/'pos-owner-keys'),out/'pos-owner-keys')   # private host material, like faucet-secrets: not mounted, not in network/
        shutil.copy2(a.captcha_secret_file,out/'faucet-secrets/hcaptcha-secret')
        (out/'claims').mkdir()
        (out/'mongo').mkdir()
        (out/'metrics').mkdir()
        (out/'monitoring').mkdir()
        write(out/'monitoring/prometheus.json', {'global':{'scrape_interval':'15s'},'rule_files':['/etc/prometheus/alerts.json'],
            # the operator listeners are loopback-only: the pod's metrics relay serves the two metrics documents (exact paths, GET) on 9102
            'scrape_configs':[{'job_name':'root','metrics_path':'/root/metrics',
                'static_configs':[{'targets':[f'pod{i}:9102' for i in range(1,a.validators+1)]}]},
                {'job_name':'shard','metrics_path':'/shard/metrics','static_configs':[{'targets':[f'pod{i}:9102' for i in range(1,a.validators+1)]}]},
                {'job_name':'rpc','static_configs':[{'targets':['rpc:9090']}]}]})
        write(out/'monitoring/alerts.json', {'groups':[{'name':'testnet','rules':[
            {'alert':'TestnetTargetDown','expr':'up == 0','for':'1m','labels':{'severity':'page'},'annotations':{'summary':'Testnet target unavailable; contact duty operator'}},
            {'alert':'TestnetRPCFailures','expr':'increase(tn_rpc_upstream_errors_total[5m]) > 0','labels':{'severity':'warning'},'annotations':{'summary':'RPC identity or upstream failures'}}]}]})
        network=json.loads((HERE/'faucet/network.example.json').read_text())
        network.update(chain_id=a.chain_id,genesis_hash='0x'+block,funding_address=next(iter(alloc)),
            validator_rpc_urls=[f'http://ureth{i}:8545' for i in range(1,a.validators+1)],captcha_sitekey=a.captcha_sitekey)
        write(out/'network/network.json',network)
        flags=[*flags,'--unicity.genesis-commitment='+genesis_commitment(json.loads((home/'genesis.json').read_text()))]
        write(out/'compose.yaml',topology(out,a.validators,{'root':roots,'evm':evms},records['images'],a.captcha_sitekey,flags,max_gas,bool(genesis),a.rpc_bind))
        manifest={'offline_validation_only':a.offline_validation,'generation':out.name,'chain_id':a.chain_id,'genesis_hash':'0x'+block,'validators':a.validators,'operator_rpc':{'bind':a.rpc_bind,'root_port':operator_rpc.ROOT_PORT,'shard_port':operator_rpc.SHARD_PORT},
            'faucet_address':next(iter(alloc)), 'artifacts':records,
            'pos':({'genesis_assignment':genesis.assignment,'first_pass_assignment':genesis.first,'custody':genesis.deployment['custody'],'election':genesis.deployment['election'],
                    'contracts':PINS['contracts'],'owner_keys':'pos-owner-keys','cadence_rounds':a.pos_cadence_rounds,'cadence_seconds':a.pos_cadence_seconds} if genesis else None),
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
