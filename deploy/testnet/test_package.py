import http.client
import json
import os
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import gateway
import generate
import pos
import handoff

class FakeRelay:
    def __init__(self): self.calls=[]
    def call(self, method, params):
        self.calls.append((method,params))
        return {'jsonrpc':'2.0','id':1,'result':'0x1'}

class ChurnBudget(unittest.TestCase):
    def test_the_generated_evm_configuration_commits_the_testnet_churn_budget(self):
        params=dict(item.split('=',1) for item in generate.evm_partition_params(1337).split(','))
        self.assertEqual(params,{'proof_type':'exec','chain_id':'1337','continuity_max_distance':'1/2'})
        num,den=params['continuity_max_distance'].split('/')
        self.assertEqual((int(num),int(den)),(1,2))
    def test_the_generator_passes_exactly_those_params_to_shard_conf_generate(self):
        source=(generate.HERE/'generate.py').read_text()
        self.assertEqual(source.count("evm_partition_params(a.chain_id)"),1)
        self.assertNotIn("f'proof_type=exec,chain_id=",source.split('def main')[1])

class B1Layout(unittest.TestCase):
    def test_the_package_is_on_the_single_b1_layout(self):
        source=(generate.HERE/'generate.py').read_text()
        self.assertNotIn('registry-layout',source)
        self.assertEqual(source.count("'--b1-profile'"),3)   # the genesis, the PoS profile's reconciling genesis, and the shard nodes: one profile is the source of all
        self.assertEqual(generate.ureth_flags_of('x\nureth flags: --unicity.a 1 --unicity.b 0xab\ny\n'),['--unicity.a','1','--unicity.b','0xab'])
        for bad in ('', 'ureth flags:\n', 'ureth flags: --a\nureth flags: --b\n'):
            with self.assertRaises(ValueError): generate.ureth_flags_of(bad)
    def test_the_genesis_carries_the_profile_gas_limit_and_the_funding(self):
        g=generate.funded_base_genesis(1337,60000000,{'ab':{'balance':'0x1'}},'cd'*32)
        self.assertEqual((g['config']['chainId'],int(g['gasLimit'],16),g['alloc'],g['extraData']),(1337,60000000,{'ab':{'balance':'0x1'}},'0x'+'cd'*32))
    def test_the_workflow_builds_the_pinned_source_and_the_verifier(self):
        workflow=(generate.REPO/'.github/workflows/testnet-package.yml').read_text()
        self.assertIn('ref: '+generate.PINS['bft'],workflow)
        self.assertIn('./scripts/b1genesis',workflow)
        self.assertIn('ref: '+generate.PINS['contracts'],workflow)   # the PoS profile's contracts checkout
        self.assertIn('--pos-contracts pinned-contracts',workflow)
    def test_the_topology_follows_the_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'tn-fixture';out.mkdir();(out/'aggregator').mkdir()
            (out/'aggregator/keys.json').write_text(json.dumps({'authKey':{'privateKey':'0x01'},'sigKey':{'privateKey':'0x02'}}))
            images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
            cfg=generate.topology(out,3,{'root':['r%d'%i for i in range(3)],'evm':['e%d'%i for i in range(3)]},images,'captcha',['--unicity.network-id','3'],123456)
            for i in (1,2,3):
                svc=cfg['services']
                self.assertEqual(svc['ureth%d'%i]['entrypoint'][-2:],['--unicity.network-id','3'])
                self.assertEqual(svc['ureth%d'%i]['entrypoint'][svc['ureth%d'%i]['entrypoint'].index('--builder.gaslimit')+1],'123456')
                shard=svc['shard%d'%i]['entrypoint']
                self.assertEqual(shard[shard.index('--b1-profile')+1],'/network/b1-profile.json')
                self.assertIn('--q3-lane',shard);self.assertNotIn('--registry-layout',shard)
                root=svc['root%d'%i]['entrypoint']
                self.assertIn('--q3-lane',root);self.assertEqual(root[root.index('--genesis-identities')+1],'/network/genesis-identities.json')

class ProofOfStake(unittest.TestCase):
    ID1='0x'+'11'*32
    ID2='0x'+'22'*32
    def test_the_assignment_id_is_read_from_the_single_line_the_tool_prints(self):
        self.assertEqual(pos.assignment_id('x\ngenesis assignment id '+self.ID1+'\n'),self.ID1)
        for bad in ('','genesis assignment id 0x12\n','genesis assignment id %s\ngenesis assignment id %s\n'%(self.ID1,self.ID2)):
            with self.assertRaises(pos.PosError): pos.assignment_id(bad)
    def test_the_pos_accounts_never_overwrite_the_funding(self):
        g={'alloc':{'ABCD':{'balance':'0x1'}}}
        self.assertEqual(pos.merge_alloc(g,{'0x1234':{'code':'0x00'}})['alloc']['0x1234'],{'code':'0x00'})
        for clash in ('0xabcd','0xABCD','abcd'):
            with self.assertRaises(pos.PosError): pos.merge_alloc({'alloc':{'ABCD':{}}},{clash:{}})
    def test_the_deployment_file_and_profile_flags_follow_the_contracts_deployment(self):
        d={'networkWord':'0xaa','chainId':31337,'custody':'0xc','custodyCodeHash':'0xch','election':'0xe','electionCodeHash':'0xeh'}
        self.assertEqual(pos.deployment_of(d,{'runtimeHash':'0xrh'}),{'networkWord':'0xaa','chainId':'31337','custody':'0xc','custodyCodeHash':'0xch',
            'registry':pos.REGISTRY,'registryCodeHash':'0xrh','election':'0xe','electionCodeHash':'0xeh'})
        args=pos.profile_args(d,'/m.json')
        self.assertEqual((args[args.index('--records-custody')+1],args[args.index('--election')+1],args[args.index('--elect-caps')+1]),('0xc','0xe','16,2,8'))
    def test_the_topology_runs_the_roots_on_the_pos_flags_and_not_the_poa_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'tn-fixture';out.mkdir();(out/'aggregator').mkdir()
            (out/'aggregator/keys.json').write_text(json.dumps({'authKey':{'privateKey':'0x01'},'sigKey':{'privateKey':'0x02'}}))
            images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
            ids={'root':['r%d'%i for i in range(3)],'evm':['e%d'%i for i in range(3)]}
            for with_pos in (False,True):
                cfg=generate.topology(out,3,ids,images,'captcha',(),30000000,with_pos)
                for i in (1,2,3):
                    root=cfg['services']['root%d'%i]['entrypoint']
                    self.assertIn('--q3-lane',root);self.assertIn('--profile-2',root)
                    if with_pos:
                        self.assertEqual(root[root.index('--pos-deployment')+1],'/network/pos-deployment.json')
                        self.assertEqual(root[root.index('--pos-genesis-identities')+1],'/network/pos-genesis-identities.json')
                        self.assertEqual(root[root.index('--pos-evm-rpc')+1],'http://ureth%d:8545'%i)
                        self.assertNotIn('--genesis-identities',root)
                    else:
                        self.assertNotIn('--pos-deployment',root);self.assertIn('--genesis-identities',root)
    def test_the_contracts_checkout_must_be_clean_at_the_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)/'contracts';(repo/'script').mkdir(parents=True);(repo/'script/p85-genesis.sh').write_text('#!/bin/sh\n')
            git=lambda *a:subprocess.run(['git','-C',str(repo),*a],check=True,capture_output=True,text=True)
            git('init','-q');git('-c','user.name=t','-c','user.email=t@t','add','-A');git('-c','user.name=t','-c','user.email=t@t','commit','-qm','x')
            head=git('rev-parse','HEAD').stdout.strip()
            genesis=pos.Genesis(Path(tmp)/'work','ubft',repo,generate.REPO,'tn-x',1,(1,2))
            with patch('pos.shutil.which',return_value='/bin/forge'):
                genesis.check_tools(head)
                with self.assertRaisesRegex(pos.PosError,'pinned commit'): genesis.check_tools('0'*40)
                (repo/'script/dirty').write_text('x')
                with self.assertRaisesRegex(pos.PosError,'modified'): genesis.check_tools(head)
            with patch('pos.shutil.which',return_value=None):
                with self.assertRaisesRegex(pos.PosError,'forge'): genesis.check_tools(head)
    def test_the_genesis_is_prepared_again_from_the_full_configuration_when_the_ids_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2))
            calls=[]
            def run(*args,**kw):
                class R: stderr='genesis assignment id '+self.ID2
                return R
            def prepare(conf,provisional):
                calls.append((str(conf),provisional));genesis.assignment=self.ID2;return genesis.assignment
            genesis.assignment=genesis.first=self.ID1;genesis.trust_base=Path('tb')
            with patch.object(genesis,'_run',side_effect=run),patch.object(genesis,'prepare',side_effect=prepare):
                self.assertEqual(genesis.reconcile('full.json'),self.ID2)
            self.assertEqual(calls,[('full.json',False)])
            genesis.assignment=self.ID2;calls.clear()
            with patch.object(genesis,'_run',side_effect=run),patch.object(genesis,'prepare',side_effect=prepare):
                genesis.reconcile('full.json')
            self.assertEqual(calls,[],'an id that already is the full configuration\'s is not prepared again')
            genesis.assignment=self.ID1
            with patch.object(genesis,'_run',side_effect=run),patch.object(genesis,'prepare',side_effect=lambda c,provisional:setattr(genesis,'assignment',self.ID1)):
                with self.assertRaisesRegex(pos.PosError,'carries'): genesis.reconcile('full.json')
    def test_verify_refuses_a_changed_full_configuration_and_an_unconfirmed_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,b=Path(tmp)/'a.json',Path(tmp)/'b.json';a.write_text('1');b.write_text('2')
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2));genesis.assignment=self.ID1;genesis.trust_base=Path('tb')
            class R: stderr="genesis assignment %s is the full shard configuration's\n"%self.ID1
            with patch.object(genesis,'_run',return_value=R):
                with self.assertRaisesRegex(pos.PosError,'changed after'): genesis.verify(a,b)
                self.assertEqual(genesis.verify(a,a),self.ID1)
            class Other: stderr="genesis assignment %s is the full shard configuration's\n"%self.ID2
            with patch.object(genesis,'_run',return_value=Other):
                with self.assertRaisesRegex(pos.PosError,'did not confirm'): genesis.verify(a,a)

    def test_a_second_contracts_genesis_that_deploys_elsewhere_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2));genesis.trust_base=Path('tb')
            deployed={'custody':'0xc','custodyCodeHash':'0x1','election':'0xe','electionCodeHash':'0x2','assignmentId':self.ID1}
            def run(*args,**kw):
                class R: stderr='genesis assignment id '+self.ID1;stdout='{}'
                if str(args[0]).endswith('p85-genesis.sh'):
                    (genesis.dir/'genesis').mkdir(exist_ok=True);(genesis.dir/'genesis/deployment.json').write_text(json.dumps(deployed))
                return R
            with patch.object(genesis,'_run',side_effect=run):
                genesis.prepare('base.json',provisional=True)
                deployed['assignmentId']=self.ID2;deployed['manifestHash']='0x9'   # the id and the manifest hash over it may differ
                genesis.prepare('full.json',provisional=False)
                deployed['custody']='0xd'                  # an address may not
                with self.assertRaisesRegex(pos.PosError,'custody'): genesis.prepare('full.json',provisional=False)
    def test_the_owner_keys_replace_the_hash_derived_addresses_and_must_cover_every_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2))
            tb,conf=Path(tmp)/'tb.json',Path(tmp)/'conf.json'
            tb.write_text(json.dumps({'rootNodes':[{'nodeId':'r1','sigKey':'k1'},{'nodeId':'r2','sigKey':'k2'}]}))
            conf.write_text(json.dumps({'validators':[{'nodeId':'e1','sigKey':'q1'},{'nodeId':'e2','sigKey':'q2'}]}))
            owners=[{'stakingId':i,'owner':'0xo%d'%i,'withdrawal':'0xw%d'%i,'payee':'0xp%d'%i} for i in (1,2)]
            genesis.plan(tb,conf,owners)
            rows=json.loads((genesis.dir/'plan.json').read_text())['identities']
            self.assertEqual([(r['owner'],r['withdrawal'],r['payee'],r['rootNodeId']) for r in rows],[('0xo1','0xw1','0xp1','r1'),('0xo2','0xw2','0xp2','r2')])
            other=pos.Genesis(Path(tmp)/'work2','ubft',tmp,generate.REPO,'tn-x',1,(1,2))
            with self.assertRaisesRegex(pos.PosError,'one to one'): other.plan(tb,conf,owners[:1])
            hashed=pos.Genesis(Path(tmp)/'work3','ubft',tmp,generate.REPO,'tn-x',1,(1,2));hashed.plan(tb,conf)
            self.assertNotEqual(json.loads((hashed.dir/'plan.json').read_text())['identities'][0]['owner'],'0xo1')
    def test_the_code_hash_is_taken_from_the_code_the_genesis_carries(self):
        genesis={'alloc':{'0xAA':{'code':'0x6001'},'0xbb':{'balance':'0x1'}}}
        class R: returncode=0;stdout='0xABCD\n';stderr=''
        with patch('pos.subprocess.run',return_value=R) as run:
            self.assertEqual(pos.code_hash(genesis,'0xaa'),'0xabcd');self.assertEqual(run.call_args[0][0],['cast','keccak','0x6001'])
        for address in ('0xbb','0xcc'):
            with self.assertRaisesRegex(pos.PosError,'no code'): pos.code_hash(genesis,address)
        d=pos.Genesis.__new__(pos.Genesis);d.deployment={'custody':'0xaa','custodyCodeHash':'0xdead','election':'0xaa','electionCodeHash':'0xabcd'}
        with patch('pos.subprocess.run',return_value=R):
            with self.assertRaisesRegex(pos.PosError,'custody code'): d.alloc_code_hashes(genesis)

class Handoff(unittest.TestCase):
    def test_the_install_override_adds_the_flag_to_every_root_and_nothing_else(self):
        compose={'services':{'root1':{'entrypoint':['ubft','root-node','run'],'volumes':['x']},'root2':{'entrypoint':['ubft','root-node','run']},
                             'shard1':{'entrypoint':['ubft','shard-node']},'root':{'entrypoint':['x']}}}
        override=handoff.install_override(compose,2)
        self.assertEqual(override,{'services':{'root1':{'entrypoint':['ubft','root-node','run','--install-handoff-epoch','2']},
                                                'root2':{'entrypoint':['ubft','root-node','run','--install-handoff-epoch','2']}}})
        self.assertEqual(compose['services']['root1']['entrypoint'],['ubft','root-node','run'],'the generated compose file is not modified')
        with self.assertRaisesRegex(ValueError,'below epoch 2'): handoff.install_override(compose,1)
        with self.assertRaisesRegex(ValueError,'already installs'): handoff.install_override({'services':{'root1':{'entrypoint':['a','--install-handoff-epoch','2']}}},3)
        with self.assertRaisesRegex(ValueError,'no root'): handoff.install_override({'services':{'shard1':{'entrypoint':['a']}}},2)

class PublicRPC(unittest.TestCase):
    def setUp(self):
        self.relay=FakeRelay()
        self.server=gateway.Server(('127.0.0.1',0),gateway.Handler,self.relay)
        self.thread=threading.Thread(target=self.server.serve_forever)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.thread.join();self.server.server_close();self.server.pool.shutdown()
    def send(self, data):
        conn=http.client.HTTPConnection(*self.server.server_address,timeout=3)
        conn.request('POST','/',data,{'Content-Type':'application/json'})
        response=conn.getresponse(); status=response.status; result=json.loads(response.read());conn.close()
        return status,result
    def rpc(self, method):
        return self.send(json.dumps({'jsonrpc':'2.0','id':17,'method':method,'params':[]}))
    def test_public_preserves_id(self):
        status,result=self.rpc('eth_sendRawTransaction')
        self.assertEqual((status,result['id']),(200,17))
    def test_privileged_never_reaches_upstream(self):
        for method in ['admin_nodeInfo','engine_newPayloadV3','personal_sign','eth_sign','debug_traceTransaction','eth_sendTransaction']:
            self.assertEqual(self.rpc(method)[0],400)
        self.assertEqual(self.relay.calls,[])
    def test_malformed_batch_and_size(self):
        for body in ['{','[]','null',json.dumps([{'method':'eth_chainId'}]),json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_sendRawTransaction','params':['0x'+'ab'*gateway.MAX_BODY]})]:
            self.assertEqual(self.send(body)[0],400)
        self.assertEqual(self.relay.calls,[])
    def test_rate_limit(self):
        with patch('gateway.time.monotonic',return_value=self.server.window):
            for _ in range(10): self.assertEqual(self.rpc('eth_chainId')[0],200)
            self.assertEqual(self.rpc('eth_chainId')[0],429)
    def test_partial_broadcast_is_not_retried(self):
        with patch.object(self.relay,'call',side_effect=ValueError('partial')) as call:
            self.assertEqual(self.rpc('eth_sendRawTransaction')[0],503)
            self.assertEqual(call.call_count,1)

class Topology(unittest.TestCase):
    def test_private_pods_and_limits(self):
        for n in [3,4,7]:
            with tempfile.TemporaryDirectory() as tmp:
                out=Path(tmp)/'tn-fixture';out.mkdir();(out/'aggregator').mkdir()
                (out/'aggregator/keys.json').write_text(json.dumps({'authKey':{'privateKey':'0x01'},'sigKey':{'privateKey':'0x02'}}))
                images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
                cfg=generate.topology(out,n,{'root':['r%d'%i for i in range(n)],'evm':['e%d'%i for i in range(n)]},images,'captcha')
                for name,svc in cfg['services'].items():
                    self.assertIn('mem_limit',svc);self.assertGreater(svc['cpus'],0)
                    self.assertEqual(svc['restart'],'no' if name.startswith('authority') else 'unless-stopped')
                    self.assertEqual(svc['logging']['options']['max-file'],'3')
                    for port in svc.get('ports',[]): self.assertTrue(port.startswith('127.0.0.1:'))
                    if name.startswith(('root','shard','authority','ureth')): self.assertNotIn('ports',svc)
                # Compose overrides the image entrypoint: verify the actual invocation.
                script=Path(__file__).parent/'faucet/backend-entrypoint.sh'
                signer=cfg['services']['signer']['entrypoint']
                if signer[0]=='/app/backend-entrypoint.sh':
                    self.assertTrue(os.access(script,os.X_OK), 'direct entrypoint must be executable')
                else:
                    self.assertEqual(signer,['/bin/sh','/app/backend-entrypoint.sh'])
                    self.assertTrue(os.access(script,os.R_OK))
                for svc in cfg['services'].values():
                    command=svc['entrypoint']
                    if command[0].endswith('.sh'):
                        source=Path(__file__).parent/'faucet'/Path(command[0]).name
                        self.assertTrue(source.is_file() and os.access(source,os.X_OK),command)
                env=cfg['services']['aggregator']['environment']
                self.assertEqual(env['AGGREGATOR_CONSISTENCY_PROOF_MODE'],'rsmt')
                self.assertNotIn('AGGREGATOR_CONSISTENCY_PROOFS',env)
                if os.environ.get('TN_REQUIRE_COMPOSE')=='1':
                    # config needs no daemon; do not silently skip this check in CI.
                    generate.write(out/'compose.yaml',cfg)
                    subprocess.run(['docker','compose','-f',str(out/'compose.yaml'),'config','--quiet'],check=True)
                self.assertTrue(cfg['networks']['validators']['internal'])
                for i in range(1,n+1):
                    shard=cfg['services']['shard%d'%i]['entrypoint']
                    self.assertEqual(shard.count('--archive-replica'),2)
                    self.assertIn('--signing-authority-socket',shard)
                    self.assertIn('./validator%d/evm:/state'%i,cfg['services']['shard%d'%i]['volumes'])


class Restore(unittest.TestCase):
    def test_restore_integrity_and_path_refusal(self):
        import hashlib
        import subprocess
        import sys
        import tarfile
        import io
        import backup
        here=Path(__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'source';(source/'network').mkdir(parents=True)
            (source/'network/config.json').write_text('{}')
            (source/'manifest.json').write_text(json.dumps({'config_sha256':{'config.json':hashlib.sha256(b'{}').hexdigest()}}))
            archive=base/'safe.tar.gz'
            with tarfile.open(archive,'w:gz') as tar: tar.add(source,arcname='generation')
            digest=archive.with_suffix('.gz.sha256')
            digest.write_text(hashlib.sha256(archive.read_bytes()).hexdigest())
            target=base/'restored'
            backup.extract(archive,target)
            self.assertEqual((target/'network/config.json').read_text(),'{}')
            with self.assertRaises(ValueError): backup.extract(archive,target)
            digest.write_text('0'*64)
            with self.assertRaises(ValueError): backup.extract(archive,base/'corrupt')
            self.assertFalse((base/'corrupt').exists())
            with tarfile.open(archive,'w:gz') as tar:
                member=tarfile.TarInfo('generation/../../escape'); member.size=1
                tar.addfile(member,io.BytesIO(b'x'))
            digest.write_text(hashlib.sha256(archive.read_bytes()).hexdigest())
            with self.assertRaises(ValueError): backup.extract(archive,base/'unsafe')
            self.assertFalse((base/'unsafe').exists())

if __name__=='__main__': unittest.main()
