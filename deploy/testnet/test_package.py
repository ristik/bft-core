import re
import http.client
import http.server
import shutil
import sys
import json
import os
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import gateway
import operator_rpc
import generate
import pos
import metrics_relay
import handoff_ops
import handoff
import observe
import joiner
import pos_sample
import pos_crash

class FakeRelay:
    def __init__(self): self.calls=[]
    def call(self, method, params):
        self.calls.append((method,params))
        return {'jsonrpc':'2.0','id':1,'result':'0x1'}

class LaneKeysAreNotInherited(unittest.TestCase):
    def test_the_plan_key_variables_never_reach_the_deployment_environment(self):
        with patch.dict(os.environ, {'P85_PLAN_OWNER_KEYS': '/x', 'P85_PLAN_WITHDRAWAL_KEYS': '/y', 'P85_PLAN_KEEP': '1', 'P85_CHAIN_ID': '7'}):
            env = pos.clean_environ()
        self.assertNotIn('P85_PLAN_OWNER_KEYS', env)
        self.assertNotIn('P85_PLAN_WITHDRAWAL_KEYS', env)
        self.assertEqual((env['P85_PLAN_KEEP'], env['P85_CHAIN_ID']), ('1', '7'))

    def test_the_plan_subprocess_gets_the_cleaned_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2))
            tb,conf=Path(tmp)/'tb.json',Path(tmp)/'conf.json'
            tb.write_text(json.dumps({'rootNodes':[{'nodeId':'r1','sigKey':'k1'},{'nodeId':'r2','sigKey':'k2'}]}))
            conf.write_text(json.dumps({'validators':[{'nodeId':'e1','sigKey':'q1'},{'nodeId':'e2','sigKey':'q2'}]}))
            seen=[]
            real=subprocess.check_output
            def spy(cmd,**kw):
                seen.append(kw.get('env'))
                return real(cmd,**kw)
            with patch.dict(os.environ,{'P85_PLAN_OWNER_KEYS':'/x','P85_PLAN_PAYEE_KEYS':'/y','P85_CAST':'cast'}), patch.object(pos.subprocess,'check_output',spy):
                genesis.plan(tb,conf)
            self.assertEqual(len(seen),1)
            self.assertIsNotNone(seen[0],'the plan script inherited os.environ (no env= given)')
            self.assertFalse([k for k in seen[0] if k.startswith('P85_PLAN_') and k.endswith('KEYS')])
            self.assertEqual(seen[0].get('P85_CAST'),'cast')


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
            out=Path(tmp)/'tn-fixture';out.mkdir()
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

class Aggregator(unittest.TestCase):
    def test_the_workflows_build_the_pinned_aggregator_go(self):
        for name in ('testnet-package.yml','testnet-rehearsal.yml','testnet-bridge.yml'):
            workflow=(generate.REPO/'.github/workflows'/name).read_text()
            self.assertNotIn('rugregator',workflow,name)
            self.assertIn('repository: ristik/aggregator-go',workflow,name)
        self.assertIn('ref: '+generate.PINS['aggregator-go'],(generate.REPO/'.github/workflows/testnet-package.yml').read_text())
        self.assertNotIn('rugregator',(generate.HERE/'build-images.py').read_text()+(generate.HERE/'Dockerfile.node').read_text())
    def test_the_aggregator_partition_asks_for_no_consistency_proof(self):
        # aggregator-go sends none; under proof_type=aggregator_rsmt_v1 the root would refuse every nonempty certification request
        source=(generate.HERE/'generate.py').read_text()
        self.assertNotIn('proof_type=aggregator_rsmt_v1',source)
        call=source[source.index("cli('shard-conf','generate','--home',home/'agg-conf'"):]
        call=call[:call.index('\n',call.index("node-info.json"))]
        self.assertNotIn('--partition-params',call)
        # aggregator-go refuses any other partition (api.AggregationPartitionID, a protocol constant)
        self.assertIn("'--partition-id','7'",call)

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
        d={'networkWord':'0xaa','chainId':31337,'custody':'0xc','custodyCodeHash':'0xch','election':'0xe','electionCodeHash':'0xeh','rewardPool':'0xrp','rewardPoolCodeHash':'0xrph'}
        self.assertEqual(pos.deployment_of(d,{'runtimeHash':'0xrh'}),{'networkWord':'0xaa','chainId':'31337','custody':'0xc','custodyCodeHash':'0xch',
            'registry':pos.REGISTRY,'registryCodeHash':'0xrh','election':'0xe','electionCodeHash':'0xeh','rewardPool':'0xrp','rewardPoolCodeHash':'0xrph'})
        args=pos.profile_args(d,{'election':'/m.json','hook':'/h.jsonl'})
        self.assertEqual((args[args.index('--records-custody')+1],args[args.index('--election')+1],args[args.index('--elect-caps')+1]),('0xc','0xe','16,1,6'))
        self.assertEqual((args[args.index('--elect-measurement')+1],args[args.index('--hook-measurement')+1]),('/m.json','/h.jsonl'))
    def test_the_deployment_file_carries_exactly_the_fields_the_pinned_roots_and_relayer_read(self):
        # the pinned roots refuse unknown fields and the relayer's loadRewardPool needs the pool pair: the generated keys are the deployment struct's json keys
        go=(generate.REPO/'cli/ubft/cmd/pos_deployment.go').read_text()
        struct=go[go.index('type posDeploymentFile struct'):]
        keys=set(re.findall(r'`json:"(\w+)(?:,omitempty)?"`',struct[:struct.index('\n}')]))
        d={'networkWord':'0xaa','chainId':31337,'custody':'0xc','custodyCodeHash':'0xch','election':'0xe','electionCodeHash':'0xeh','rewardPool':'0xrp','rewardPoolCodeHash':'0xrph'}
        self.assertEqual(set(pos.deployment_of(d,{'runtimeHash':'0xrh'})),keys)
    def test_the_rehearsal_stages_are_methods_and_the_workflow_runs_it(self):
        import rehearse
        for name,method in rehearse.STAGES: self.assertTrue(callable(getattr(rehearse.Rehearsal,method)),name)
        self.assertIn('deploy/testnet/rehearse.py',(generate.REPO/'.github/workflows/testnet-rehearsal.yml').read_text())
    def test_the_pos_stages_are_methods_the_workflow_runs_and_the_default_list_excludes_them(self):
        import rehearse
        workflow=(generate.REPO/'.github/workflows/testnet-rehearsal.yml').read_text()
        for name,method in rehearse.POS_STAGES:
            self.assertTrue(callable(getattr(rehearse.Rehearsal,method)),name)
            self.assertIn(name,workflow)
            self.assertNotIn(name,[n for n,_ in rehearse.STAGES])   # the PoA generation has no registry: the default run must not name them
        self.assertIn('--pos-contracts pinned-contracts',workflow)
        self.assertIn('ref: ${{ steps.pins.outputs.contracts }}',workflow)
    def test_pos_owner_names_the_revert_selector_it_expects(self):
        import json,rehearse,pos_owner
        class Fake:   # the two helpers it needs: a selector table and an eth_call that fails with a given revert data
            cast='cast'
            def __init__(self,data): self.data=data
            def cast_run(self,*a):
                assert all(isinstance(x,str) for x in a),a   # subprocess takes strings only
                return '0xaaaaaaaa' if a[0]=='sig' else '0xcalldata'
            def rpc(self,body,ip): return 200,json.dumps({'error':{'data':self.data}})
            def expect(self,ok,what,detail=''):
                if not ok: raise rehearse.Failure(what)
        Fake.__module__=rehearse.__name__
        pos_owner.expect_reverts(Fake('0xaaaaaaaa00'),'NotOwner()','0x1','0x2','f()')
        pos_owner.expect_reverts(Fake('0xaaaaaaaa00'),'NotOwner()','0x1','0x2','f(uint256,address)',1,'0x3')   # a number argument (the first run failed on it)
        with self.assertRaises(rehearse.Failure): pos_owner.expect_reverts(Fake('0xbbbbbbbb'),'NotOwner()','0x1','0x2','f()')   # another error
        with self.assertRaises(rehearse.Failure): pos_owner.expect_reverts(Fake(''),'NotOwner()','0x1','0x2','f()')   # no revert at all
    def test_the_paired_client_gets_the_registry_genesis_commitment(self):
        # ureth requires --unicity.genesis-commitment (a required argument since 6e59b68c, still at the pinned ureth), and b1-profile does not print it
        slot='0x'+'ab'*32
        class Done: stdout=slot+'\n'
        real=generate.subprocess.run
        generate.subprocess.run=lambda *a,**k: Done()
        try:
            reg=pos.REGISTRY.lower().removeprefix('0x')
            word='0x'+'01'*32
            self.assertEqual(generate.genesis_commitment({'alloc':{pos.REGISTRY:{'storage':{slot.upper().replace('0X','0x'):word}}}}),word)
            self.assertEqual(generate.genesis_commitment({'alloc':{reg:{'storage':{slot:'0x5'}}}}),'0x'+'00'*31+'05')
            for bad in ({}, {slot:'0x0'}):
                with self.assertRaises(ValueError): generate.genesis_commitment({'alloc':{reg:{'storage':bad}}})
        finally: generate.subprocess.run=real
    def test_the_shadow_profile_has_the_hook_and_no_election(self):
        d={'custody':'0xc','election':'0xe'}
        args=pos.profile_args(d,{'election':'/m.json','hook':'/h.jsonl'},shadow=True)
        self.assertNotIn('--election',args);self.assertNotIn('--elect-measurement',args)
        self.assertEqual((args[args.index('--records-custody')+1],args[args.index('--hook-measurement')+1],args[args.index('--elect-caps')+1]),('0xc','/h.jsonl','16,1,6'))
        full=pos.profile_args(d,{'election':'/m.json','hook':'/h.jsonl'})
        self.assertEqual(sorted(set(full)-set(args)),sorted(['--election','--elect-measurement','0xe','/m.json']))
    def test_the_caps_are_covered_by_the_per_record_reservation(self):
        # the cold RecoveryAck: 2,281,165 for 6 members of one lot (3,629,888 for 8 members of 2 lots); the guard's margin is 1.25
        self.assertEqual(pos.CAPS,(16,1,6))
        self.assertLessEqual(2_281_165*125//100,pos.HOOK_RECORD_GAS)
        self.assertGreater(3_629_888*125//100,pos.HOOK_RECORD_GAS)
    def test_pos_refuses_more_validators_than_the_caps_cover_before_any_key(self):
        done=subprocess.run([sys.executable,str(Path(__file__).parent/'generate.py'),'--out','/nonexistent/tn-x','--validators',str(pos.CAPS[2]+1),'--ubft','x','--keygen','x','--b1genesis','x',
            '--images','x','--captcha-sitekey','a','--captcha-secret-file','x','--pos','--pos-contracts','x'],text=True,capture_output=True)
        self.assertEqual(done.returncode,2);self.assertIn('cover at most %d genesis identities'%pos.CAPS[2],done.stderr)
    def test_genesis_weights_default_to_one_and_nothing_else_is_buildable(self):
        self.assertEqual(pos.genesis_weights(4),[1,1,1,1]);self.assertEqual(pos.genesis_weights(3,['1','1','1']),[1,1,1])
        for bad,why in ((['1','1'],'one per identity'),(['0','1','1'],'positive'),(['2','1','1'],'stake == 1'),(['1','1','4'],'elected by a handoff')):
            with self.assertRaises(pos.PosError) as e: pos.genesis_weights(3,bad)
            self.assertIn(why,str(e.exception))
    def test_the_plan_carries_one_weight_per_identity_in_the_trust_base_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);(tmp/'tb.json').write_text(json.dumps({'rootNodes':[{'nodeId':'r%d'%i,'sigKey':'0x0%d'%i} for i in (1,2,3)]}))
            (tmp/'c.json').write_text(json.dumps({'validators':[{'nodeId':'e%d'%i,'sigKey':'0x1%d'%i} for i in (1,2,3)]}))
            script=Path(__file__).resolve().parents[2]/'scripts/p85-genesis-plan.py'
            plan=lambda units:subprocess.run([sys.executable,str(script),str(tmp/'tb.json'),str(tmp/'c.json'),'100',units],text=True,capture_output=True)
            self.assertEqual([r['bondUnits'] for r in json.loads(plan('1').stdout)['identities']],[1,1,1])          # the lane's single number
            self.assertEqual([r['bondUnits'] for r in json.loads(plan('1,2,4').stdout)['identities']],[1,2,4])
            self.assertNotEqual(plan('1,2').returncode,0)
    def test_the_topology_runs_the_roots_on_the_pos_flags_and_not_the_poa_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'tn-fixture';out.mkdir()
            images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
            ids={'root':['r%d'%i for i in range(3)],'evm':['e%d'%i for i in range(3)]}
            for with_pos in (False,True):
                cfg=generate.topology(out,3,ids,images,'captcha',(),30000000,with_pos)
                for i in (1,2,3):
                    root=cfg['services']['root%d'%i]['entrypoint']
                    self.assertIn('--q3-lane',root);self.assertIn('--profile-3',root)
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
            with patch('pos.shutil.which',side_effect=lambda t:'/bin/forge' if t=='forge' else None):
                with self.assertRaisesRegex(pos.PosError,'cast'): genesis.check_tools(head)
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
                if 'utb-manifest' in map(str,args): R.stdout='x\nroot genesis id  0x'+'ab'*32+'\nroot network id  5\nutb genesis id    0x00\n'
                if str(args[0]).endswith('p85-genesis.sh'):
                    (genesis.dir/'genesis').mkdir(exist_ok=True);(genesis.dir/'genesis/deployment.json').write_text(json.dumps(deployed))
                return R
            with patch.object(genesis,'_run',side_effect=run):
                genesis.prepare('base.json',provisional=True)
                deployed['assignmentId']=self.ID2;deployed['manifestHash']='0x9'   # the id and the manifest hash over it may differ
                genesis.prepare('full.json',provisional=False)
                deployed['custody']='0xd'                  # an address may not
                with self.assertRaisesRegex(pos.PosError,'custody'): genesis.prepare('full.json',provisional=False)
    def test_the_root_identity_reaches_the_contracts_genesis_and_is_never_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2));genesis.trust_base=Path('tb')
            (Path(tmp)/'script').mkdir();(Path(tmp)/'script/P85Genesis.s.sol').write_text('vm.envBytes32("P85_ROOT_GENESIS")')
            envs=[]
            def run(*args,**kw):
                class R: stderr='genesis assignment id '+self.ID1;stdout='{}'
                if 'utb-manifest' in map(str,args): R.stdout='root genesis id  0x'+'ab'*32+'\nroot network id  5\n'
                if str(args[0]).endswith('p85-genesis.sh'):
                    envs.append(kw['env']);(genesis.dir/'genesis').mkdir(exist_ok=True)
                    (genesis.dir/'genesis/deployment.json').write_text(json.dumps({'custody':'0xc','custodyCodeHash':'0x1','election':'0xe','electionCodeHash':'0x2','assignmentId':self.ID1}))
                return R
            with patch.object(genesis,'_run',side_effect=run):
                genesis.prepare('base.json',provisional=True)
            self.assertEqual((envs[0]['P85_ROOT_NETWORK'],envs[0]['P85_ROOT_GENESIS']),('5','0x'+'ab'*32))
            for out in ('root genesis id  0x'+'ab'*32+'\n','root genesis id  0x12\nroot network id  5\n','root genesis id  0x'+'ab'*32+'\nroot network id  0\n'):
                bad=pos.Genesis(Path(tmp)/('w'+str(hash(out))),'ubft',tmp,generate.REPO,'tn-x',1,(1,2));bad.trust_base=Path('tb')
                class R: stdout=out;stderr=''
                with patch.object(bad,'_run',return_value=R):
                    with self.assertRaisesRegex(pos.PosError,'no root network id'): bad.root_identity()
    def test_an_older_contracts_checkout_gets_no_root_identity_and_the_manifest_tool_is_not_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis=pos.Genesis(Path(tmp)/'work','ubft',tmp,generate.REPO,'tn-x',1,(1,2));genesis.trust_base=Path('tb')
            (Path(tmp)/'script').mkdir();(Path(tmp)/'script/P85Genesis.s.sol').write_text('vm.envBytes32("P85_NETWORK_WORD")')
            self.assertFalse(genesis.contracts_take_root_identity())
            seen=[]
            def run(*args,**kw):
                class R: stderr='genesis assignment id '+self.ID1;stdout='{}'
                seen.append((list(map(str,args)),kw.get('env')))
                if str(args[0]).endswith('p85-genesis.sh'):
                    (genesis.dir/'genesis').mkdir(exist_ok=True)
                    (genesis.dir/'genesis/deployment.json').write_text(json.dumps({'custody':'0xc','custodyCodeHash':'0x1','election':'0xe','electionCodeHash':'0x2','assignmentId':self.ID1}))
                return R
            with patch.object(genesis,'_run',side_effect=run):
                genesis.prepare('base.json',provisional=True)
            self.assertFalse(any('utb-manifest' in a for a,_ in seen))
            genv=[e for a,e in seen if a[0].endswith('p85-genesis.sh')][0]
            self.assertNotIn('P85_ROOT_GENESIS',genv)
            (Path(tmp)/'script/P85Genesis.s.sol').write_text('P85_ROOT_GENESIS')
            self.assertTrue(genesis.contracts_take_root_identity())
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
    def test_the_reward_pool_code_and_funding_are_checked_against_the_genesis_state(self):
        class R: returncode=0;stdout='0xABCD\n';stderr=''
        dep={'custody':'0xaa','custodyCodeHash':'0xabcd','election':'0xaa','electionCodeHash':'0xabcd','policy':'0xaa','policyCodeHash':'0xabcd',
             'rewardPool':'0xcc','rewardPoolCodeHash':'0xabcd','rewardFunding':'1000'}
        def genesis(balance):
            return {'alloc':{'0xAA':{'code':'0x6001'},'0xCC':{'code':'0x6001','balance':balance}}}
        d=pos.Genesis.__new__(pos.Genesis);d.deployment=dep
        with patch('pos.subprocess.run',return_value=R):
            d.alloc_code_hashes(genesis(hex(1000)))
            for wrong in (hex(999),hex(1001),'0x0'):
                with self.assertRaisesRegex(pos.PosError,'recorded funding'): d.alloc_code_hashes(genesis(wrong))
            d.deployment=dict(dep,rewardPoolCodeHash='0xdead')
            with self.assertRaisesRegex(pos.PosError,'rewardPool code'): d.alloc_code_hashes(genesis(hex(1000)))
            d.deployment=dict(dep,policyCodeHash='0xdead')
            with self.assertRaisesRegex(pos.PosError,'policy code'): d.alloc_code_hashes(genesis(hex(1000)))

class EntityNamespace(unittest.TestCase):
    def cfg(self,n=4):
        tmp=tempfile.mkdtemp();self.addCleanup(shutil.rmtree,tmp)
        out=Path(tmp)/'tn-fixture';out.mkdir()
        images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
        return generate.topology(out,n,{'root':['r%d'%i for i in range(n)],'evm':['e%d'%i for i in range(n)]},images,'captcha'),out
    def test_root_and_shard_of_one_entity_share_one_namespace_and_other_entities_do_not(self):
        cfg,_=self.cfg();services=cfg['services']
        for i in (1,2,3,4):
            holder=services['pod%d'%i]
            # validator 1's namespace also holds the one aggregator: it reads root 1's loopback-only trust-base endpoint
            self.assertEqual(holder['networks'],{'validators':{'aliases':['root1','shard1','aggregator']},'aggregator':{}} if i==1 else {'validators':{'aliases':['root%d'%i,'shard%d'%i]}});self.assertIs(holder['init'],True)
            for name in ('root%d'%i,'shard%d'%i,'metrics%d'%i):
                self.assertEqual(services[name]['network_mode'],'service:pod%d'%i);self.assertNotIn('networks',services[name])
            for name in ('authority%d'%i,'ureth%d'%i):
                self.assertNotIn('network_mode',services[name]);self.assertEqual(services[name]['networks'],['validators'])
        for i in (1,2,3,4): self.assertIn('./validator%d/jwt:/jwt:ro'%i,services['root%d'%i]['volumes'],'readiness runs in the root with only this entity\'s JWT')
        self.assertEqual(services['aggregator']['network_mode'],'service:pod1');self.assertNotIn('networks',services['aggregator'])
        joined=[n for n,s in services.items() if 'network_mode' in s]
        self.assertEqual(sorted(joined),sorted([f'{k}{i}' for k in ('root','shard','metrics') for i in (1,2,3,4)]+['aggregator']))
        self.assertEqual([n for n,s in services.items() if isinstance(s.get('networks'),dict)],['pod1','pod2','pod3','pod4'])
        for name,svc in services.items():
            if name.startswith(('pod','root','shard','metrics','authority','ureth')): self.assertNotIn('ports',svc)
    def test_the_operator_listeners_bind_to_loopback_and_nothing_else_serves_them(self):
        cfg,_=self.cfg(3)
        for i in (1,2,3):
            root=cfg['services']['root%d'%i]['entrypoint'];shard=cfg['services']['shard%d'%i]['entrypoint']
            self.assertEqual(root[root.index('--rpc-server-address')+1],'127.0.0.1:8002')
            self.assertEqual(shard[shard.index('--rpc-server-address')+1],'127.0.0.1:9101')
        text=json.dumps(cfg)
        self.assertNotIn('0.0.0.0:8002',text);self.assertNotIn('0.0.0.0:9101',text)
    def test_the_bind_is_a_loopback_config_value_that_every_reader_follows(self):
        import operator_rpc
        self.assertEqual(operator_rpc.DEFAULT_BIND,'127.0.0.1')
        for ok in ('127.0.0.1','127.0.0.2','127.255.255.254'): self.assertEqual(operator_rpc.check_bind(ok),ok)
        for bad in ('0.0.0.0','::','::1','[::1]','10.0.0.5','172.30.88.2','128.0.0.1','localhost','','1.2.3'):
            with self.assertRaises(operator_rpc.BindError,msg=bad): operator_rpc.check_bind(bad)
        self.assertEqual(operator_rpc.listen('127.0.0.2',8002),'127.0.0.2:8002')
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'tn-fixture';out.mkdir()
            images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
            ids={'root':['r%d'%i for i in range(3)],'evm':['e%d'%i for i in range(3)]}
            cfg=generate.topology(out,3,ids,images,'captcha',(),30000000,False,'127.0.0.2')
            generate.write(out/'compose.yaml',cfg)
            for i in (1,2,3):
                root=cfg['services']['root%d'%i]['entrypoint'];shard=cfg['services']['shard%d'%i]['entrypoint']
                self.assertEqual((root[root.index('--rpc-server-address')+1],shard[shard.index('--rpc-server-address')+1]),('127.0.0.2:8002','127.0.0.2:9101'))
                self.assertEqual(cfg['services']['metrics%d'%i]['environment'],{'ROOT_RPC':'127.0.0.2:8002','SHARD_RPC':'127.0.0.2:9101'})
            # the wrapper reads the listener from the generated file, not from a constant
            self.assertEqual(handoff_ops.DockerTransport(out).root_rpc,'http://127.0.0.2:8002')
            self.assertEqual(handoff_ops.abort_commands(out,[1],[])[1][-1],'http://127.0.0.2:8002')
    def test_the_relay_takes_its_upstreams_from_the_environment(self):
        self.assertEqual(metrics_relay.routes({'ROOT_RPC':'127.0.0.2:8002','SHARD_RPC':'127.0.0.3:9101'}),{'/root/metrics':'http://127.0.0.2:8002/api/v1/metrics','/shard/metrics':'http://127.0.0.3:9101/api/v1/metrics'})
        with self.assertRaises(KeyError): metrics_relay.routes({})
    def test_the_generator_refuses_a_non_loopback_bind_before_any_key(self):
        for bad in ('0.0.0.0','10.1.2.3','example.org'):
            done=subprocess.run([sys.executable,str(Path(__file__).parent/'generate.py'),'--out','/nonexistent/tn-x','--validators','4','--ubft','x','--keygen','x','--b1genesis','x',
                '--images','x','--captcha-sitekey','a','--captcha-secret-file','x','--rpc-bind',bad],text=True,capture_output=True)
            self.assertEqual(done.returncode,2,bad);self.assertIn('--rpc-bind',done.stderr)
    def test_every_root_must_carry_the_same_operator_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,out=EntityNamespace.cfg(self,3)
            self.assertEqual(operator_rpc.common_urls(cfg),('http://127.0.0.1:8002','http://127.0.0.1:9101'))
            for victim,want in (('root2','roots'),('shard3','shards')):
                bad=json.loads(json.dumps(cfg));entry=bad['services'][victim]['entrypoint']
                entry[entry.index('--rpc-server-address')+1]='127.0.0.9:'+entry[entry.index('--rpc-server-address')+1].split(':')[1]
                with self.assertRaisesRegex(operator_rpc.BindError,want+' carry different'): operator_rpc.common_urls(bad)
                if victim=='root2':
                    generate.write(out/'compose.yaml',bad)
                    with self.assertRaises(operator_rpc.BindError): handoff_ops.DockerTransport(out)
            bad=json.loads(json.dumps(cfg));entry=bad['services']['root3']['entrypoint']
            entry[entry.index('--rpc-server-address')+1]='127.0.0.9:8002';generate.write(out/'compose.yaml',bad)
            with self.assertRaises(operator_rpc.BindError): handoff_ops.abort_commands(out,[1,2,3],[])
    def test_the_validator_count_is_capped_at_the_registry_ceiling_with_the_reason(self):
        for n,ok in ((2,False),(3,True),(16,True),(17,False),(32,False)):
            done=subprocess.run([sys.executable,str(Path(__file__).parent/'generate.py'),'--out','/nonexistent/tn-x','--validators',str(n),'--ubft','/nonexistent/ubft','--keygen','x','--b1genesis','x',
                '--images','x','--captcha-sitekey','a','--captcha-secret-file','x'],text=True,capture_output=True)
            if ok: self.assertNotIn('validators must be 3..16',done.stderr,n)
            else:
                self.assertEqual(done.returncode,2,n);self.assertIn('validators must be 3..16, got %d'%n,done.stderr);self.assertIn('at most 16 committee members',done.stderr)
    def test_no_source_hardcodes_an_operator_listener_address(self):
        here=Path(__file__).parent
        for name in ('generate.py','handoff_ops.py','metrics_relay.py','validate-pos.py','validate-aggregator.py','validate-handoff.py'):
            text=(here/name).read_text()
            for literal in ("'127.0.0.1:8002'","'127.0.0.1:9101'","http://127.0.0.1:8002","http://127.0.0.1:9101","0.0.0.0:8002","0.0.0.0:9101"):
                self.assertNotIn(literal,text,f'{name} hardcodes {literal}')
    def test_prometheus_scrapes_the_relay_not_the_loopback_listeners(self):
        source=Path(generate.__file__).read_text()
        self.assertIn("'/root/metrics'",source);self.assertIn("'/shard/metrics'",source);self.assertNotIn("f'root{i}:8002'",source);self.assertNotIn("f'shard{i}:9101'",source)
    def test_compose_accepts_the_namespace_topology(self):
        if shutil.which('docker') is None: self.skipTest('no docker CLI')
        cfg,out=self.cfg(3);generate.write(out/'compose.yaml',cfg)
        done=subprocess.run(['docker','compose','-f',str(out/'compose.yaml'),'config','--format','json'],capture_output=True,text=True)
        self.assertEqual(done.returncode,0,done.stderr)
        rendered=json.loads(done.stdout)['services']
        self.assertEqual(rendered['root1']['network_mode'],'service:pod1')
        self.assertEqual(rendered['pod1']['networks']['validators']['aliases'],['root1','shard1','aggregator'])
        self.assertEqual(rendered['aggregator']['network_mode'],'service:pod1')

class MetricsRelay(unittest.TestCase):
    def setUp(self):
        seen=self.seen=[]
        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_GET(h):
                seen.append((h.path,dict(h.headers)));body=b'metric 1\n'
                h.send_response(200);h.send_header('Content-Length',str(len(body)));h.end_headers();h.wfile.write(body)
            def log_message(h,*a): pass
        self.up=http.server.HTTPServer(('127.0.0.1',0),Upstream);threading.Thread(target=self.up.serve_forever,daemon=True).start()
        self.addCleanup(self.up.shutdown)
        base='http://127.0.0.1:%d'%self.up.server_address[1]
        patcher=patch.object(metrics_relay,'ROUTES',{'/root/metrics':base+'/api/v1/metrics','/shard/metrics':base+'/api/v1/metrics'});patcher.start();self.addCleanup(patcher.stop)
        self.relay=http.server.ThreadingHTTPServer(('127.0.0.1',0),metrics_relay.Handler);threading.Thread(target=self.relay.serve_forever,daemon=True).start()
        self.addCleanup(self.relay.shutdown)
    def request(self,method,path,headers=None,body=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.relay.server_address[1],timeout=3);conn.request(method,path,body,headers or {})
        r=conn.getresponse();data=r.read();conn.close();return r.status,data
    def test_only_the_two_metrics_paths_by_get_reach_the_node(self):
        self.assertEqual(self.request('GET','/root/metrics'),(200,b'metric 1\n'))
        self.assertEqual(self.request('GET','/shard/metrics')[0],200)
        for path in ('/','/api/v1/metrics','/api/v1/handoff/plan','/root/metrics?x=1','/root/metrics/','/ROOT/metrics','/root/metrics/..','/root/../api/v1/handoff/abort','/q3/status'):
            self.assertEqual(self.request('GET',path)[0],404,path)
        for method in ('POST','PUT','DELETE','PATCH','OPTIONS'):
            self.assertEqual(self.request(method,'/root/metrics',{'Content-Type':'application/json'},'{}')[0],405,method)
        self.assertEqual([p for p,_ in self.seen],['/api/v1/metrics']*2,'only the fixed metrics URL was ever requested')
    def test_nothing_the_client_sends_reaches_the_node(self):
        self.request('GET','/root/metrics',{'Origin':'http://evil','Content-Type':'application/json','X-Forwarded-For':'127.0.0.1','Cookie':'a=b'})
        headers={k.lower() for k in self.seen[0][1]}
        self.assertFalse(headers&{'origin','content-type','x-forwarded-for','cookie'},headers)

class HandoffWrapper(unittest.TestCase):
    class Fake:
        """A transport that records every call. `endorse_script[entity]` is the list of (status, body) the entity answers, last one repeating."""
        def __init__(self,entities,plans=None,endorse_script=None):
            self.calls=[];self.entities=entities;self.plans=list(plans or [b'PLAN-1']);self.script=endorse_script or {}
        def post(self,entity,path,body,timeout=10):
            self.calls.append((entity,path,body))
            if path.endswith('/plan'): return 200,self.plans.pop(0) if len(self.plans)>1 else self.plans[0]
            if path.endswith('/intent'): return 204,b''
            answers=self.script.get(entity,[(204,b'')]);index=sum(1 for c in self.calls if c[0]==entity and c[1].endswith('/endorse'))-1
            return answers[min(index,len(answers)-1)]
    def wrapper(self,fake,rows,**kw):
        clock=[0.0]
        def sleep(s): clock[0]+=s
        return handoff_ops.Wrapper(fake,[1,2,3,4],rows.append,sleep=sleep,now=lambda:clock[0],**kw)
    def test_one_plan_from_the_first_entity_the_same_bytes_as_every_intent_then_endorsements_of_that_plan(self):
        fake=self.Fake([1,2,3,4]);rows=[]
        self.assertEqual(self.wrapper(fake,rows).propose(b'REQUEST'),4)
        plans=[c for c in fake.calls if c[1].endswith('/plan')];intents=[c for c in fake.calls if c[1].endswith('/intent')];endorsements=[c for c in fake.calls if c[1].endswith('/endorse')]
        self.assertEqual([(c[0],c[2]) for c in plans],[(1,b'REQUEST')])
        self.assertEqual(sorted((c[0],c[2]) for c in intents),[(2,b'PLAN-1'),(3,b'PLAN-1'),(4,b'PLAN-1')])
        self.assertEqual(sorted((c[0],c[2]) for c in endorsements),[(e,b'PLAN-1') for e in (1,2,3,4)])
        self.assertEqual(fake.calls.index(plans[0]),0,'the plan precedes every intent and endorsement')
        self.assertEqual([r['event'] for r in rows],['plan','intent','endorse'])
        self.assertEqual(rows[0]['plan_sha256'],handoff_ops.sha(b'PLAN-1'));self.assertEqual(rows[0]['request_sha256'],handoff_ops.sha(b'REQUEST'))
    def test_hold_endorses_at_the_first_entity_only_and_the_abort_target_is_derived_from_the_context_and_the_plan(self):
        import base64,json
        body=b'CANONICAL-BODY';plan=json.dumps({'Attempt':3,'Body':base64.b64encode(body).decode()}).encode()
        fake=self.Fake([1,2,3,4],plans=[plan]);rows=[]
        self.assertEqual(self.wrapper(fake,rows).hold(b'R'),plan)
        self.assertEqual([c[0] for c in fake.calls if c[1].endswith('/endorse')],[1],'one endorsement, below the quorum: no Freeze follows')
        self.assertEqual(sorted(c[0] for c in fake.calls if c[1].endswith('/intent')),[2,3,4])
        self.assertEqual([r['event'] for r in rows],['plan','hold'])
        class Context(self.Fake):
            def post(self,entity,path,body,timeout=10):
                return (200,json.dumps({'network':7,'attempt':3,'predecessor':'0x'+'ab'*32}).encode()) if path.endswith('/evm-assignment/context') else (422,b'invalid operator approval')
        context=handoff_ops.abort_context(Context([1]),1)
        target=handoff_ops.abort_target(context,plan,1)
        self.assertEqual(target,{'network':7,'oldEpoch':1,'predecessorBodyId':'0x'+'ab'*32,'attempt':3,'nextBodyId':'0x'+handoff_ops.sha(body)})
        with self.assertRaisesRegex(handoff_ops.HandoffError,'planned attempt 3'):
            handoff_ops.abort_target(context,json.dumps({'Attempt':2,'Body':base64.b64encode(body).decode()}).encode(),1)
        with self.assertRaises(ValueError,msg='a tampered plan (a body that is not canonical base64) names no target'):
            handoff_ops.abort_target(context,json.dumps({'Attempt':3,'Body':'not base64!'}).encode(),1)
        with self.assertRaises(KeyError,msg='a plan without a body names no target'):
            handoff_ops.abort_target(context,json.dumps({'Attempt':3}).encode(),1)
        with self.assertRaisesRegex(handoff_ops.HandoffError,'refused the context: 422'):
            handoff_ops.abort_context(type('Busy',(),{'post':lambda self,*a,**k:(422,b'invalid operator approval')})(),1)
    def test_hold_is_not_held_when_the_first_endorsement_is_refused_and_a_proposal_records_the_plan_identity_abort_names(self):
        import base64,json
        body=b'B2';plan=json.dumps({'Attempt':1,'Body':base64.b64encode(body).decode()}).encode()
        fake=self.Fake([1,2,3,4],plans=[plan],endorse_script={1:[(422,b'refused')]});rows=[]
        with self.assertRaises(handoff_ops.HandoffError):
            self.wrapper(fake,rows).hold(b'R')
        self.assertEqual(rows[-1]['event'],'hold');self.assertEqual(rows[-1]['endorsed'],[],'nothing is held when the endorsement is refused')
        rows=[];self.wrapper(self.Fake([1,2,3,4],plans=[plan]),rows).propose(b'R')
        self.assertEqual((rows[0]['plan_attempt'],rows[0]['next_body_id']),(1,'0x'+handoff_ops.sha(body)),'the plan row carries what pos-too-late names in the Abort')
    def test_an_endorsement_refused_before_the_prepare_is_retried_until_it_is_prepared(self):
        fake=self.Fake([1,2,3,4],endorse_script={2:[(409,b'endorsed before the handoff is prepared')]*2+[(204,b'')]})
        self.assertEqual(self.wrapper(fake,[]).propose(b'R'),4)
        self.assertEqual(sum(1 for c in fake.calls if c[0]==2 and c[1].endswith('/endorse')),3)
    def test_a_prepare_that_never_comes_is_refused_after_the_timeout_and_a_quorum_is_two_thirds_plus_one(self):
        never=[(409,b'before the handoff is prepared')]
        fake=self.Fake([1,2,3,4],endorse_script={3:never,4:never})   # 2 of 4 < 4*2//3+1 = 3
        with self.assertRaisesRegex(handoff_ops.HandoffError,'only 2/4'): self.wrapper(fake,[],prepare_timeout=5).propose(b'R')
        fake=self.Fake([1,2,3,4],endorse_script={4:never})           # 3 of 4 is a quorum
        self.assertEqual(self.wrapper(fake,[],prepare_timeout=5).propose(b'R'),3)
    def test_a_lapsed_prepare_replans_a_new_attempt_and_is_bounded(self):
        lapsed=[(409,b"the Prepare's freeze has lapsed")]
        fake=self.Fake([1,2,3,4],plans=[b'PLAN-1',b'PLAN-2'],endorse_script={e:lapsed for e in (1,2,3,4)})
        rows=[]
        with self.assertRaises(handoff_ops.HandoffLapsed): self.wrapper(fake,rows,max_attempts=2).propose(b'R')
        self.assertEqual(sum(1 for c in fake.calls if c[1].endswith('/plan')),2,'two attempts, no more')
        self.assertEqual([r['event'] for r in rows].count('lapsed'),2)
        # an attempt that lapses once and then succeeds: the second plan's bytes are what the second round distributes
        fake=self.Fake([1,2,3,4],plans=[b'PLAN-1',b'PLAN-2'])
        original=fake.post
        state={'n':0}
        def post(entity,path,body,timeout=10):
            if path.endswith('/endorse') and body==b'PLAN-1': return 409,b"the Prepare's freeze has lapsed"
            return original(entity,path,body,timeout)
        fake.post=post
        self.assertEqual(self.wrapper(fake,[]).propose(b'R'),4)
        self.assertEqual([c[2] for c in fake.calls if c[1].endswith('/intent')][-3:],[b'PLAN-2']*3)
    def test_a_root_that_refuses_the_intent_stops_the_attempt_before_any_endorsement(self):
        fake=self.Fake([1,2,3,4]);original=fake.post
        fake.post=lambda e,p,b,timeout=10:(422,b'no') if (e==3 and p.endswith('/intent')) else original(e,p,b,timeout)
        with self.assertRaisesRegex(handoff_ops.HandoffError,'validator 3 refused the plan'): self.wrapper(fake,[]).propose(b'R')
        self.assertFalse([c for c in fake.calls if c[1].endswith('/endorse')])
    def test_the_intent_delay_pauses_before_each_intent_only(self):
        fake=self.Fake([1,2,3,4]);clock=[0.0];slept=[]
        def sleep(s): slept.append(s);clock[0]+=s
        wrapper=handoff_ops.Wrapper(fake,[1,2,3,4],[].append,sleep=sleep,now=lambda:clock[0],intent_delay=1.5)
        self.assertEqual(wrapper.propose(b'R'),4)
        self.assertEqual(slept,[1.5,1.5,1.5],'one pause for each of the three intents')
    def test_an_intent_refused_because_its_prepare_lapsed_replans_and_any_other_refusal_is_final_and_recorded(self):
        later=(422,b"root handoff: invalid operator approval: the plan is for attempt 0, this validator's committed state plans attempt 1")
        fake=self.Fake([1,2,3,4],plans=[b'PLAN-1',b'PLAN-2']);original=fake.post
        fake.post=lambda e,p,b,timeout=10:later if (e==4 and p.endswith('/intent') and b==b'PLAN-1') else original(e,p,b,timeout)
        rows=[]
        self.assertEqual(self.wrapper(fake,rows).propose(b'R'),4)
        self.assertEqual([c[2] for c in fake.calls if c[1].endswith('/intent')][-3:],[b'PLAN-2']*3)
        self.assertEqual([r['event'] for r in rows].count('lapsed'),1)
        refused=[r for r in rows if r['event']=='intent-refused']
        self.assertEqual((refused[0]['entity'],refused[0]['status']),(4,422))
        # a lapse that repeats is bounded like any other
        fake=self.Fake([1,2,3,4],plans=[b'PLAN-1',b'PLAN-2']);original=fake.post
        fake.post=lambda e,p,b,timeout=10:later if (e==4 and p.endswith('/intent')) else original(e,p,b,timeout)
        with self.assertRaises(handoff_ops.HandoffLapsed): self.wrapper(fake,[],max_attempts=2).propose(b'R')
        # the bare refusal is not retried or turned into a lapse
        bare=(422,b'root handoff: invalid operator approval')
        fake=self.Fake([1,2,3,4]);original=fake.post;n={'x':0}
        def post(e,p,b,timeout=10):
            if e==4 and p.endswith('/intent'): n['x']+=1;return bare
            return original(e,p,b,timeout)
        fake.post=post
        with self.assertRaisesRegex(handoff_ops.HandoffError,'validator 4 refused the plan'): self.wrapper(fake,[]).propose(b'R')
        self.assertEqual(n['x'],1)
    def test_the_helper_runs_inside_the_entity_namespace_without_privileges_and_the_abort_is_dispatched_to_each_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,out=EntityNamespace.cfg(self,3);generate.write(out/'compose.yaml',cfg)
            transport=handoff_ops.DockerTransport(out)
            self.assertEqual(transport.entities,[1,2,3])
            with patch.object(transport,'holder',return_value='CID2'):
                command=transport.command(2,'/api/v1/handoff/intent',10)
            self.assertIn('container:CID2',command);self.assertIn('--read-only',command);self.assertEqual(command[command.index('--cap-drop')+1],'ALL')
            self.assertNotIn('-v',command);self.assertNotIn('--volume',command);self.assertNotIn('--privileged',command)
            self.assertEqual(command[-2:],['http://127.0.0.1:8002/api/v1/handoff/intent','10'])   # the default bind
            commands=handoff_ops.abort_commands(out,[1,2,3],['--network','3','--old-epoch','1'])
            self.assertEqual(sorted(commands),[1,2,3])
            self.assertEqual(commands[2][-2:],['--root-rpc','http://127.0.0.1:8002'])
            self.assertIn('root2',commands[2]);self.assertEqual(commands[2].count('--root-rpc'),1)

class HandoffHelper(unittest.TestCase):
    def test_the_helper_posts_json_and_reports_status_then_body_including_refusals(self):
        seen=[]
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(h):
                body=h.rfile.read(int(h.headers['Content-Length']));seen.append((h.path,h.headers['Content-Type'],body,h.headers.get('Origin')))
                status=204 if h.path.endswith('/ok') else 409;data=b'' if status==204 else b'before the handoff is prepared'
                h.send_response(status);h.send_header('Content-Length',str(len(data)));h.end_headers();h.wfile.write(data)
            def log_message(h,*a): pass
        server=http.server.HTTPServer(('127.0.0.1',0),H);threading.Thread(target=server.serve_forever,daemon=True).start();self.addCleanup(server.shutdown)
        base='http://127.0.0.1:%d'%server.server_address[1]
        run=lambda path,data:subprocess.run(['python3','-c',handoff_ops.HELPER,base+path,'5'],input=data,capture_output=True)
        ok=run('/ok',b'{"a":1}');self.assertEqual(ok.stdout,b'204\n')
        refused=run('/no',b'{}');self.assertEqual(refused.stdout,b'409\nbefore the handoff is prepared')
        self.assertEqual(seen[0],('/ok','application/json',b'{"a":1}',None))

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

class HandoffDryForm(unittest.TestCase):
    def load(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('validate_handoff',Path(__file__).parent/'validate-handoff.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    def test_the_flag_reader_and_the_cli_check_name_a_missing_command_or_flag(self):
        dry=self.load()
        self.assertEqual(dry.flags_of("Flags:\n  -h, --help   help\n      --next-trust-base string   x\n  -o, --out string  y\n"),{'help','next-trust-base','out'})
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'ubft'
            fake.write_text("#!/bin/sh\ncase \"$*\" in\n *known*) printf 'Flags:\\n      --a  x\\n      --b  y\\n';;\n *) exit 1;;\nesac\n");fake.chmod(0o755)
            self.assertEqual(dry.check_cli(fake,{'known cmd':['a','b']}),1)
            with self.assertRaisesRegex(AssertionError,'lacks --c'): dry.check_cli(fake,{'known cmd':['a','c']})
            with self.assertRaisesRegex(AssertionError,'does not exist'): dry.check_cli(fake,{'other cmd':['a']})

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
                out=Path(tmp)/'tn-fixture';out.mkdir()
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
                # the one aggregator (owner decision 40): aggregator-go, one full-range shard, no HA, beside root 1 (its trust-base endpoint is loopback-only)
                agg=cfg['services']['aggregator']
                env=agg['environment']
                self.assertEqual(agg['entrypoint'],['aggregator']);self.assertEqual(agg['network_mode'],'service:pod1')
                self.assertEqual((env['SHARDING_MODE'],env['BFT_ENABLED'],env['DISABLE_HIGH_AVAILABILITY'],env['SMT_BACKEND']),('standalone','true','true','memory'))
                self.assertEqual(env['BFT_RPC_ADDRESS'],'http://127.0.0.1:%d'%operator_rpc.ROOT_PORT)
                self.assertEqual(env['BFT_BOOTSTRAP_ADDRESSES'].count('/dns4/root'),n)
                self.assertEqual(env['SIGNING_KEY_FILE'],'/state/keys.json');self.assertIn('./aggregator:/state:ro',agg['volumes'])
                self.assertNotIn('env_file',agg)
                self.assertFalse([k for k in env if re.search('KEY|SECRET|PASSWORD',k) and k!='SIGNING_KEY_FILE'],'no secret in the public manifest')
                self.assertEqual(agg['depends_on'],{'mongo':{'condition':'service_healthy'}})
                self.assertIn('aggregator',cfg['services']['pod1']['networks']['validators']['aliases'])
                self.assertFalse(any('aggregator' in cfg['services']['pod%d'%i]['networks']['validators']['aliases'] for i in range(2,n+1)))
                mongo=cfg['services']['mongo']
                self.assertEqual(mongo['image'],generate.PINS['mongo']);self.assertRegex(mongo['image'],r'^mongo:[0-9.]+@sha256:[0-9a-f]{64}$')
                self.assertEqual(mongo['networks'],['aggregator']);self.assertNotIn('ports',mongo);self.assertTrue(cfg['networks']['aggregator']['internal'])
                self.assertEqual([k for k,v in cfg['services'].items() if 'aggregator' in (v.get('networks') or {})],['pod1','mongo'],'only the aggregator\'s namespace reaches MongoDB')
                self.assertEqual((mongo['user'],mongo['read_only'],mongo['cap_drop']),('10001:10001',True,['ALL']))
                self.assertIn('--replSet',mongo['entrypoint']);self.assertIn('rs.initiate',mongo['healthcheck']['test'][-1])
                self.assertEqual(mongo['stop_grace_period'],'30s');self.assertEqual(mongo['volumes'],['./mongo:/data/db']);self.assertIn('/data/configdb:size=1m,mode=1777',mongo['tmpfs'])
                if os.environ.get('TN_REQUIRE_COMPOSE')=='1':
                    # config needs no daemon; do not silently skip this check in CI.
                    generate.write(out/'compose.yaml',cfg)
                    subprocess.run(['docker','compose','-f',str(out/'compose.yaml'),'config','--quiet'],check=True)
                self.assertTrue(cfg['networks']['validators']['internal'])
                for i in range(1,n+1):
                    shard=cfg['services']['shard%d'%i]['entrypoint']
                    self.assertNotIn('--archive-replica',shard,'the node derives its archive replicas')
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

class TesterCheck(unittest.TestCase):
    """deploy/testnet/tester-check.py against a stub JSON-RPC endpoint."""
    GEN='0x'+'ab'*32
    def module(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('tester_check',Path(__file__).parent/'tester-check.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def serve(self,chain=31337,zero=None,heights=(5,6),net=None):
        zero=zero or self.GEN;hs=iter(heights);last=[heights[0]]
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a): pass
            def do_POST(self):
                req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                r={'eth_chainId':hex(chain),'net_version':str(net or chain),'eth_getBlockByNumber':{'hash':zero}}.get(req['method'])
                if req['method']=='eth_blockNumber':
                    last[0]=next(hs,last[0]);r=hex(last[0])
                body=json.dumps({'jsonrpc':'2.0','id':1,'result':r}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        srv=http.server.HTTPServer(('127.0.0.1',0),H);threading.Thread(target=srv.serve_forever,daemon=True).start();self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_port}/'
    def run_check(self,url,*extra):
        import io,contextlib
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=self.module().main(['--rpc',url,*extra])
        return code,out.getvalue(),err.getvalue()
    def test_the_published_network_passes(self):
        code,out,_=self.run_check(self.serve(),'--chain-id','31337','--genesis-hash','0x'+'AB'*32,'--wait','5')
        self.assertEqual(code,0,out);self.assertIn('serves the published network',out)
    def test_a_wrong_chain_id_fails(self):
        code,out,_=self.run_check(self.serve(chain=1),'--chain-id','31337','--genesis-hash',self.GEN)
        self.assertEqual(code,1);self.assertIn('FAIL chain ID',out)
    def test_a_wrong_net_version_alone_fails(self):
        code,out,_=self.run_check(self.serve(net=1),'--chain-id','31337','--genesis-hash',self.GEN)
        self.assertEqual(code,1);self.assertIn('FAIL net_version',out);self.assertIn('ok   chain ID',out)
    def test_a_manifest_together_with_explicit_values_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'m.json';f.write_text(json.dumps({'chain_id':31337,'genesis_hash':self.GEN}))
            self.assertEqual(self.run_check(self.serve(),'--manifest',str(f),'--chain-id','31337')[0],2)
    def test_a_reset_network_with_another_block_zero_fails(self):
        code,out,_=self.run_check(self.serve(zero='0x'+'cd'*32),'--chain-id','31337','--genesis-hash',self.GEN)
        self.assertEqual(code,1);self.assertIn('FAIL block-zero hash',out);self.assertIn('DO NOT USE',out)
    def test_a_stalled_chain_fails_only_when_a_block_is_required(self):
        url=self.serve(heights=(5,))
        self.assertEqual(self.run_check(url,'--chain-id','31337','--genesis-hash',self.GEN)[0],0)
        self.assertEqual(self.run_check(url,'--chain-id','31337','--genesis-hash',self.GEN,'--wait','2')[0],1)
    def test_the_manifest_file_form_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'m.json';f.write_text(json.dumps({'chain_id':31337,'genesis_hash':self.GEN,'captcha_sitekey':'x','validators':4}))
            self.assertEqual(self.run_check(self.serve(),'--manifest',str(f))[0],0)
    def test_a_malformed_publication_or_unreachable_endpoint_is_exit_2(self):
        self.assertEqual(self.run_check(self.serve(),'--chain-id','31337','--genesis-hash','0x12')[0],2)
        self.assertEqual(self.run_check('http://127.0.0.1:1/','--chain-id','31337','--genesis-hash',self.GEN)[0],2)

class BridgeRelease(unittest.TestCase):
    """bridge/release.py on a fake generation, with the image's files and the chain served by a stub of the tools image."""
    CORPUS='9c'*32;VAULT='0x'+'aa'*20;VERIFIER='0x'+'bb'*20;IMAGE='sha256:'+'11'*32
    def module(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('release',Path(__file__).parent/'bridge/release.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def generation(self,tmp,image=None,vault=None):
        gen=Path(tmp)/'gen';(gen/'bridge').mkdir(parents=True);(gen/'network').mkdir();art=Path(tmp)/'artifacts';art.mkdir()
        (gen/'manifest.json').write_text(json.dumps({'generation':'tn-x','chain_id':31337,'genesis_hash':'0x'+'ab'*32,'validators':4,'artifacts':{'sources':{'ureth':'u'},'images':{'node':'n'}}}))
        (art/'bridge-images.json').write_text(json.dumps({'sources':{'contracts':'c'*40,'native-bridge-plugins':'p'*40},'dnb_tool_sha256':'d'*64,'images':{'bridge':image or self.IMAGE}}))
        (gen/'bridge/bridge-addresses.json').write_text(json.dumps({'BridgeVault':vault or self.VAULT,'TokenVerifier':self.VERIFIER,'CFG':'0x'+'cf'*32}))
        txs=[{'contractName':'TokenVerifier','transactionType':'CREATE','contractAddress':self.VERIFIER,'hash':'0x01'},
             {'contractName':'BridgeVault','transactionType':'CREATE','contractAddress':self.VAULT,'hash':'0x02'},
             {'contractName':'BridgeVault','transactionType':'CALL','contractAddress':self.VAULT,'hash':'0x03'}]   # a later call to the vault is not its deployment
        (gen/'bridge/bridge-broadcast.json').write_text(json.dumps({'transactions':txs,'receipts':[{'transactionHash':h,'blockNumber':hex(b)} for h,b in (('0x01',7),('0x02',8),('0x03',9))]}))
        (gen/'network/b1-profile.json').write_text(json.dumps({'maxGas':269547540+60000000,'ordinaryCapacity':60000000}))
        return gen,art
    def tools(self,pinned=None):
        files={'/opt/bridge/native-bridge-plugins/protocol/vectors/MANIFEST.sha256':self.CORPUS+'\n',
               '/opt/bridge/contracts/script/bridge-golden/corpus-pin.json':json.dumps({'corpus':{'manifestSha256':pinned or self.CORPUS}}),
               '/opt/bridge/native-bridge-plugins/node_modules/@unicitylabs/state-transition-sdk/package.json':json.dumps({'version':'4.0.0-utb.x'}),
               '/opt/bridge/native-bridge-plugins/package-lock.json':json.dumps({'packages':{'node_modules/@unicitylabs/state-transition-sdk':{'resolved':'file:sdk.tgz','integrity':'sha512-x'}}}),
               '/opt/bridge/native-bridge-plugins/node_modules/@unicitylabs/state-transition-sdk/lib/api/IBatchAggregatorClient.js':'export const BATCH_MAX_STATE_IDS = 256;\n'}
        def run(*args):
            if args[0]=='cat': return files[args[1]]
            if args[:2]==('cast','codehash'): return '0x'+args[-1][2:4]*32+'\n'
            raise AssertionError(args)
        return run
    def build(self,gen,art,tools=None,image=None):
        m=self.module()
        with patch.object(m,'ARTIFACTS',art):
            return m.build(gen,tools or self.tools(),image or self.IMAGE,['unicity-reth','node','--rpc.eth-proof-window','64'],16384)
    def test_the_manifest_joins_the_pins_the_deployment_the_profile_and_the_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=self.build(*self.generation(tmp))
        self.assertEqual(r['contracts']['BridgeVault'],{'address':self.VAULT,'transaction':'0x02','block':8,'codeHash':'0x'+'aa'*32})
        self.assertEqual(r['contracts']['TokenVerifier']['block'],7);self.assertEqual(r['contracts']['commit'],'c'*40);self.assertEqual(r['contracts']['cfg'],'0x'+'cf'*32)
        self.assertEqual((r['profile']['corpusDigest'],r['profile']['nativeBridgePlugins'],r['profile']['sdk']['version']),(self.CORPUS,'p'*40,'4.0.0-utb.x'))
        limits={k:v['value'] for k,v in r['limits'].items()}
        self.assertEqual((limits['D1envelopeBytes'],limits['D3ordinaryCapacity'],limits['blockGasLimit'],limits['proofWindowBlocks'],limits['gatewayMaxBodyBytes'],limits['aggregatorBatchStateIds']),
                         (2097152,60000000,329547540,64,16384,256))
        self.assertIn('at most 254 transfers',r['limits']['aggregatorBatchStateIds']['source'])
        self.assertEqual((r['package']['generation'],r['bridge']['image']),('tn-x',self.IMAGE))
    def test_another_image_than_the_recorded_one_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit,'records'): self.build(*self.generation(tmp,image='sha256:'+'22'*32))
    def test_plugins_whose_corpus_is_not_the_contracts_pin_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit,'corpus'): self.build(*self.generation(tmp),tools=self.tools(pinned='00'*32))
    def test_addresses_that_are_not_the_broadcast_deployments_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit,'not bridge-addresses'): self.build(*self.generation(tmp,vault='0x'+'cc'*20))

class LoadGenerator(unittest.TestCase):
    """deploy/testnet/loadgen.py against an in-memory node and a fake clock."""
    def module(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('loadgen',Path(__file__).parent/'loadgen.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    class Node:
        def __init__(self,limit_every=0,status='0x1',fail_at=None,mine=True):
            self.sent=[];self.calls=0;self.limit_every=limit_every;self.status=status;self.fail_at=fail_at;self.mine=mine;self.xff=set()
        def post(self,method,params,xff=None):
            self.xff.add(xff)
            ok=lambda r:(200,json.dumps({'jsonrpc':'2.0','id':1,'result':r}))
            if method=='eth_getTransactionCount': return ok(hex(0 if params[1]=='pending' else (len(self.sent) if self.mine else 0)))
            if method=='eth_gasPrice': return ok('0x1')
            if method=='eth_sendRawTransaction':
                self.calls+=1
                if self.limit_every and self.calls%self.limit_every==0: return 429,'limited'
                if self.fail_at is not None and len(self.sent)==self.fail_at: return 500,'boom'
                self.sent.append(params[0]);return ok('0x%064x'%len(self.sent))
            if method=='eth_getTransactionReceipt': return ok({'status':self.status})
            raise AssertionError(method)
    def run_load(self,node,**kw):
        now=[0.0]
        def sleep(d): now[0]+=d
        args=dict(sender='0xaa',sign=lambda to,n,p: f'raw{n}',rate=10,duration=3,ips=0,ip_prefix='203.0.113.',recipients=4,receipt_wait=5,min_accepted=1)
        args.update(kw)
        return self.module().run(node,args.pop('sender'),args.pop('sign'),args.pop('rate'),args.pop('duration'),args.pop('ips'),args.pop('ip_prefix'),args.pop('recipients'),
                                 args.pop('receipt_wait'),args.pop('min_accepted'),clock=lambda:now[0],sleep=sleep)
    def test_every_accepted_transfer_mined_is_a_pass(self):
        node=self.Node();s,problems=self.run_load(node)
        self.assertEqual(problems,[]);self.assertEqual((s['submitted'],s['accepted'],s['mined_ok'],s['rate_limited_429']),(30,30,30,0))
        self.assertEqual(node.sent,[f'raw{i}' for i in range(30)])
    def test_rate_limited_submissions_are_counted_and_resent_with_the_same_nonce(self):
        node=self.Node(limit_every=4);s,problems=self.run_load(node)
        self.assertEqual(problems,[]);self.assertGreater(s['rate_limited_429'],0);self.assertEqual(node.sent,[f'raw{i}' for i in range(30)])
    def test_the_requests_are_spread_over_the_client_addresses(self):
        node=self.Node();self.run_load(node,ips=3)
        self.assertEqual(node.xff,{'203.0.113.1','203.0.113.2','203.0.113.3'})
    def test_a_transfer_mined_with_a_failed_status_fails_the_run(self):
        s,problems=self.run_load(self.Node(status='0x0'))
        self.assertTrue(any('failed status' in p for p in problems),problems)
    def test_a_refused_submission_other_than_the_rate_limit_fails_the_run(self):
        s,problems=self.run_load(self.Node(fail_at=5))
        self.assertTrue(any('HTTP 500' in p for p in problems),problems);self.assertEqual(s['errors'],25)
    def test_accepted_transfers_that_are_never_mined_fail_the_run(self):
        s,problems=self.run_load(self.Node(mine=False))
        self.assertTrue(any('not mined within' in p for p in problems),problems)
    def test_too_few_accepted_fails_the_run(self):
        s,problems=self.run_load(self.Node(),min_accepted=31)
        self.assertTrue(any('only 30 accepted' in p for p in problems),problems)



class Joiner(unittest.TestCase):
    images={k:'sha256:'+'a'*64 for k in ['node','rpc','guard','signer']}
    def topology(self,n):
        with tempfile.TemporaryDirectory() as d:
            return generate.topology(Path(d),n,{'root':['r%d'%i for i in range(n)],'evm':['e%d'%i for i in range(n)]},self.images,'captcha',['--unicity.network-id','3'],123456,True)
    def test_the_joiner_services_are_exactly_what_a_generation_of_one_more_validator_writes(self):
        four,five=self.topology(4),self.topology(5)
        got=joiner.joiner_services(four,5,'r4','e4')
        want={n:five['services'][n] for n in ('pod5','metrics5','root5','authority5','ureth5','shard5')}
        self.assertEqual(sorted(got),sorted(want))
        for name in want: self.assertEqual(got[name],want[name],name)
    def test_prepare_makes_the_entity_private_to_its_owner_and_writes_the_override(self):
        import stat
        with tempfile.TemporaryDirectory() as d:
            gen=Path(d)/'gen';gen.mkdir();(gen/'compose.yaml').write_text(json.dumps(self.topology(4)))
            fake=Path(d)/'ubft'   # the three commands prepare runs: init (makes the home), credential (a file), node-id (prints one)
            fake.write_text("#!/usr/bin/env python3\nimport sys,os\na=sys.argv[1:]\n"
                            "if a[1]=='init': os.makedirs(a[a.index('--home')+1])\n"
                            "elif a[0]=='signing-authority': open(a[a.index('--out')+1],'w').write('c')\n"
                            "elif a[0]=='node-id': print('id-'+os.path.basename(a[a.index('--home')+1]))\n");fake.chmod(0o755)
            old=os.umask(0o022)   # a permissive caller: prepare must not inherit it
            try: out=joiner.prepare(gen,fake)
            finally: os.umask(old)
            self.assertEqual((out['index'],out['root'],out['evm']),(5,'id-root','id-evm'))
            val=gen/'validator5'
            for path in [val,*val.rglob('*')]:
                mode=stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode&0o077,0,f'{path} is accessible to group or others: {oct(mode)}')
            self.assertTrue((val/'jwt'/'jwt.hex').is_file())
            override=json.loads((gen/'compose.joiner.json').read_text())
            self.assertEqual(sorted(override['services']),['authority5','metrics5','pod5','root5','shard5','ureth5'])
            self.assertIn('id-evm',override['services']['authority5']['entrypoint'])
    def test_the_genesis_services_are_untouched_and_a_taken_index_is_refused(self):
        four=self.topology(4);before=json.dumps(four,sort_keys=True)
        joiner.joiner_services(four,5,'r4','e4')
        self.assertEqual(json.dumps(four,sort_keys=True),before)
        with self.assertRaisesRegex(ValueError,'already exists'): joiner.joiner_services(four,3,'x','y')
    def test_incomplete_bootnode_lists_are_refused_rather_than_guessed(self):
        four=self.topology(4)
        for name,svc in four['services'].items():
            if re.fullmatch(r'(root|shard)\d+',name): svc['entrypoint']=[re.sub(r'/dns4/root4/[^,]*,?','',p).rstrip(',') for p in svc['entrypoint']]
        with self.assertRaisesRegex(ValueError,'not all in the bootnode lists'): joiner.joiner_services(four,5,'r4','e4')

class Observe(unittest.TestCase):
    def sample(self,rounds,**kw):
        base={'roots':{str(i+1):{'epoch':1,'round':r} for i,r in enumerate(rounds)},'services':{'root1':{'state':'running','health':None,'restarts':0}},
              'disk_percent':40.0,'gateway':{'healthz':200,'block':self.block},'faucet':{'healthz':200,'body':'{}'}}
        self.block+=1   # the chain moves with every sample unless a test pins the gateway
        base.update(kw);return base
    block=0
    def setUp(self): self.block=0
    def test_a_healthy_sample_raises_nothing_and_a_head_that_moves_resets_the_stall_clock(self):
        w=observe.Watch(stall=120)
        self.assertEqual(w.step(self.sample([10,10,10,10]),0),[])
        self.assertEqual(w.step(self.sample([60,60,60,60]),100),[])
        self.assertEqual(w.step(self.sample([60,60,60,60]),200),[],'100 s since the last move is below the 120 s stall')
        self.assertTrue(any('stopped' in a and 'round 60' in a for a in w.step(self.sample([60,60,60,60]),230)))
    def test_one_root_moving_is_progress_and_a_root_without_a_head_is_an_alert(self):
        w=observe.Watch(stall=120);w.step(self.sample([10,10,10,10]),0)
        alerts=w.step(self.sample([50,10,10,10]),500)
        self.assertEqual(alerts,[],'the heads are the certified chain: one root ahead is progress')
        self.assertTrue(any('root 2 gave no certified head' in a for a in w.step(self.sample([60],roots={'1':{'round':60,'epoch':1},'2':{'error':'x'}}),510)))
    def test_a_down_unhealthy_or_restarted_service_disk_and_gateway_are_alerts(self):
        w=observe.Watch();w.step(self.sample([1]),0)
        bad=self.sample([2],services={'root1':{'state':'exited','health':None,'restarts':0},'shard1':{'state':'running','health':'unhealthy','restarts':3}},disk_percent=91.0,
                        gateway={'healthz':503,'block':None},faucet={'healthz':0,'body':'URLError'})
        text=' | '.join(w.step(bad,10))
        for part in ('root1 is exited','shard1 is unhealthy','disk 91.0%','gateway /healthz answered 503','faucet /healthz answered 0'): self.assertIn(part,text)
        self.assertTrue(any('root1 restarted (0 -> 1)' in a for a in w.step(self.sample([3],services={'root1':{'state':'running','health':None,'restarts':1}}),20)))
        self.assertFalse(any('restarted' in a for a in w.step(self.sample([4],services={'root1':{'state':'running','health':None,'restarts':1}}),30)),'an unchanged count is not a restart')
    def test_roots_moving_while_the_execution_chain_does_not_is_an_alert(self):
        w=observe.Watch(stall=120)
        pinned={'healthz':200,'block':5}
        for at,round_ in ((0,10),(60,70),(100,110)): self.assertEqual(w.step(self.sample([round_]*4,gateway=pinned),at),[],'the chain at block 5 for under 120 s from the start')
        alerts=w.step(self.sample([310]*4,gateway=pinned),130)
        self.assertTrue(any('execution chain stopped' in a and 'block past 5' in a for a in alerts))
        self.assertFalse(any('certified heads stopped' in a for a in alerts),'the roots did move')
        self.assertEqual(w.step(self.sample([320]*4,gateway={'healthz':200,'block':6}),140),[],'a block that moves clears it')
    def test_an_unreadable_gateway_block_is_an_alert_with_its_status(self):
        alerts=observe.Watch().step(self.sample([1],gateway={'healthz':200,'block':None,'block_status':'403 forbidden'}),0)
        self.assertTrue(any('gateway block is unreadable: 403 forbidden' in a for a in alerts))
    def test_the_block_request_carries_the_forwarded_address_the_gateway_requires(self):
        seen={}
        def fake(host,path,body=None,timeout=10,headers=None):
            seen['headers']=headers;return 200,'{"result":"0x7"}'
        with patch.object(observe,'get',fake), patch.object(observe.shutil,'disk_usage',lambda p:type('U',(),{'used':1,'total':10})()), patch.object(observe.subprocess,'run',lambda *a,**k:type('R',(),{'stdout':''})()):
            with tempfile.TemporaryDirectory() as d:
                Path(d,'compose.yaml').write_text(json.dumps({'name':'p','services':{}}))
                sample=observe.collect(d,type('T',(),{'entities':[]})(),faucet=False)
        self.assertEqual(seen['headers'],{'X-Forwarded-For':observe.CLIENT_IP});self.assertEqual(sample['gateway']['block'],7)
    def test_a_service_with_no_container_is_an_alert_and_ps_is_read_in_both_forms(self):
        self.assertTrue(any('signer has no container' in a for a in observe.Watch().step(self.sample([1],missing=['signer']),0)))
        row={'Service':'root1','State':'running','ID':'x'}
        self.assertEqual(observe.ps_rows(json.dumps([row])),[row],'an array')
        self.assertEqual(observe.ps_rows(json.dumps(row)+'\n'+json.dumps(row)),[row,row],'one object per line')
        self.assertEqual(observe.ps_rows(''),[])
    def test_the_faucet_can_be_left_out(self):
        s=self.sample([1]);del s['faucet']
        self.assertEqual(observe.Watch().step(s,0),[])

class PosSample(unittest.TestCase):
    def pos(self,**kw):
        base={'progress':100,'ucTime':50,'recordCount':3,'recordCursor':3,'liveCount':4,'thresholds':['500','300'],'openResult':None,
              'pool':{'balance':'1000','available':'900','totalCredits':'100','accounted':'1000','nextStart':'0'},'errors':[]}
        base.update(kw);return base
    def test_a_healthy_sample_raises_nothing_and_progress_moving_resets_the_stall(self):
        w=pos_sample.PosWatch(stall=120)
        self.assertEqual(w.step(self.pos(progress=10),0),[])
        self.assertEqual(w.step(self.pos(progress=11),100),[])
        self.assertEqual(w.step(self.pos(progress=11),200),[],'100 s since it last moved is under the stall')
        self.assertTrue(any('registry progress stopped at 11' in a for a in w.step(self.pos(progress=11),230)))
    def test_a_custody_behind_the_registry_is_an_alert_only_after_the_lag_and_catching_up_clears_it(self):
        w=pos_sample.PosWatch(lag=300)
        self.assertEqual(w.step(self.pos(recordCount=5,recordCursor=3),0),[])
        self.assertEqual(w.step(self.pos(progress=101,recordCount=5,recordCursor=3),299),[])
        self.assertTrue(any('custody is behind' in a and '3 of 5' in a for a in w.step(self.pos(progress=102,recordCount=5,recordCursor=3),300)))
        self.assertEqual(w.step(self.pos(progress=103,recordCount=5,recordCursor=5),310),[],'caught up')
        self.assertEqual(w.step(self.pos(progress=104,recordCount=6,recordCursor=5),320),[],'the lag clock starts again')
        self.assertTrue(any('past the registry' in a for a in w.step(self.pos(progress=105,recordCount=3,recordCursor=4),330)))
    def test_an_election_result_open_too_long_is_an_alert_and_resolving_it_clears_it(self):
        w=pos_sample.PosWatch(open_limit=3600);r='0x'+'ab'*32
        self.assertEqual(w.step(self.pos(openResult=r),0),[])
        self.assertTrue(any('open for 3600 s' in a for a in w.step(self.pos(progress=101,openResult=r),3600)))
        self.assertEqual(w.step(self.pos(progress=102),3700),[],'resolved')
        self.assertEqual(w.step(self.pos(progress=103,openResult=r),3800),[],'a new opening is timed from its own start')
    def test_the_pool_books_and_unreadable_views_are_alerts(self):
        w=pos_sample.PosWatch()
        short=self.pos(pool={'balance':'999','available':'900','totalCredits':'100','accounted':'1000','nextStart':'0'})
        self.assertTrue(any('less than the 1000 it has accounted for' in a for a in w.step(short,0)))
        self.assertTrue(any('no funded balance left' in a for a in w.step(self.pos(progress=101,pool={'balance':'5','available':'0','totalCredits':'5','accounted':'5','nextStart':'1'}),10)),'0 after it was funded')
        unfunded=pos_sample.PosWatch()
        self.assertEqual(unfunded.step(self.pos(pool={'balance':'0','available':'0','totalCredits':'0','accounted':'0','nextStart':'0'}),0),[],'a pool never funded is not exhausted')
        alerts=w.step({'errors':['recordCursor: eth_call: 403 forbidden'],'pool':{}},30)
        self.assertEqual(alerts,['unreadable: recordCursor: eth_call: 403 forbidden'])
    def test_collect_reads_the_views_through_the_gateway_and_records_a_refused_one(self):
        def word(n): return '0x'+format(n,'064x')
        by_selector={pos_sample.SELECTORS['progress']:word(7),pos_sample.SELECTORS['ucTime']:word(70),pos_sample.SELECTORS['recordCount']:word(4),
                     pos_sample.SELECTORS['recordCursor']:word(4),pos_sample.SELECTORS['liveCount']:word(4),pos_sample.SELECTORS['thresholds']:word(500)+word(300)[2:],
                     pos_sample.SELECTORS['openResult']:word(0),pos_sample.SELECTORS['available']:word(10**18),pos_sample.SELECTORS['totalCredits']:word(2),
                     pos_sample.SELECTORS['accounted']:word(10**18+2),pos_sample.SELECTORS['nextStart']:word(1000)}
        refuse=set()
        def fake(method,params):
            if method=='eth_getBalance': return hex(10**18+2)
            data=params[0]['data']
            if data in refuse: raise ValueError('eth_call: 403 forbidden')
            return by_selector[data]
        with tempfile.TemporaryDirectory() as d:
            Path(d,'network').mkdir();Path(d,'network','pos-deployment.json').write_text(json.dumps({'custody':'0xc','election':'0xe','rewardPool':'0xp'}))
            with patch.object(pos_sample,'eth',fake):
                got=pos_sample.pos_collect(d)
                refuse.add(pos_sample.SELECTORS['recordCursor'])
                bad=pos_sample.pos_collect(d)
        self.assertEqual((got['progress'],got['recordCount'],got['recordCursor'],got['openResult'],got['thresholds']),(7,4,4,None,['500','300']))
        self.assertEqual(got['pool'],{'available':str(10**18),'totalCredits':'2','accounted':str(10**18+2),'nextStart':'1000','balance':str(10**18+2)},'wei amounts are decimal strings')
        self.assertEqual(got['errors'],[])
        self.assertNotIn('recordCursor',bad);self.assertEqual(bad['errors'],['recordCursor: eth_call: 403 forbidden'])
    def test_a_rate_limited_call_is_retried_and_a_persistent_refusal_is_named(self):
        answers=[(429,'{"error":"rate limit"}'),(429,'{"error":"rate limit"}'),(200,'{"result":"0x01"}')]
        sleeps=[]
        with patch.object(observe,'get',lambda *a,**k:answers.pop(0)), patch.object(pos_sample.time,'sleep',sleeps.append):
            self.assertEqual(pos_sample.eth('eth_blockNumber',[]),'0x01')
        self.assertEqual(len(answers),0);self.assertGreaterEqual(sleeps.count(1),2,'a 429 waits a second before the retry')
        calls=[]
        def refuse(*a,**k): calls.append(1);return 429,'{"error":"rate limit"}'
        with patch.object(observe,'get',refuse), patch.object(pos_sample.time,'sleep',lambda s:None):
            with self.assertRaises(ValueError) as e: pos_sample.eth('eth_blockNumber',[])
        self.assertIn('429',str(e.exception));self.assertEqual(len(calls),pos_sample.RETRIES+1,'bounded retries')
    def test_not_healthy_lists_services_whose_healthcheck_has_not_reported_healthy(self):
        rows=[{'Service':'rpc','Health':'starting'},{'Service':'root1','Health':'healthy'},{'Service':'shard1','Health':''},{'Service':'x'},{'Service':'ureth1','Health':'unhealthy'}]
        with patch.object(pos_sample.subprocess,'run',lambda *a,**k:type('R',(),{'stdout':'\n'.join(json.dumps(x) for x in rows)})()):
            self.assertEqual(pos_sample.not_healthy('/g'),{'rpc':'starting','ureth1':'unhealthy'})
    def test_the_observe_stage_waits_for_the_health_checks_and_names_what_never_reports(self):
        import rehearse
        waits=[]
        class Fake:
            evidence=Path(tempfile.mkdtemp());gen=Path('/g')
            def say(self,x): pass
            def expect(self,ok,what,detail=''):
                if not ok: raise rehearse.Failure(what+' '+detail)
            def wait(self,what,probe,seconds):
                waits.append((what,seconds));
                for _ in range(3):
                    if probe(): return True
                raise rehearse.Failure(what)
        states=[{'rpc':'starting'},{'rpc':'starting'},{}]
        calls=[]
        def health(g): calls.append(1);return states[min(len(calls)-1,2)]
        def fail(*a,**k): raise AssertionError('the sampler must not start before the services are healthy')
        with patch.object(pos_sample,'not_healthy',lambda g:{'rpc':'starting'}), patch.object(pos_sample.subprocess,'run',fail):
            with self.assertRaises(rehearse.Failure) as e: pos_sample.pos_observe(Fake())
        self.assertIn("rpc",str(e.exception));self.assertEqual(waits[-1],('every healthchecked service is healthy',180))
        waits.clear()
        with patch.object(pos_sample,'not_healthy',health), patch.object(pos_sample.subprocess,'run',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('sampler started'))):
            with self.assertRaises(RuntimeError): pos_sample.pos_observe(Fake())   # healthy on the third look: only then does it start the sampler
        self.assertEqual(len(calls),3)
    def test_pos_crash_scans_logs_and_runs_before_the_stage_that_must_stay_last(self):
        import rehearse
        self.assertEqual(pos_crash.scan_log("ok\nlevel=error msg=x\nthread 'main' panicked at src/x.rs\nWARN y\npanic: boom\n"),(2,2))
        self.assertEqual(pos_crash.scan_log("all quiet\n"),(0,0))
        names=[n for n,_ in rehearse.POS_STAGES]
        self.assertEqual(names[-1],'pos-owner','pos-owner declares a retirement: nothing may follow it')
        for name,_ in pos_crash.STAGES:
            self.assertLess(names.index('pos-recreate'),names.index(name));self.assertLess(names.index(name),names.index('pos-owner'))
            self.assertTrue(callable(getattr(rehearse.Rehearsal,dict(rehearse.POS_STAGES)[name])),name)
        workflow=(generate.REPO/'.github/workflows/testnet-rehearsal.yml').read_text()
        default=re.search(r'POS_STAGES:-([^}]*)\}',workflow).group(1).split(',')
        for name,_ in pos_crash.STAGES: self.assertNotIn(name,default,'the crash stages are opt-in: bft-core #843 fails today')
    def test_restart_counts_reads_each_container_and_reports_a_missing_one(self):
        class R:
            def compose(self,*a,check=True): return {'ureth2':'abc\n','root2':'def\n'}.get(a[-1],'')
        def run(cmd,**k): return type('P',(),{'stdout':{'abc':'3\n','def':'x\n'}[cmd[-1]]})()
        with patch.object(pos_crash.subprocess,'run',run):
            self.assertEqual(pos_crash.restart_counts(R(),['ureth2','root2','shard2']),{'ureth2':3,'root2':None,'shard2':None})
    def test_a_result_that_is_not_whole_words_is_refused(self):
        with self.assertRaises(ValueError): pos_sample.words('0x'+'00'*31)
        with self.assertRaises(ValueError): pos_sample.words('0x')
    def test_the_selectors_are_cast_sig_of_the_views(self):
        import shutil
        cast=shutil.which('cast') or str(Path.home()/'.foundry'/'bin'/'cast')
        if not Path(cast).exists(): self.skipTest('cast is not installed')
        for name,selector in pos_sample.SELECTORS.items():
            self.assertEqual(subprocess.run([cast,'sig',name+'()'],text=True,capture_output=True,check=True).stdout.strip(),selector,name)

if __name__=='__main__': unittest.main()
