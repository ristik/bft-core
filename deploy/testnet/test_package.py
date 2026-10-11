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
