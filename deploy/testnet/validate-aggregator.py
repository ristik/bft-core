#!/usr/bin/env python3
"""CI-only native root/aggregator probe; no EVM or deployable authority lifetime.

Use the generated partition, keys and environment. Only transport addresses and
host paths change. Success requires a root-certified nonempty SMT transition,
not merely HTTP admission or an aggregator health response.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

import generate

# Canonical absent-deadline SDK request used by the pinned F8 mixed-lane probe.
REQUEST = 'd9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820c034e096d7bdf71ba759558663b5cafb7279ecb7e284443e5e6cbce0461aceeef6584154ca6b19a7dbcae7a6adc38af5c8672f81943ecaf51345436684299b4b7ac81a57db2653f32048981e37913db4749ca08d998d1fac4a52ab5579988bc2c50de90000'
STATE_ID = 'ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81a'


def get(url, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data, {'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def validate(generation, ubft, aggregator):
    cfg = json.loads((generation/'compose.yaml').read_text())
    processes = []
    logs = []

    def launch(name, command, env=None):
        path = generation/(name+'.log')
        logs.append(path)
        log = path.open('w')
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        processes.append((proc, log))

    def wait_for(probe):
        deadline = time.monotonic()+120
        last = None
        while time.monotonic() < deadline:
            if any(proc.poll() is not None for proc, _ in processes):
                raise RuntimeError('native service exited')
            try:
                result = probe()
                if result:
                    return result
                last = result
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last = str(exc)
            time.sleep(1)
        raise RuntimeError(f'certification probe timed out: {last}')

    try:
        n = json.loads((generation/'manifest.json').read_text())['validators']
        for i in range(1,n+1):
            command = cfg['services'][f'root{i}']['entrypoint'].copy()
            command[0] = str(ubft)
            for j, arg in enumerate(command):
                arg = arg.replace('/state',str(generation/f'validator{i}/root'))
                arg = arg.replace('/network',str(generation/'network'))
                arg = re.sub(r'/dns4/root(\d+)/tcp/8000',lambda m:f'/ip4/127.0.0.1/tcp/{23000+int(m[1])}',arg)
                command[j] = arg.replace('/ip4/0.0.0.0/tcp/8000',f'/ip4/127.0.0.1/tcp/{23000+i}').replace('0.0.0.0:8002',f'127.0.0.1:{23100+i}')
            launch(f'root{i}',command)
        env = {k:v for k,v in os.environ.items() if not k.startswith('AGGREGATOR_')}
        env.update(cfg['services']['aggregator']['environment'])
        for line in (generation/'aggregator/secrets.env').read_text().splitlines():
            key,value = line.split('=',1)
            env[key] = value
        env.update(AGGREGATOR_LISTEN='127.0.0.1:23200',
                   AGGREGATOR_BFT_ADDR='/ip4/127.0.0.1/tcp/23001',
                   AGGREGATOR_P2P_ADDR='/ip4/127.0.0.1/tcp/0',
                   AGGREGATOR_DB_PATH=str(generation/'aggregator/db'))
        # Clap renders the effective environment value in this pinned binary's help.
        help_text = subprocess.check_output([str(aggregator),'--help'],env=env,text=True)
        assert '[env: AGGREGATOR_CONSISTENCY_PROOF_MODE=rsmt]' in help_text, 'pinned binary did not resolve generated RSMT environment'
        assert json.loads((generation/'network/aggregator-conf.json').read_text())['partitionParams']['proof_type']=='aggregator_rsmt_v1'
        launch('aggregator',[str(aggregator)],env)
        root_url = 'http://127.0.0.1:23101/api/v1/roundInfo'
        def certified():
            return next((row for row in get(root_url)['partitionShards'] if row['partitionId']==9 and row['shardId'].lower()=='0x80'),None)
        before = wait_for(certified)
        rpc_url = 'http://127.0.0.1:23200/'
        def submit():
            result = get(rpc_url,{'jsonrpc':'2.0','id':1,'method':'certification_request','params':REQUEST})
            if result.get('error',{}).get('message')=='SERVICE_NOT_READY':
                return False
            assert result.get('result',{}).get('status')=='SUCCESS', result
            return True
        wait_for(submit)
        def included():
            result = get(rpc_url,{'jsonrpc':'2.0','id':2,'method':'get_inclusion_proof.v2','params':{'stateId':STATE_ID}})
            return isinstance(result.get('result'),str) and bool(result['result'])
        wait_for(included)
        def advanced():
            after = certified()
            return after if after and int(after['roundNumber'])>int(before['roundNumber']) and after['stateRoot']!=before['stateRoot'] else False
        after = wait_for(advanced)
        print(json.dumps({'native_aggregator_nonempty_certification':'PASS','before':before,'after':after}))
    except BaseException:
        for path in logs:
            print(f'--- {path.name} ---\n{path.read_text()[-24000:]}')
        raise
    finally:
        for proc, _ in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc, log in processes:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
            log.close()
