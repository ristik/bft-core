#!/usr/bin/env python3
"""Quiesced backup/restore with LIVE signing authorities; never a host-loss recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def compose(generation,*args):
    return subprocess.check_output(['docker','compose','-f',str(generation/'compose.yaml'),*args],text=True)

def status(generation):
    config=json.loads((generation/'compose.yaml').read_text())
    authorities=[name for name in config['services'] if name.startswith('authority')]
    running=set(compose(generation,'ps','--services','--status','running').split())
    if running != set(authorities):
        raise ValueError('keep ALL authorities live and ALL other services stopped before backup/restore')
    result={}
    for name in authorities:
        result[name]=json.loads(compose(generation,'exec','-T',name,'ubft','signing-authority','status',
            '--operator-socket','/authority/operator.sock','--operator-credential','/authority/operator.cred'))
        if not result[name]['enrollmentComplete'] or result[name]['faulted'] or result[name]['keyLost']:
            raise ValueError('authority is not enrolled and healthy: '+name)
    return result

def extract(archive,generation):
    if generation.exists(): raise ValueError('restore target must not exist')
    expected=archive.with_suffix(archive.suffix+'.sha256').read_text().strip()
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected: raise ValueError('backup digest mismatch')
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            name=Path(member.name)
            if name.is_absolute() or '..' in name.parts or name.parts[0]!='generation' or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe archive member')
        generation.mkdir(parents=True,mode=0o700)
        for member in tar.getmembers():
            relative=Path(*Path(member.name).parts[1:])
            target=generation/relative
            if member.isdir(): target.mkdir(exist_ok=True,parents=True)
            else:
                target.parent.mkdir(exist_ok=True,parents=True)
                target.write_bytes(tar.extractfile(member).read())
            target.chmod(member.mode & 0o777)
    manifest=json.loads((generation/'manifest.json').read_text())
    for name,digest in manifest['config_sha256'].items():
        if hashlib.sha256((generation/'network'/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('restored network manifest mismatch: '+name)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['backup','restore'])
    p.add_argument('generation',type=Path)
    p.add_argument('archive',type=Path)
    p.add_argument('--live-generation',type=Path,help='required on restore: original path with surviving authorities')
    a=p.parse_args()
    generation=a.generation.resolve(); archive=a.archive.resolve()
    if a.action=='backup':
        if archive.exists() or generation in archive.parents:
            p.error('new backup must be outside generation directory')
        manifest=json.loads((generation/'manifest.json').read_text())
        if manifest.get('offline_validation_only'): p.error('offline fixture cannot be backed up as live')
        config=json.loads((generation/'compose.yaml').read_text())
        stopped=[name for name in config['services'] if not name.startswith('authority')]
        compose(generation,'stop',*stopped)
        authority_status=status(generation)
        (generation/'backup-authorities.json').write_text(json.dumps(authority_status,indent=2)+'\n')
        def keep(info):
            # Credentials are not authority keys/state. Do not archive open sockets/locks.
            return None if info.name.endswith(('.sock','.sock.lock')) else info
        with tarfile.open(archive,'w:gz') as tar:
            tar.add(generation,arcname='generation',filter=keep)
        archive.chmod(0o600)
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(archive.suffix+'.sha256').write_text(digest+'\n')
        print('Non-authority services stopped; authorities MUST stay live. SHA256:',digest)
    else:
        if a.live_generation is None: p.error('--live-generation required; host-loss restore is impossible with memory-only signing keys')
        live=a.live_generation.resolve()
        current=status(live)
        extract(archive,generation)
        previous=json.loads((generation/'backup-authorities.json').read_text())
        if current!=previous: p.error('authority lifetime/state advanced since backup: use H6 archive replay, or fresh reset')
        live_manifest=json.loads((live/'manifest.json').read_text())
        manifest=json.loads((generation/'manifest.json').read_text())
        if live_manifest['genesis_hash']!=manifest['genesis_hash']: p.error('surviving authority network differs')
        config=json.loads((generation/'compose.yaml').read_text())
        for svc in config['services'].values():
            svc['volumes']=[str(live / mount.split(':')[0][2:])+':/authority' if mount.endswith('/auth:/authority') else mount for mount in svc['volumes']]
        (generation/'compose.yaml').write_text(json.dumps(config,indent=2)+'\n')
        print('Restored offline. Authority mounts point to surviving original lifetimes. Chown restored files, then start non-authority services ONLY.')

if __name__=='__main__': main()
