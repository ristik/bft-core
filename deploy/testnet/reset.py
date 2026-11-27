#!/usr/bin/env python3
"""ASSET-LOSING reset. Removes a stopped, generated network and makes a fresh one."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--old',required=True,type=Path)
p.add_argument('--lose-all-assets',action='store_true',required=True)
p.add_argument('--disposable',action='store_true',help='the old generation is a disposable one WITHOUT a signed history (made with --no-utb, no root-genesis '
               'pin): the replacement starts a fresh retired-key inventory (generate.py --first-generation). Refused for a generation that has a UTB pin, '
               'whose reset always needs its own verified history (#1297)')
p.add_argument('generator_args',nargs=argparse.REMAINDER)
a=p.parse_args()
old=a.old.resolve()
manifest=json.loads((old/'manifest.json').read_text())
if not manifest.get('genesis_hash') or not (old/'compose.yaml').is_file() or not old.name.startswith('tn-'):
    p.error('old path must be a generated tn-* directory')
args=a.generator_args
if args[:1]==['--']: args=args[1:]
# Preflight new generation args before deleting anything.
if '--out' not in args: p.error('supply generator --out for a new generation')
# the image records must be the ones of the profile the replacement is generated with, for EVERY profile (--no-utb needs the integration images):
# generate.py would refuse them only after the teardown. The variant choices are the generator's own.
sys.path.insert(0,str(Path(__file__).resolve().parent))
import generate
q=argparse.ArgumentParser(add_help=False)
q.add_argument('--images',type=Path,default=generate.HERE/'artifacts/images.json')
q.add_argument('--utb',action=argparse.BooleanOptionalAction,default=True)
q.add_argument('--utb-aggregator',choices=generate.UTB_AGGREGATORS,default='integration')
known,_=q.parse_known_args(args)
if not known.utb and known.utb_aggregator!='integration': p.error('--utb-aggregator needs --utb')
if not known.images.is_file(): p.error(f'image records {known.images} not found')
err=generate.image_sources_error(json.loads(known.images.read_text()),known.utb_aggregator if known.utb else 'integration')
if err: p.error(err)
# #1297: the replacement's retired-key inventory needs the old generation's signed UTB history (every epoch's root keys, joins and rotations
# included): export and verify it BEFORE the teardown (deploy/testnet/README.md, "Retired root keys"); generate.py refuses only after it
import root_keys
priors=[Path(args[i+1]) for i,x in enumerate(args[:-1]) if x=='--prior-generation']
if '--first-generation' in args: p.error('a reset replaces an existing root history: pass its UTB history keys as --prior-generation, not --first-generation')
kept=[]
if a.disposable:
    # a throwaway rehearsal generation with no signed history: nothing can bind an inventory to it, and its keys were made fresh
    if root_keys.generation_pin(old) or manifest.get('utb'):
        p.error('--disposable is only for a generation without a signed history; this one has a root-genesis pin: pass its verified UTB history keys')
    if priors: p.error('--disposable starts a fresh inventory: give no --prior-generation')
    args=args+['--first-generation']
elif not any(root_keys.is_history(x) for x in priors):
    p.error('supply --prior-generation <utb-verify --keys-out file of the old generation> before anything is deleted')
# the history must be THIS generation's, complete through its newest installed epoch (a stale export or a truncated --url read is refused)
why=None if a.disposable else root_keys.bind_to_generation([x for x in priors if root_keys.is_history(x)],old)
if why: p.error(why)
# the old generation's inherited list and its genesis keys are part of the inventory: kept beside it and passed on, never optional
for name,src in (('retired-root-keys.json',old/'network'/root_keys.FILE),('retired-root-signing-keys.json',old/'manifest.json')):
    if a.disposable:
        break
    if src==old/'manifest.json' and not manifest.get('root_signing_keys'):
        continue
    if src.is_file():
        try:
            root_keys.load(src)
        except (ValueError,KeyError,root_keys.RetiredKeyError) as error:
            p.error(f'{src}: {error}')
        kept.append((old.with_suffix('.'+name),src))
args=args+[x for dst,_ in kept for x in ('--prior-generation',str(dst))]
new=Path(args[args.index('--out')+1]).resolve()
if new.exists() or old==new or old in new.parents or new in old.parents:
    p.error('new generation must be a distinct, nonexistent directory')
subprocess.run(['docker','compose','-f',str(old/'compose.yaml'),'down'],check=True)
old.with_suffix('.retired-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for dst,src in kept:
    shutil.copyfile(src,dst)
shutil.rmtree(old)
subprocess.run([sys.executable,str(Path(__file__).with_name('generate.py')),*args],check=True)
print('Old balances, transactions and keys destroyed. Publish new wallet/network pins before opening routing.')
