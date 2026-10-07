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
new=Path(args[args.index('--out')+1]).resolve()
if new.exists() or old==new or old in new.parents or new in old.parents:
    p.error('new generation must be a distinct, nonexistent directory')
subprocess.run(['docker','compose','-f',str(old/'compose.yaml'),'down'],check=True)
old.with_suffix('.retired-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
shutil.rmtree(old)
subprocess.run([sys.executable,str(Path(__file__).with_name('generate.py')),*args],check=True)
print('Old balances, transactions and keys destroyed. Publish new wallet/network pins before opening routing.')
