#!/usr/bin/env python3
"""Run the testnet package's retry-aware creation over this paired lane's local Cast transport."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/testnet/bridge/nb2'))
from deploy_nb2 import create  # noqa: E402

rpc, keydir, label = sys.argv[1:]
assert ipaddress.ip_address(urlsplit(rpc).hostname).is_loopback
keydir = Path(keydir)
initcode = sys.stdin.read().strip()


def local_cast(_generation, *args, capture=False):
    args = list(args)
    for flag, value in (
        ('--rpc-url', rpc),
        ('--keystore', str(keydir / 'sender')),
        ('--password-file', str(keydir / 'password')),
    ):
        args[args.index(flag) + 1] = value
    return subprocess.run(args, check=True, text=True, capture_output=capture).stdout


print(json.dumps(create(None, initcode, label, transport=local_cast)))
