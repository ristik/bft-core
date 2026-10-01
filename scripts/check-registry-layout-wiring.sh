#!/usr/bin/env bash
# Static guard for the per-run SealRegistry layout (helper.sh registry_layout_*): every script that starts
# `shard-node run ... engine-api` or a ureth (`"$URETH_BIN" node`) must read/verify the layout persisted in
# test-nodes/registry-layout, and setup-evm-nodes.sh must resolve it. Run from the repository root.
set -euo pipefail
python3 - <<'PY'
import re, glob, sys
bad = []
files = sorted(glob.glob("scripts/*.sh") + glob.glob("scripts/lib/*.sh") + ["setup-evm-nodes.sh", "helper.sh"])
for path in files:
    lines = open(path, encoding="utf-8").read().split("\n")
    for i, line in enumerate(lines):
        code = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
        if line.lstrip().startswith("#") or "echo " in line or "pgrep" in line or "pkill" in line or "stop_" in line \
           or "signal_owned" in line or "pass " in line or "fail " in line:
            continue
        window = "\n".join(lines[max(0, i - 3):i + 6])
        if re.search(r'shard-node (run|restore)\b', line) and "engine-api" in window and "--executor" in window:
            if "--registry-layout" not in "\n".join(lines[i:i + 8]) and "layoutArgs" not in "\n".join(lines[i:i + 12]):
                bad.append(f"{path}:{i+1}: shard-node run/restore with engine-api without --registry-layout")
        if re.search(r'"\$URETH_BIN" node --chain', line) and "registry_layout_require" not in "\n".join(lines[max(0, i - 3):i + 1]):
            if not path.endswith("f6c-reth-backup-acceptance.sh"):
                bad.append(f"{path}:{i+1}: ureth start without registry_layout_require")
setup = open("setup-evm-nodes.sh", encoding="utf-8").read()
if "registry_layout_init" not in setup:
    bad.append("setup-evm-nodes.sh does not resolve the registry layout")
helper = open("helper.sh", encoding="utf-8").read()
for fn in ("generate_evm_genesis", "start_one_evm_validator"):
    m = re.search(r'function %s\(\) \{(.*?)\n\}' % fn, helper, re.S)
    if not m or "registry_layout_require" not in m.group(1):
        bad.append(f"helper.sh {fn} does not call registry_layout_require")
if bad:
    print("\n".join(bad)); sys.exit(1)
print("registry layout wiring OK")
PY
