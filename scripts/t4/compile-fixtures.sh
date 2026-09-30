#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
SOURCE=$SCRIPT_DIR/T4SelfDestructFixtures.sol
OUT_DIR=${1:?usage: compile-fixtures.sh OUTPUT_DIR}
EXPECTED_SOLC='0.8.28+commit.7893614a.Emscripten.clang'

mkdir -p "$OUT_DIR"
actual_solc=$(npx --yes --package=solc@0.8.28 solcjs --version)
[[ "$actual_solc" == "$EXPECTED_SOLC" ]] || {
  echo "unexpected T4 Solidity compiler: $actual_solc (want $EXPECTED_SOLC)" >&2
  exit 1
}
printf '%s\n' "$actual_solc" >"$OUT_DIR/solc-version.txt"

python3 - "$SOURCE" "$OUT_DIR/solc-input.json" <<'PY'
import json,sys
source=open(sys.argv[1],encoding="utf-8").read()
input_data={"language":"Solidity","sources":{"T4SelfDestructFixtures.sol":{"content":source}},
 "settings":{"optimizer":{"enabled":True,"runs":200},"evmVersion":"cancun",
 "outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
with open(sys.argv[2],"w",encoding="utf-8") as out:
    json.dump(input_data,out,separators=(",",":"))
    out.write("\n")
PY

npx --yes --package=solc@0.8.28 solcjs --standard-json \
  <"$OUT_DIR/solc-input.json" >"$OUT_DIR/solc-output.json"

python3 - "$OUT_DIR/solc-output.json" "$OUT_DIR" <<'PY'
import json,sys
raw=open(sys.argv[1],encoding="utf-8").read()
start=raw.find("{")
if start < 0:
    raise SystemExit("solc emitted no standard-JSON object")
output=json.loads(raw[start:])
errors=[item for item in output.get("errors",[]) if item.get("severity")=="error"]
if errors:
    raise SystemExit("\n".join(item.get("formattedMessage",str(item)) for item in errors))
contracts=output.get("contracts",{}).get("T4SelfDestructFixtures.sol",{})
expected={"SameTransactionSelfDestructToSelf","ExistingSelfDestruct"}
if set(contracts)!=expected:
    raise SystemExit(f"compiled contracts differ from expected set: {sorted(contracts)}")
for name,data in contracts.items():
    bytecode=data.get("evm",{}).get("bytecode",{}).get("object","")
    if not bytecode or len(bytecode)%2:
        raise SystemExit(f"compiler emitted invalid creation bytecode for {name}")
    with open(f"{sys.argv[2]}/{name}.bin","w",encoding="ascii") as out:
        out.write("0x"+bytecode+"\n")
    with open(f"{sys.argv[2]}/{name}.abi.json","w",encoding="utf-8") as out:
        json.dump(data["abi"],out,indent=2)
        out.write("\n")
print("compiled Cancun fixtures with solc "+open(f"{sys.argv[2]}/solc-version.txt",encoding="utf-8").read().strip())
PY

shasum -a 256 "$SOURCE" "$OUT_DIR/solc-input.json" "$OUT_DIR/solc-output.json" \
  "$OUT_DIR/solc-version.txt" "$OUT_DIR/SameTransactionSelfDestructToSelf.bin" \
  "$OUT_DIR/ExistingSelfDestruct.bin" >"$OUT_DIR/SHA256SUMS"
