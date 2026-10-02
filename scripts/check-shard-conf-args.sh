#!/usr/bin/env bash
# Self-test for helper.sh collect_shard_conf_args: no shard-conf files means no --shard-conf argument (never the literal glob),
# and every existing file is passed once, in order. Run from the repository root.
set -euo pipefail
repo=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fn=$(sed -n '/^function collect_shard_conf_args()/,/^}/p' "$repo/helper.sh")
[ -n "$fn" ] || { echo "FAIL: collect_shard_conf_args is not defined in helper.sh" >&2; exit 1; }
cd "$work"
mkdir test-nodes
eval "$fn"
collect_shard_conf_args
[ "${#shardConfArgs[@]}" -eq 0 ] || { echo "FAIL: ${#shardConfArgs[@]} arguments without any shard-conf file: ${shardConfArgs[*]}" >&2; exit 1; }
echo "PASS: no shard-conf files, no --shard-conf argument"
touch test-nodes/shard-conf-8_0.json test-nodes/shard-conf-f8-a-left.json
collect_shard_conf_args
want="--shard-conf test-nodes/shard-conf-8_0.json --shard-conf test-nodes/shard-conf-f8-a-left.json"
[ "${shardConfArgs[*]}" = "$want" ] || { echo "FAIL: got '${shardConfArgs[*]}', want '$want'" >&2; exit 1; }
echo "PASS: every existing shard-conf file is passed once"
