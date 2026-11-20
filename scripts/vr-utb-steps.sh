#!/usr/bin/env bash
# The signed trust-base history (UTB) checks of a VR generation (VR_UTB=1, VR_AGG=1; briefs/impl-vr-utb.md). Sourced by scripts/vr-boundary-steps.sh,
# which defines vrb_log and runs in the paired devnet's shell (so agg-lib.sh, utb-lib.sh and m2_rpc_port are loaded). The independent verifier is
# utb-evidence (scripts/utb-evidence, UTB_EVIDENCE: a prebuilt binary); the SDK client is the JS SDK 4.0 (UTB_SDK_JS: a built package or checkout with
# lib/api/bft/trustbase/TrustBaseHistory.js). Nothing here trusts a node's own claim: every number comes from the history bytes a client would fetch.
#
#   vru_before   before the handoff: the aggregator holds epoch 1 only; a certificate of epoch 1 is saved (its digest is recorded) and verifies under it
#   vru_after    after the Boundary installed J: epochs 1 and 2 are served (the aggregator's /api/v1/trustbases; a root's own REST serves the V1 runtime
#                projection, so a root's signed history is read from its entry store below), epoch 2 is signed by epoch 1's quorum, it names the
#                committee the VR generation installed, the epoch-1 certificate still verifies under the history, a post-switch certificate verifies under epoch 2,
#                the SDK client holding the genesis alone fetches and verifies both, and a forged entry is refused; every root and shard node's own store
#                exports a history that verifies from the pin

vru_dir() { mkdir -p "$VR_EVIDENCE/utb" && echo "$VR_EVIDENCE/utb"; }
vru_fail() { vrb_log "FAIL: $*"; return 1; }
vru_ev() { "${UTB_EVIDENCE:?UTB_EVIDENCE (a built scripts/utb-evidence) is not set}" "$@"; }

vru_agg_tip() { local t; t=$(mktemp); if vru_ev fetch --url "$(utb_agg_url)" --out "$t" >/dev/null 2>&1; then vru_ev verify --bundle "$t" --pin "$(utb_pin)" 2>/dev/null | sed -n 's/^ok: epochs [0-9]*\.\.\([0-9]*\), tip.*/\1/p'; else echo 0; fi; rm -f "$t"; }
vru_wait_tip() { # want seconds
  local want=$1 i tip=0
  for i in $(seq 1 "$(($2 / 2))"); do tip=$(vru_agg_tip); [ "${tip:-0}" -ge "$want" ] && return 0; sleep 2; done
  vrb_log "the aggregator serves tip ${tip:-0}, expected >= $want"; tail -c 3000 "$(utb_agg_log)" >&2; return 1
}
vru_confs() { # OUT: the shard configurations certificates are verified against (the EVM shard's, the aggregator's)
  local out=$1; mkdir -p "$out/manifest"
  cp test-nodes/evm-full-shard-conf-v2.json "$out/manifest/shard-conf.json" && cp "$(agg_conf 1)" "$out/manifest/shard-conf-aggregator.json" || return 1
  utb_manifest_confs "$out"
}

vru_before() {
  local out i; out=$(vru_dir); mkdir -p "$out"/{bundle,proofs,entries,sdk,stores}
  [ -x "${UTB_EVIDENCE:-}" ] || { vru_fail "UTB_EVIDENCE ($UTB_EVIDENCE) is not built"; return 1; }
  vru_wait_tip 1 120 || return 1
  vru_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/initial.cbor" || return 1
  vru_ev verify --bundle "$out/bundle/initial.cbor" --pin "$(utb_pin)" | tee "$out/bundle/initial.verify.txt"
  grep -q '^ok: epochs 1\.\.1,' "$out/bundle/initial.verify.txt" || { vru_fail "the aggregator holds more than the genesis before the handoff"; return 1; }
  for i in $(seq 1 30); do grep -aq '"msg":"Signed trust-base history loaded"' "$(utb_agg_log)" && break; sleep 1; done
  grep -aq '"msg":"Signed trust-base history loaded"' "$(utb_agg_log)" || { vru_fail "the aggregator did not report its history loaded from the pinned genesis"; return 1; }
  for i in $(seq 1 30); do utb_agg_latest_uc "$out/proofs/epoch1-token.cbor" && break; sleep 2; done
  [ -s "$out/proofs/epoch1-token.cbor" ] || { vru_fail "the aggregator served no block certificate within 60 s"; return 1; }
  shasum -a 256 "$out/proofs/epoch1-token.cbor" | cut -d' ' -f1 >"$out/proofs/epoch1-token.sha256"
  vru_ev uc-verify --token "$out/proofs/epoch1-token.cbor" --bundle "$out/bundle/initial.cbor" --shard-conf "$(vru_confs "$out")" | tee "$out/proofs/epoch1-before-switch.txt" || return 1
  grep -q '^certificate 0: epoch 1 ' "$out/proofs/epoch1-before-switch.txt" || { vru_fail "the saved certificate is not one of epoch 1"; return 1; }
  vrb_log "PASS: before the handoff the aggregator holds epoch 1 from the pin; an epoch-1 certificate ($(cut -c1-12 "$out/proofs/epoch1-token.sha256")...) verifies under it"
}

vru_after() {
  local out i n t rc; out=$(vru_dir)
  vru_wait_tip 2 300 || return 1
  vru_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/final.cbor" || return 1
  vru_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | tee "$out/bundle/final.verify.txt" || return 1
  grep -q '^ok: epochs 1\.\.2,' "$out/bundle/final.verify.txt" || { vru_fail "the aggregator's history is not epochs 1..2 verified from the pin"; return 1; }
  grep '^epoch 2 ' "$out/bundle/final.verify.txt" >"$out/bundle/epoch2.line" && cat "$out/bundle/epoch2.line"
  # epoch 2's entry is signed by epoch 1's quorum: the verifier's own line names the predecessor and the signed weight against the threshold; assert it
  python3 - "$out/bundle/epoch2.line" <<'PY' || { vru_fail "epoch 2 is not signed by a quorum of epoch 1"; return 1; }
import re, sys
l = open(sys.argv[1]).read()
m = re.search(r"predecessor-epoch (\d+) .* members (\d+) signers (\d+) signed-weight (\d+) total-weight (\d+) threshold (\d+) ok", l)
if not m: sys.exit("unparsed verifier line: " + l)
pe, members, signers, sw, tw, th = map(int, m.groups())
if pe != 1: sys.exit("predecessor epoch %d" % pe)
print("epoch 2: predecessor epoch 1, signers %d of %d members of epoch 2's record, signed weight %d >= threshold %d (the threshold is the predecessor's)" % (signers, members, sw, th))
PY
  vru_ev extract --bundle "$out/bundle/final.cbor" --epoch 2 --out "$out/entries/epoch2.cbor" >/dev/null || return 1
  vru_ev extract --bundle "$out/bundle/final.cbor" --epoch 1 --out "$out/entries/epoch1.cbor" >/dev/null || return 1
  # the entry covers exactly the committee and weights VR installed: compare it with the committee the roots themselves report for epoch 2
  vru_ev members --bundle "$out/bundle/final.cbor" --epoch 2 >"$out/entries/epoch2.members" || return 1
  cast call --rpc-url "$vrb_rpc" "$vrb_vr" 'committee()' >"$out/vr-committee-after.hex" || return 1
  python3 -I "$(dirname "${BASH_SOURCE[0]}")/vr-utb-committee.py" "$out/entries/epoch2.members" "$out/vr-committee-after.hex" "$out/committee-check.txt" || { vru_fail "epoch 2's entry is not the installed committee"; return 1; }
  # certificates: the epoch-1 one verifies under the final history; a post-switch one under epoch 2
  vru_ev uc-verify --token "$out/proofs/epoch1-token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$(vru_confs "$out")" | tee "$out/proofs/epoch1-after-switch.txt" || { vru_fail "the epoch-1 certificate no longer verifies after the switch"; return 1; }
  grep -q '^certificate 0: epoch 1 ' "$out/proofs/epoch1-after-switch.txt" || { vru_fail "the old-epoch certificate was verified under another epoch"; return 1; }
  [ "$(shasum -a 256 "$out/proofs/epoch1-token.cbor" | cut -d' ' -f1)" = "$(cat "$out/proofs/epoch1-token.sha256")" ] || { vru_fail "the saved epoch-1 certificate changed"; return 1; }
  for i in $(seq 1 90); do
    if utb_agg_latest_uc "$out/proofs/epoch2-token.cbor" && vru_ev uc-verify --token "$out/proofs/epoch2-token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$(vru_confs "$out")" 2>&1 | grep -q '^certificate 0: epoch 2 '; then break; fi
    sleep 2
  done
  vru_ev uc-verify --token "$out/proofs/epoch2-token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$(vru_confs "$out")" | tee "$out/proofs/epoch2.txt" | grep -q '^certificate 0: epoch 2 ' || { vru_fail "no post-switch certificate of epoch 2 verifies within 180 s"; return 1; }
  # the aggregator took the entry without ever dropping an invalid one
  ! utb_agg_lines_since 0 | jq -e -s 'any(.[]; .msg=="dropping an invalid trust-base update")' >/dev/null 2>&1 || { vru_fail "the aggregator dropped an attached trust-base update as invalid"; return 1; }
  utb_agg_lines_since 0 | jq -c 'select(.msg=="Signed trust-base history loaded" or .msg=="trust-base entries appended from certification response" or (.msg|startswith("trust-base catch-up")))' >"$out/aggregator-history.jsonl"
  # the two refusals that must never appear, over every root's log of the run (the sentinel text of ErrUTBSuccessor and ErrUTBMismatch)
  n=$(cat test-nodes/root*/debug.log 2>/dev/null | grep -c 'successor trust-base entry cannot be derived\|endorses another successor trust-base entry') || true
  echo "root log refusals (cannot derive / endorses another entry): $n" >"$out/root-log-refusals.txt"
  [ "${n:-0}" = 0 ] || { vru_fail "$n UTB successor refusals in the roots' logs (see $out/root-log-refusals.txt)"; return 1; }
  # the stores of the nodes: every root's and shard node's own finalized entries verify from the pin (an export opens the store with the pin and the genesis entry)
  mkdir -p "$out/stores"
  local bad=0
  for f in test-nodes/root*/root-utb-entries.db test-nodes/evm*/shard-utb-entries.db; do
    [ -f "$f" ] || continue
    n=$(basename "$(dirname "$f")"); cp "$f" "$out/stores/$n.db"
    if ! build/ubft trust-base utb-export --utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id "$(utb_pin)" --utb-entries-db "$out/stores/$n.db" --out "$out/stores/$n.cbor" >"$out/stores/$n.export.log" 2>&1; then
      vrb_log "FAIL: $n's entry store does not export from the pinned genesis ($(tail -n 1 "$out/stores/$n.export.log"))"; bad=$((bad + 1))
    elif ! vru_ev verify --bundle "$out/stores/$n.cbor" --pin "$(utb_pin)" >"$out/stores/$n.verify.txt" 2>&1 || ! grep -q '^ok: epochs 1\.\.2,' "$out/stores/$n.verify.txt"; then
      vrb_log "FAIL: $n's own store holds no verified epochs 1..2 ($(tail -n 1 "$out/stores/$n.verify.txt"))"; bad=$((bad + 1))
    elif ! vru_ev extract --bundle "$out/stores/$n.cbor" --epoch 2 --out "$out/stores/$n-epoch2.cbor" >/dev/null || ! cmp -s "$out/stores/$n-epoch2.cbor" "$out/entries/epoch2.cbor"; then
      vrb_log "FAIL: $n's epoch-2 entry is not the aggregator's, byte for byte"; bad=$((bad + 1))
    else
      vrb_log "PASS: $n's own entry store verifies epochs 1..2 from the pin, epoch 2 byte for byte the aggregator's"
    fi
    rm -f "$out/stores/$n.db"
  done
  # the SDK 4.0 client: genesis alone, the epoch-1 certificate verifies, the epoch-2 one names an unknown epoch and is repaired by the SDK's own fetch, and a forged entry is refused
  if [ -n "${UTB_SDK_JS:-}" ]; then
    git -C "$UTB_SDK_JS" rev-parse HEAD >"$out/sdk/sdk-commit.txt" 2>/dev/null || grep -m1 '"version"' "$UTB_SDK_JS/package.json" >"$out/sdk/sdk-version.txt"
    node "$PWD/scripts/utb-sdk-client/vr-check.mjs" --sdk "$UTB_SDK_JS" --url "http://127.0.0.1:$(agg_port 1)" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" \
      --epoch1-uc "$out/proofs/epoch1-token.cbor" --uc "$out/proofs/epoch2-token.cbor" --entry "2=$out/entries/epoch2.cbor" --out "$out/sdk/client.log"
    rc=$?; cat "$out/sdk/client.log" 2>/dev/null
    [ "$rc" = 0 ] && grep -q '^sdk client check: PASSED' "$out/sdk/client.log" || { vru_fail "the SDK client check failed"; return 1; }
  else
    vru_fail "UTB_SDK_JS is not set (the SDK 4.0 client check is part of the acceptance)"; return 1
  fi
  [ "$bad" = 0 ] || { vru_fail "$bad node stores did not verify (see above)"; return 1; }
  vrb_log "PASS: UTB across the VR handoff: epochs 1 and 2 served from the pin, epoch 2 signed by epoch 1's quorum and the installed committee, the epoch-1 certificate verifies after the switch, the SDK client verifies both and refuses a forged entry"
}
