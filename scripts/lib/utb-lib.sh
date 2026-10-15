# The combined UTB acceptance lane (briefs/utb-signed-entries-design.md §11.4): the any-age/P85 lane machinery (ANYAGE_LANE=1: one aggregation partition, the
# EVM shard, exact-K recovery) with the signed trust-base entry profile on from the first voting epoch. Definitions only: sourcing this file starts nothing,
# reads nothing and takes no port.
#
# The caller defines (before calling a function): info (optional), and runs from the repository root (test-nodes/, build/ubft). UBFT overrides build/ubft.

UBFT=${UBFT:-build/ubft}
UTB_DIR=${UTB_DIR:-test-nodes/utb}

# The genesis artifacts of the deployment, generated once, in dependency order, from the epoch-1 trust base the lane already wrote (test-nodes/trust-base.json):
# the canonical genesis entry, its EntryID (the pin) and the manifest every later check recomputes. UTB_COMPONENTS is a space-separated list of name=value
# pins recorded in the manifest (ureth commit, contracts commit, the aggregator binary digest...).
utb_prepare_genesis() {
  local tb=${1:-test-nodes/trust-base.json} comp=() c out id
  for c in ${UTB_COMPONENTS:-}; do comp+=(--component "$c"); done
  mkdir -p "$UTB_DIR"
  out=$("$UBFT" trust-base utb-manifest --trust-base "$tb" --out-dir "$UTB_DIR" ${comp[@]+"${comp[@]}"}) || { echo "utb_prepare_genesis: the manifest could not be generated: $out" >&2; return 1; }
  id=$(sed -n 's/^utb genesis id *//p' <<<"$out")
  case "$id" in 0x????????????????????????????????????????????????????????????????) ;; *) echo "utb_prepare_genesis: no genesis EntryID in the tool's output: $out" >&2; return 1 ;; esac
  cp "$UTB_DIR/utb-genesis.cbor" test-nodes/utb-genesis.cbor
  printf '%s\n' "$id" >test-nodes/utb-genesis.id
  "$UBFT" trust-base utb-manifest --check "$UTB_DIR/utb-manifest.json" >/dev/null || { echo "utb_prepare_genesis: the generated manifest does not check out" >&2; return 1; }
}

# The flags a root or a shard node of the lane starts with. The pin is read from the file the generation wrote, never from a value copied into a script.
utb_pin() { tr -d '[:space:]' <test-nodes/utb-genesis.id; }
utb_root_flags() { # node (unused: every root has the same profile)
  [ -s test-nodes/utb-genesis.cbor ] && [ -s test-nodes/utb-genesis.id ] || { echo "utb_root_flags: no UTB genesis (utb_prepare_genesis first)" >&2; return 1; }
  mkdir -p "test-nodes/utb-ucresp/root${1:-0}"
  echo "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(utb_pin) --utb-capture-ucresp test-nodes/utb-ucresp/root${1:-0}"
}
# a shard node takes the profile flags only (it sends no certification response, so it captures nothing)
utb_shard_flags() { echo "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(utb_pin)"; }

# The environment of the patched aggregator (dev4's local build, briefs/builds/aggregator-utb-<patch sha8>/README.md): UTB mode is enabled by UTB_GENESIS_ID; the
# genesis entry file is the fresh chain's history (UTB_BUNDLE_FILE would be a complete tagged history instead); UTB_ENTRIES_DB is its own append-only store. In UTB mode
# the binary uses neither the V1 trust-base files nor root REST.
utb_agg_env() { # K (1-based)
  local k=${1:-1}
  [ -s test-nodes/utb-genesis.cbor ] && [ -s test-nodes/utb-genesis.id ] || { echo "utb_agg_env: no UTB genesis (utb_prepare_genesis first)" >&2; return 1; }
  # BFT_RPC_ADDRESS is a dead port: in UTB mode the aggregator builds no root REST client, and the lane shows root HTTP is not what it uses. JSON logs: the
  # evidence reads the log lines by their exact messages (briefs/builds/aggregator-utb-*/LOG_MARKERS.md).
  echo "UTB_GENESIS_FILE=$PWD/test-nodes/utb-genesis.cbor UTB_GENESIS_ID=$(utb_pin) UTB_ENTRIES_DB=$PWD/test-nodes/utb-agg$k.db BFT_RPC_ADDRESS=http://127.0.0.1:1 LOG_FORMAT=json LOG_ENABLE_JSON=true"
}
# The aggregator's read-only binary history range (design 11.3 item 4): GET /api/v1/trustbases?from=E[&to=E]..., the PR6 response codec. The same endpoint serves the
# lane's reference client; port is the aggregator's (agg_port from scripts/lib/agg-lib.sh when it is loaded).
utb_agg_history_url() { local k=${1:-1} port=${AGG_PORT:-3001}; echo "http://127.0.0.1:$((port + k - 1))/api/v1/trustbases"; }

# The patched aggregator's provenance directory: the one whose sha256.txt records this binary's digest. It must also hold the base, the patch and a sha256.txt that
# records the patch's digest. Prints the directory.
utb_agg_provenance() { # BIN [BUILDS_DIR]
  local bin=$1 builds=${2:-${AGRE_ROOT:-..}/briefs/builds} sum d psum
  sum=$(shasum -a 256 "$bin" 2>/dev/null | cut -d' ' -f1)
  [ -n "$sum" ] || { echo "utb_agg_provenance: cannot read $bin" >&2; return 1; }
  for d in "$builds"/aggregator-utb-*/; do
    [ -s "${d}sha256.txt" ] && grep -q "^$sum " "${d}sha256.txt" || continue
    for f in base.txt patch.diff; do [ -s "${d}$f" ] || { echo "utb_agg_provenance: ${d}$f is missing or empty" >&2; return 1; }; done
    psum=$(shasum -a 256 "${d}patch.diff" | cut -d' ' -f1)
    grep -q "^$psum " "${d}sha256.txt" || { echo "utb_agg_provenance: ${d}sha256.txt does not record the patch digest $psum" >&2; return 1; }
    echo "${d%/}"; return 0
  done
  echo "utb_agg_provenance: no aggregator-utb-* provenance under $builds records the binary digest $sum" >&2
  return 1
}

# The components pinned in the manifest, from what the lane was given: the aggregator's base commit, patch and binary digests (from its provenance) and the other
# builds by their environment names.
utb_lane_components() {
  local d out=()
  [ -z "${M2_URETH_COMMIT:-}" ] || out+=("ureth=$M2_URETH_COMMIT")
  if [ -n "${AGG_BIN:-}" ] && d=$(utb_agg_provenance "$AGG_BIN" 2>/dev/null); then
    out+=("aggregator-base=$(awk 'NR==1{print $3}' "$d/base.txt")" "aggregator-patch=sha256:$(shasum -a 256 "$d/patch.diff" | cut -d' ' -f1)" "aggregator-binary=sha256:$(shasum -a 256 "$AGG_BIN" | cut -d' ' -f1)")
  fi
  [ -z "${P85_CONTRACTS:-}" ] || ! git -C "$P85_CONTRACTS" rev-parse HEAD >/dev/null 2>&1 || out+=("contracts=$(git -C "$P85_CONTRACTS" rev-parse HEAD)")
  [ -z "${NBP_DIR:-}" ] || ! git -C "$NBP_DIR" rev-parse HEAD >/dev/null 2>&1 || out+=("native-bridge-plugins=$(git -C "$NBP_DIR" rev-parse HEAD)")
  printf '%s ' "${out[@]+"${out[@]}"}"
}


# ---- lane steps (UTB_LANE=1; sourced by scripts/p85-recovery-steps.sh next to the any-age steps, which supply anyage_dir, anyage_nbp, p85_*, agg-lib.sh) ----------
# Each is a function the P85 step runner calls like its own (nonzero return = the lane fails and tears down). The evidence goes to $(utb_dir); the independent verifier is
# utb-evidence (scripts/utb-evidence), which trusts no node. Entries: epoch 2 is the K->J handoff (activated, never acknowledged by J's EVM), epoch 3 the derived recovery.
utb_dir() { mkdir -p "${H3_DIR:?}" && echo "$(cd "$H3_DIR" && pwd)/utb"; }
utb_ev() { "${UTB_EVIDENCE:?}" "$@"; }
utb_agg_log() { echo "$PWD/$(agg_dir 1)/logs/aggregator.log"; }
utb_agg_url() { utb_agg_history_url 1; }
# the aggregator log lines (JSON) written since byte offset $1
utb_agg_lines_since() { tail -c +"$(($1 + 1))" "$(utb_agg_log)" 2>/dev/null | grep -a '^{'; }
utb_agg_offset() { wc -c <"$(utb_agg_log)" 2>/dev/null | tr -d ' ' || echo 0; }
# the tip epoch the aggregator serves (0 if it serves nothing)
utb_agg_tip() {
  local t; t=$(mktemp)
  if utb_ev fetch --url "$(utb_agg_url)" --out "$t" >/dev/null 2>&1; then
    utb_ev verify --bundle "$t" --pin "$(utb_pin)" 2>/dev/null | sed -n 's/^ok: epochs [0-9]*\.\.\([0-9]*\), tip.*/\1/p'
  else echo 0; fi
  rm -f "$t"
}
utb_wait_agg_tip() { # want seconds
  local want=$1 tip i
  for i in $(seq 1 "$2"); do
    tip=$(utb_agg_tip); [ "${tip:-0}" -ge "$want" ] && return 0
    sleep 2
  done
  echo "the aggregator serves tip ${tip:-0}, expected >= $want after $(( $2 * 2 )) s; its log tail:" >&2; tail -c 3000 "$(utb_agg_log)" >&2
  return 1
}

# Before rotation: the aggregator and the reference client hold only the genesis history; the saved original proof verifies under it.
utb_step_u1() {
  local out; out=$(utb_dir); mkdir -p "$out"/{bundle,entries,ucresp,verifier,catchup,handoff,proofs,history,manifest}
  [ -x "${UTB_EVIDENCE:-}" ] || { echo "UTB_EVIDENCE ($UTB_EVIDENCE) is not built" >&2; return 1; }
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/initial.cbor" || { echo "the aggregator serves no history at $(utb_agg_url)" >&2; return 1; }
  utb_ev verify --bundle "$out/bundle/initial.cbor" --pin "$(utb_pin)" | tee "$out/bundle/initial.verify.txt" || return 1
  grep -q '^ok: epochs 1\.\.1,' "$out/bundle/initial.verify.txt" || { echo "the aggregator held more than the genesis before any rotation" >&2; return 1; }
  grep -aq '"msg":"Signed trust-base history loaded"' "$(utb_agg_log)" || { echo "the aggregator did not report its history loaded" >&2; return 1; }
  # the original proof, saved by L1a: the digest is recorded now and nothing refetches it
  cp "$(anyage_dir)/l1/token.cbor" "$out/proofs/token.cbor" || return 1
  shasum -a 256 "$out/proofs/token.cbor" | cut -d' ' -f1 >"$out/proofs/original-proof.sha256"
  # the original proof is the bridge token's: certified for the EVM shard, so its certificates bind the EVM shard's full configuration (not the aggregator's)
  cp test-nodes/evm-full-shard-conf-v2.json "$out/manifest/shard-conf.json" || return 1
  utb_ev uc-verify --token "$out/proofs/token.cbor" --bundle "$out/bundle/initial.cbor" --shard-conf "$out/manifest/shard-conf.json" | tee "$out/proofs/before-rotation-verify.txt" || return 1
  # the reference client starts from the genesis alone and holds it through the whole rotation
  utb_ev client --url "$(utb_agg_url)" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" | tee "$out/history/client-start.log" || return 1
  echo "U1: the aggregator and the client hold the genesis only; the original proof ($(cut -c1-12 "$out/proofs/original-proof.sha256")...) verifies under it"
}

# The K->J handoff is activated: the aggregator received the signed entry of epoch 2 attached to a certification response (and nothing else could have told it).
utb_step_u2() {
  local out off t; out=$(utb_dir)
  utb_wait_agg_tip 2 90 || return 1
  t="$out/bundle/after-activation.cbor"
  utb_ev fetch --url "$(utb_agg_url)" --out "$t" && utb_ev verify --bundle "$t" --pin "$(utb_pin)" | tee "$out/bundle/after-activation.verify.txt" || return 1
  utb_ev extract --bundle "$t" --epoch 2 --out "$out/entries/ordinary-handoff.cbor" || return 1
  # piggyback and not repair: an append from a certification response, with no catch-up started anywhere before it in the aggregator's life
  utb_agg_lines_since 0 | jq -c 'select(.msg=="received CertificationResponseV2" or .msg=="trust-base entries appended from certification response" or .msg=="trust-base catch-up started" or .msg=="trust-base gap in certification response")' >"$out/handoff/aggregator-ordinary.jsonl"
  python3 - "$out/handoff/aggregator-ordinary.jsonl" "$out/handoff/ordinary-ack.log" <<'PY' || return 1
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
app = [i for i, l in enumerate(lines) if l["msg"] == "trust-base entries appended from certification response" and l.get("added", 0) >= 1 and l.get("tip") == 2]
if not app: raise SystemExit("no piggyback append of epoch 2 in the aggregator log")
if any(l["msg"] == "trust-base catch-up started" for l in lines[:app[0] + 1]): raise SystemExit("a catch-up started before the piggyback append: the entry was not delivered by the response")
rcv = [l for l in lines[:app[0]] if l["msg"] == "received CertificationResponseV2" and l.get("trustBaseUpdates", 0) >= 1]
if not rcv: raise SystemExit("no received CertificationResponseV2 with an attachment before the append")
open(sys.argv[2], "w").write("piggyback: the aggregator received a version 2 response with %d attached entries and appended epoch 2 (tip 2) with no catch-up\n%s\n%s\n" % (rcv[-1]["trustBaseUpdates"], json.dumps(rcv[-1]), json.dumps(lines[app[0]])))
PY
  # the real message the root sent: captured just before it was sent
  local f; f=$(ls test-nodes/utb-ucresp/root*/ucresp-e2-*.cbor 2>/dev/null | head -1)
  [ -n "$f" ] || { echo "no captured version 2 response with the epoch-2 entry under test-nodes/utb-ucresp" >&2; return 1; }
  cp "$f" "$out/ucresp/piggyback-sample.cbor"
  utb_ev ucresp --file "$out/ucresp/piggyback-sample.cbor" --entry "$out/entries/ordinary-handoff.cbor" | tee "$out/ucresp/piggyback-sample.check.txt" || return 1
  echo "U2: epoch 2 reached the aggregator by piggyback (tip 2); the root's message was captured"
}

# The aggregator restarts from its retained store with unchanged records; then a controlled fault: it goes down with its store lost, and stays down through the recovery.
utb_step_u3a() {
  local out db before after; out=$(utb_dir); db=$PWD/test-nodes/utb-agg1.db
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/before-restart.cbor" >/dev/null || return 1
  restart_agg 1 || return 1
  utb_wait_agg_tip 2 60 || return 1
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/after-restart.cbor" >/dev/null || return 1
  cmp -s "$out/bundle/before-restart.cbor" "$out/bundle/after-restart.cbor" || { echo "the aggregator's history changed across a restart" >&2; return 1; }
  { echo "aggregator restart from its retained store: the history bytes are unchanged ($(shasum -a 256 <"$out/bundle/after-restart.cbor" | cut -d' ' -f1))"
    utb_agg_lines_since 0 | jq -c 'select(.msg=="Signed trust-base history loaded")' | tail -1; } >"$out/catchup/restart.log"
  # the controlled fault: the aggregator is down and its history store is gone (Mongo, with its last certified block, is kept)
  stop_aggs; rm -f "$db"; : >"$out/catchup/fault.txt"; echo "$(date -u +%FT%TZ) the aggregator was stopped and $db removed before the stalled successor and the recovery" >"$out/catchup/fault.txt"
  echo "U3a: the aggregator restarted from its store with unchanged records, then stopped with its history store removed"
}

# After the recovery: the aggregator restarts holding the genesis only, root HTTP unavailable to it; it repairs the missing entries from a genesis-committee root.
utb_step_u3b() {
  local out off; out=$(utb_dir)
  off=$(utb_agg_offset)
  start_agg 1 || return 1
  utb_wait_agg_tip 3 90 || return 1
  utb_agg_lines_since "$off" | jq -c 'select(.msg|startswith("trust-base catch-up") or .msg=="trust-base gap in certification response" or .msg=="Signed trust-base history loaded" or .msg=="trust-base handshake to the newest held committee")' >"$out/catchup/aggregator-repair.jsonl"
  python3 - "$out/catchup/aggregator-repair.jsonl" "$out/catchup/aggregator-peer-repair.log" <<'PY' || return 1
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
st = [i for i, l in enumerate(lines) if l["msg"] == "trust-base catch-up started"]
if not st: raise SystemExit("no catch-up started after the restart")
fin = [i for i, l in enumerate(lines) if l["msg"] == "trust-base catch-up finished" and "error" not in l and l.get("added", 0) >= 2]
if not fin: raise SystemExit("no successful catch-up finished (added >= 2)")
pages = [l for l in lines[st[0]:fin[0]] if l["msg"] == "trust-base catch-up page" and l.get("status") == "OK" and l.get("entries", 0) >= 1]
if not pages: raise SystemExit("no OK catch-up page from a root between the start and the finish")
out = ["peer repair: started from epoch %s, %d OK page(s), peers %s, finished adding %s (tip %s)" % (lines[st[0]].get("from"), len(pages), sorted({p["peer"] for p in pages}), lines[fin[0]]["added"], lines[fin[0]]["tip"])]
out += [json.dumps(l) for l in lines]
open(sys.argv[2], "w").write("\n".join(out) + "\n")
PY
  echo "U3b: the aggregator repaired epochs 2..3 from a root over GetTrustBase (root HTTP was not available to it)"
}

# After the acknowledgement: the post-recovery token (certified under the epoch-3 committee), the client's unknown-epoch gap, the aggregator's second restart.
utb_step_u4() {
  local out sav hist cl; out=$(utb_dir); sav=$(anyage_dir)/l1-post; mkdir -p "$sav"
  anyage_nbp save "$PWD/test-nodes/lane-config.json" "$sav" 2>&1 | tee "$sav/save.log" || return 1
  cp "$sav/token.cbor" "$out/proofs/post-recovery-token.cbor"
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/final.cbor" && utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | tee "$out/bundle/final.verify.txt" || return 1
  utb_ev extract --bundle "$out/bundle/final.cbor" --epoch 3 --out "$out/entries/recovery.cbor" || return 1
  utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | grep '^epoch 2 ' >"$out/verifier/ordinary.txt" && utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | grep '^epoch 3 ' >"$out/verifier/recovery.txt" || return 1
  # the reference client was last seen at the genesis: the post-recovery certificate names an epoch it does not hold
  utb_ev client --export "$out/history/client-stale.cbor" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" --url "" >/dev/null 2>&1 || true
  if utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/history/client-stale.cbor" --shard-conf "$out/manifest/shard-conf.json" >"$out/history/client-before-sync.txt" 2>&1; then
    echo "the stale client verified an epoch-3 certificate: it should have met an unknown epoch" >&2; return 1
  fi
  grep -q "does not hold" "$out/history/client-before-sync.txt" || { echo "the stale client failed for another reason: $(cat "$out/history/client-before-sync.txt")" >&2; return 1; }
  utb_ev client --url "$(utb_agg_url)" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" --export "$out/history/client-synced.cbor" | tee "$out/catchup/client-gap-two-entries.log" || return 1
  grep -q "appended \[2 3\]" "$out/catchup/client-gap-two-entries.log" || { echo "the client did not fetch both missed entries in one sync" >&2; return 1; }
  utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/history/client-synced.cbor" --shard-conf "$out/manifest/shard-conf.json" | tee "$out/history/client-after-sync.txt" || return 1
  # the aggregator restarts once more from its (repaired) store: unchanged bytes, certification resumes
  restart_agg 1 || return 1
  utb_wait_agg_tip 3 60 || return 1
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/after-second-restart.cbor" >/dev/null && cmp -s "$out/bundle/final.cbor" "$out/bundle/after-second-restart.cbor" || { echo "the aggregator's history changed across its second restart" >&2; return 1; }
  echo "second restart: unchanged history bytes ($(shasum -a 256 <"$out/bundle/final.cbor" | cut -d' ' -f1))" >>"$out/catchup/restart.log"
  curl -fsS "http://127.0.0.1:$(agg_port 1)/health" >>"$out/catchup/restart.log" 2>&1 || { echo "the aggregator is not healthy after its second restart" >&2; return 1; }
  echo "U4: the stale client met epoch 3, fetched [2 3] in one request and verified; the aggregator restarted twice with unchanged records"
}

# After L1c: the original proof verifies unchanged under its historical committee; the bridge receipt; the exported history reloads exactly.
utb_step_u5() {
  local out got; out=$(utb_dir)
  [ "$(shasum -a 256 <"$out/proofs/token.cbor" | cut -d' ' -f1)" = "$(cat "$out/proofs/original-proof.sha256")" ] || { echo "the original proof changed" >&2; return 1; }
  utb_ev uc-verify --token "$out/proofs/token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$out/manifest/shard-conf.json" | tee "$out/proofs/historical-verify.log" || return 1
  cp "$(anyage_dir)/l1/release.json" "$out/proofs/bridge-receipt.json" || return 1
  # the complete history is exported as one tagged file (the final bundle) and a fresh client store reloads it to exactly the same records and tip
  rm -f "$out/reload.db"
  utb_ev client --url "$(utb_agg_url)" --store "$out/reload.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" --export "$out/history/reloaded.cbor" | tee "$out/history/client-reload.log" || return 1
  cmp -s "$out/history/reloaded.cbor" "$out/bundle/final.cbor" || { echo "the reloaded client history differs from the exported final bundle" >&2; return 1; }
  echo "final bundle sha256 $(shasum -a 256 <"$out/bundle/final.cbor" | cut -d' ' -f1)" >>"$out/history/client-reload.log"
  echo "U5: the original proof verifies unchanged under its historical committee, the bridge receipt is kept, the client reload reproduces the final history"
}

# The pack: the evidence files the checker requires, the manifest rewritten with relative paths (self-contained), then the checker.
utb_step_final() {
  local out comp; out=$(utb_dir)
  cp test-nodes/trust-base.json "$out/manifest/trust-base.json"
  comp=$(python3 -c "import json;print(' '.join('--component %s=%s' % kv for kv in json.load(open('test-nodes/utb/utb-manifest.json')).get('components',{}).items()))")
  "$UBFT" trust-base utb-manifest --trust-base "$out/manifest/trust-base.json" --out-dir "$out/manifest" --relative-paths $comp >/dev/null || return 1
  [ "$(python3 -c "import json;print(json.load(open('$out/manifest/utb-manifest.json'))['derived']['utbGenesisEntryId'])")" = "$(utb_pin)" ] || { echo "the pack manifest's genesis is not the deployment's" >&2; return 1; }
  { echo "bft-core $(git rev-parse HEAD) ubft sha256 $(shasum -a 256 "$UBFT" | cut -d' ' -f1)"; echo "utb-evidence sha256 $(shasum -a 256 "$UTB_EVIDENCE" | cut -d' ' -f1)"; echo "aggregator sha256 $(shasum -a 256 "$AGG_BIN" | cut -d' ' -f1)"; } >"$out/manifest/build.txt"
  mkdir -p "$out/manifest/aggregator"; cp "$(utb_agg_provenance "$AGG_BIN" "${AGRE_ROOT:-$PWD/..}/briefs/builds")"/{base.txt,patch.diff,sha256.txt} "$out/manifest/aggregator/" || return 1
  cp "$(agg_dir 1)/logs/aggregator.log" "$out/catchup/aggregator.log" 2>/dev/null || true
  # the recovery's closures, as the lane's own step printed them (both closures before the RecoveryAck, J closed at its closure's anchors)
  grep -a "closed at\|PASS: p85_recovery\|PASS: p85_resolved\|PASS: anyage_step_l2" "${EVIDENCE_LANE_LOG:?}" >"$out/handoff/recovery-closure.log" || true
  grep -q "closed at" "$out/handoff/recovery-closure.log" || { echo "the lane log shows no closure result for the recovery" >&2; return 1; }
  utb_check_evidence "$out" || return 1
  echo "UTB lane: all steps PASSED"
}

# The evidence the lane must leave (design §11.4); a root log saying "signed" or a client printing the new epoch number is not evidence. The pack is
# self-contained: the manifest names its files relative to itself, and nothing below reads the live deployment.
utb_evidence_required() {
  cat <<'LIST'
manifest/utb-manifest.json
manifest/trust-base.json
manifest/utb-genesis.cbor
manifest/shard-conf.json
manifest/build.txt
manifest/aggregator/base.txt
manifest/aggregator/patch.diff
manifest/aggregator/sha256.txt
bundle/initial.cbor
bundle/final.cbor
entries/ordinary-handoff.cbor
entries/recovery.cbor
ucresp/piggyback-sample.cbor
verifier/ordinary.txt
verifier/recovery.txt
catchup/client-gap-two-entries.log
catchup/aggregator-peer-repair.log
catchup/restart.log
handoff/ordinary-ack.log
handoff/recovery-closure.log
proofs/token.cbor
proofs/original-proof.sha256
proofs/historical-verify.log
proofs/bridge-receipt.json
history/client-reload.log
LIST
}

UTB_EVIDENCE=${UTB_EVIDENCE:-build/utb-evidence}

# utb_check_evidence DIR: every required file exists and is non-empty, and the bytes are what they claim to be, checked by the tools and not by keyword:
#  - the manifest checks out against the trust base and genesis entry inside the pack;
#  - bundle/final.cbor is a tagged history from the manifest's pinned genesis, every record verified from its predecessor (utb-evidence verify);
#  - each verifier output is exactly that tool's line for the record's epoch (2: the K->J handoff, 3: the recovery), and each entries/*.cbor is exactly that history's record for it;
#  - bundle/initial.cbor verifies from the same pin, is shorter, and is a prefix of the final history;
#  - the UCResp sample is a version 2 response whose attachment is byte-identical to entries/ordinary-handoff.cbor;
#  - proofs/token.cbor is the original (its digest is the recorded one) and its certificates verify under their own epochs' committees (the recorded output is the
#    tool's output on these bytes);
#  - the client reload recorded the final bundle's digest and tip; the two-entry gap was fetched in one sync; the bridge receipt is a successful redemption.
utb_check_evidence() {
  local dir=$1 f missing=0 tool=$UTB_EVIDENCE pin out want got
  [ -d "$dir" ] || { echo "utb_check_evidence: $dir is not a directory" >&2; return 1; }
  [ -x "$tool" ] || { echo "utb_check_evidence: $tool is not built (go build -o build/utb-evidence ./scripts/utb-evidence)" >&2; return 1; }
  while read -r f; do
    [ -s "$dir/$f" ] || { echo "evidence missing or empty: $f" >&2; missing=1; }
  done < <(utb_evidence_required)
  [ "$missing" -eq 0 ] || return 1
  "$UBFT" trust-base utb-manifest --check "$dir/manifest/utb-manifest.json" >/dev/null 2>&1 || { echo "the evidence manifest does not check out against the trust base and genesis entry in the pack" >&2; return 1; }
  pin=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['derived']['utbGenesisEntryId'])" "$dir/manifest/utb-manifest.json") || return 1
  out=$("$tool" verify --bundle "$dir/bundle/final.cbor" --pin "$pin" 2>&1) || { echo "bundle/final.cbor does not verify from the pinned genesis: $out" >&2; return 1; }
  local e name
  local file
  for e in "ordinary:2:ordinary-handoff" "recovery:3:recovery"; do
    name=${e%%:*}; file=${e##*:}; e=${e#*:}; e=${e%%:*}
    want=$(grep "^epoch $e " <<<"$out") && [ -n "$want" ] || { echo "the final history holds no record for epoch $e ($name)" >&2; return 1; }
    [ "$(cat "$dir/verifier/$name.txt")" = "$want" ] || { echo "verifier/$name.txt is not the verifier's line for epoch $e" >&2; return 1; }
    got=$(mktemp); "$tool" extract --bundle "$dir/bundle/final.cbor" --epoch "$e" --out "$got" >/dev/null 2>&1 || { rm -f "$got"; echo "cannot extract epoch $e" >&2; return 1; }
    cmp -s "$got" "$dir/entries/$file.cbor" || { rm -f "$got"; echo "entries/$file.cbor is not the history's record for epoch $e" >&2; return 1; }
    rm -f "$got"
  done
  local initial
  initial=$("$tool" verify --bundle "$dir/bundle/initial.cbor" --pin "$pin" 2>&1) || { echo "bundle/initial.cbor does not verify from the pin: $initial" >&2; return 1; }
  [ "$(tail -1 <<<"$initial")" != "$(tail -1 <<<"$out")" ] || { echo "the final history equals the initial one: the chain did not advance" >&2; return 1; }
  # the initial history is a prefix of the final one: every record line it printed appears identically in the final output
  while read -r f; do
    grep -qxF "$f" <<<"$out" || { echo "the initial history is not a prefix of the final one (record: $f)" >&2; return 1; }
  done < <(grep -E '^(genesis )?epoch ' <<<"$initial")
  "$tool" ucresp --file "$dir/ucresp/piggyback-sample.cbor" --entry "$dir/entries/ordinary-handoff.cbor" >/dev/null 2>&1 || { echo "the UCResp sample is not a version 2 response attaching entries/ordinary-handoff.cbor byte for byte" >&2; return 1; }
  want=$(tr -d '[:space:]' <"$dir/proofs/original-proof.sha256" | cut -d' ' -f1)
  [ "$(shasum -a 256 <"$dir/proofs/token.cbor" | cut -d' ' -f1)" = "${want%% *}" ] || { echo "proofs/token.cbor is not the original proof (its digest is not the recorded one)" >&2; return 1; }
  got=$("$tool" uc-verify --token "$dir/proofs/token.cbor" --bundle "$dir/bundle/final.cbor" --shard-conf "$dir/manifest/shard-conf.json" 2>&1) || { echo "the original proof's certificates do not verify under their epochs' committees: $got" >&2; return 1; }
  [ "$(cat "$dir/proofs/historical-verify.log")" = "$got" ] || { echo "proofs/historical-verify.log is not the verifier's output on proofs/token.cbor" >&2; return 1; }
  local tip; tip=$(sed -n 's/^ok: epochs [0-9]*\.\.\([0-9]*\), tip.*/\1/p' <<<"$out")
  have=$(shasum -a 256 <"$dir/bundle/final.cbor" | cut -d' ' -f1)
  grep -q "$have" "$dir/history/client-reload.log" && grep -q "tip now $tip" "$dir/history/client-reload.log" || { echo "history/client-reload.log does not record the final bundle digest $have and tip $tip" >&2; return 1; }
  grep -q "appended \[2 3\]" "$dir/catchup/client-gap-two-entries.log" || { echo "the client gap log does not show epochs 2 and 3 fetched in one sync" >&2; return 1; }
  jq -e '(.redeem.gasUsed | tonumber) > 0 and (.claim.gasUsed | tonumber) > 0' "$dir/proofs/bridge-receipt.json" >/dev/null 2>&1 || { echo "proofs/bridge-receipt.json is not a successful redemption and claim" >&2; return 1; }
}

# ---- chain-free self-tests -----------------------------------------------------------------------------------------------------------------------------
utb_st() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $what"; else echo "  FAIL  $what"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); fi; }
utb_st_no() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $what (accepted)"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); else echo "  ok    $what"; fi; }

# needs a built ubft ($UBFT) and a genesis trust base file: UTB_ST_TRUSTBASE (the Go test of the tool writes none; the lane's own preflight builds one)
utb_selftest() {
  UTB_ST_BAD=0
  local t cwd; cwd=$PWD; t=$(mktemp -d)
  trap 'rm -rf "$t"' RETURN
  [ -x "$UBFT" ] && [ -n "${UTB_ST_TRUSTBASE:-}" ] && [ -s "$UTB_ST_TRUSTBASE" ] || { echo "utb_selftest: set UBFT to a built ubft and UTB_ST_TRUSTBASE to an epoch-1 trust base file" >&2; return 1; }
  mkdir -p "$t/test-nodes"
  cp "$UTB_ST_TRUSTBASE" "$t/test-nodes/trust-base.json"
  ( cd "$t" || exit 1
    UBFT=$(cd "$cwd" && realpath "$UBFT") UTB_DIR="$t/test-nodes/utb" UTB_COMPONENTS="ureth=6e59b68c aggregator=sha256:00" utb_prepare_genesis ) \
    && echo "  ok    the genesis, its pin and the manifest are generated and check out" || { echo "  FAIL  utb_prepare_genesis"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); }
  ( cd "$t" || exit 1
    flags=$(utb_root_flags 1) && [ "$flags" = "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(tr -d '[:space:]' <test-nodes/utb-genesis.id) --utb-capture-ucresp test-nodes/utb-ucresp/root1" ] \
      && [ "$(utb_shard_flags 1)" = "--utb-genesis test-nodes/utb-genesis.cbor --utb-genesis-id $(tr -d '[:space:]' <test-nodes/utb-genesis.id)" ] ) \
    && echo "  ok    root and shard flags carry the generated file and the pin read from it (the root also its capture directory)" || { echo "  FAIL  utb_root_flags"; UTB_ST_BAD=$((UTB_ST_BAD + 1)); }
  utb_st_no "no flags without a generated genesis" bash -c "cd '$t/empty' 2>/dev/null || mkdir -p '$t/empty' && cd '$t/empty' && source '$cwd/scripts/lib/utb-lib.sh' && utb_root_flags 1"
  # the aggregator provenance: the directory that records the binary and the patch is found; a missing patch, an unrecorded patch digest or an unknown binary is refused
  local bld="$t/builds" bin="$t/agg"
  mkdir -p "$bld/aggregator-utb-aaaaaaaa"
  printf 'binary\n' >"$bin"; printf 'patch\n' >"$bld/aggregator-utb-aaaaaaaa/patch.diff"; printf 'aggregator-go base: 63cdca1 (x)\n' >"$bld/aggregator-utb-aaaaaaaa/base.txt"
  printf '%s  patch.diff\n%s  binary\n' "$(shasum -a 256 <"$bld/aggregator-utb-aaaaaaaa/patch.diff" | cut -d' ' -f1)" "$(shasum -a 256 <"$bin" | cut -d' ' -f1)" >"$bld/aggregator-utb-aaaaaaaa/sha256.txt"
  utb_st "the aggregator provenance is found by the binary digest" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(utb_agg_provenance '$bin' '$bld')\" = '$bld/aggregator-utb-aaaaaaaa' ]"
  utb_st_no "an unrecorded binary is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'other\n' >'$t/other'; utb_agg_provenance '$t/other' '$bld'"
  utb_st_no "a provenance that does not record the patch digest is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'edited\n' >>'$bld/aggregator-utb-aaaaaaaa/patch.diff'; utb_agg_provenance '$bin' '$bld'"
  printf 'patch\n' >"$bld/aggregator-utb-aaaaaaaa/patch.diff"
  utb_st "the aggregator environment carries the genesis, the pin and its own store" bash -c "cd '$t' && source '$cwd/scripts/lib/utb-lib.sh' && env=\$(utb_agg_env 2) && grep -q 'UTB_GENESIS_FILE=$t/test-nodes/utb-genesis.cbor' <<<\"\$env\" && grep -q 'UTB_GENESIS_ID=0x' <<<\"\$env\" && grep -q 'UTB_ENTRIES_DB=$t/test-nodes/utb-agg2.db' <<<\"\$env\""
  utb_st "the history URL follows the aggregator's port" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(AGG_PORT=3100 utb_agg_history_url 2)\" = http://127.0.0.1:3101/api/v1/trustbases ]"
  # the evidence checker is exercised on real bytes (a generated chain, a served history, a captured response) by the Go test of scripts/utb-evidence: each bad-byte
  # property is refused by its own check, and a pack of placeholders is refused here
  local ev="$t/ev"
  mkdir -p "$ev"
  while read -r f; do mkdir -p "$ev/$(dirname "$f")"; printf 'x\n' >"$ev/$f"; done < <(utb_evidence_required)
  UBFT=$(realpath "$UBFT") utb_st_no "a pack of placeholders is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' UTB_EVIDENCE='${UTB_EVIDENCE:-build/utb-evidence}' utb_check_evidence '$ev'"
  utb_st "the evidence checker accepts a real pack and refuses each bad property (go test ./scripts/utb-evidence -run EvidencePack)" bash -c "cd '$cwd' && UBFT_BIN='$(realpath "$UBFT")' go test -count=1 ./scripts/utb-evidence -run EvidencePack"
  echo "utb lane self-test: $UTB_ST_BAD failures"
  [ "$UTB_ST_BAD" -eq 0 ]
}
