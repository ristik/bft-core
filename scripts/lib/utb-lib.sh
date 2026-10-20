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

# The environment of the aggregator (ristik/aggregator-go integration/enshrined-evm at the pinned AGG_COMMIT, built by utb_agg_build): UTB mode is enabled by UTB_GENESIS_ID; the
# genesis entry file is the fresh chain's history (UTB_BUNDLE_FILE would be a complete tagged history instead); UTB_ENTRIES_DB is its own append-only store. In UTB mode
# the binary uses neither the V1 trust-base files nor root REST.
utb_agg_env() { # K (1-based)
  local k=${1:-1}
  [ -s test-nodes/utb-genesis.cbor ] && [ -s test-nodes/utb-genesis.id ] || { echo "utb_agg_env: no UTB genesis (utb_prepare_genesis first)" >&2; return 1; }
  # BFT_RPC_ADDRESS is a dead port: in UTB mode the aggregator builds no root REST client, and the lane shows root HTTP is not what it uses. JSON logs: the
  # evidence reads the log lines by their exact messages (the markers of the aggregator's UTB history code: internal/bft/utb.go).
  echo "UTB_GENESIS_FILE=$PWD/test-nodes/utb-genesis.cbor UTB_GENESIS_ID=$(utb_pin) UTB_ENTRIES_DB=$PWD/test-nodes/utb-agg$k.db BFT_RPC_ADDRESS=http://127.0.0.1:1 LOG_LEVEL=debug LOG_FORMAT=json LOG_ENABLE_JSON=true"
}
# The aggregator's read-only binary history range (design 11.3 item 4): GET /api/v1/trustbases?from=E[&to=E]..., the PR6 response codec. The same endpoint serves the
# lane's reference client; port is the aggregator's (agg_port from scripts/lib/agg-lib.sh when it is loaded).
utb_agg_history_url() { local k=${1:-1} port=${AGG_PORT:-3001}; echo "http://127.0.0.1:$((port + k - 1))/api/v1/trustbases"; }

# The aggregator is ristik/aggregator-go integration/enshrined-evm at a pinned commit (AGG_COMMIT, 40 hex), built from a clean clone by utb_agg_build, never from a local patch.
# Its provenance directory builds/aggregator-<sha8>/ records the commit, the go.mod pins of bft-core and bft-go-base, the toolchain and the digest of the binary.
UTB_AGG_REPO=${UTB_AGG_REPO:-https://github.com/ristik/aggregator-go.git}

# utb_agg_build COMMIT [BUILDS_DIR]: clone, check out COMMIT, refuse a commit that is not on origin/integration/enshrined-evm, build with VCS stamping (the binary then
# carries its own revision), write the provenance directory and print the binary's path. Nothing is pushed anywhere.
utb_agg_build() {
  local commit=$1 builds=${2:-${AGRE_ROOT:-..}/builds} src out
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "utb_agg_build: AGG_COMMIT must be 40 hex digits" >&2; return 1; }
  src="$builds/aggregator-${commit:0:8}-src"; out="$builds/aggregator-${commit:0:8}"
  rm -rf "$src"; mkdir -p "$out"
  git clone -q "$UTB_AGG_REPO" "$src" || return 1
  git -C "$src" remote set-url --push origin DISABLED-the-lane-builds-and-never-pushes
  git -C "$src" checkout -q "$commit" || { echo "utb_agg_build: $commit is not in $UTB_AGG_REPO" >&2; return 1; }
  git -C "$src" merge-base --is-ancestor "$commit" origin/integration/enshrined-evm || { echo "utb_agg_build: $commit is not on integration/enshrined-evm" >&2; return 1; }
  [ -z "$(git -C "$src" status --porcelain)" ] || { echo "utb_agg_build: the clone is not clean" >&2; return 1; }
  ( cd "$src" && CGO_ENABLED=1 go build -trimpath -o "$out/aggregator" ./cmd/aggregator ) || return 1
  { echo "$commit"; } >"$out/commit.txt"
  grep -E '^[[:space:]]*(replace )?github.com/(unicitynetwork|ristik)/(bft-core|bft-go-base)( |$)' "$src/go.mod" >"$out/gomod-pins.txt"
  { go version; } >"$out/toolchain.txt"
  ( cd "$out" && shasum -a 256 aggregator commit.txt gomod-pins.txt ) >"$out/sha256.txt"
  echo "$out/aggregator"
}

# The aggregator binary's provenance directory: the aggregator-<sha8> directory whose sha256.txt records the binary's digest, which holds commit.txt (40 hex) and
# gomod-pins.txt, and whose commit is the one the binary itself reports as its VCS revision (go version -m). Prints the directory.
utb_agg_provenance() { # BIN [BUILDS_DIR]
  local bin=$1 builds=${2:-${AGRE_ROOT:-..}/builds} sum d commit rev
  sum=$(shasum -a 256 "$bin" 2>/dev/null | cut -d' ' -f1)
  [ -n "$sum" ] || { echo "utb_agg_provenance: cannot read $bin" >&2; return 1; }
  for d in "$builds"/aggregator-*/; do
    [ -s "${d}sha256.txt" ] && grep -q "^$sum " "${d}sha256.txt" || continue
    for f in commit.txt gomod-pins.txt; do [ -s "${d}$f" ] || { echo "utb_agg_provenance: ${d}$f is missing or empty" >&2; return 1; }; done
    commit=$(tr -d '[:space:]' <"${d}commit.txt")
    [[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "utb_agg_provenance: ${d}commit.txt is not a 40-hex commit" >&2; return 1; }
    rev=$(go version -m "$bin" 2>/dev/null | sed -n 's/^[[:space:]]*build[[:space:]]*vcs.revision=//p')
    [ "$rev" = "$commit" ] || { echo "utb_agg_provenance: the binary reports revision '${rev:-none}', its provenance says $commit" >&2; return 1; }
    go version -m "$bin" 2>/dev/null | grep -q 'vcs.modified=true' && { echo "utb_agg_provenance: the binary was built from a modified tree" >&2; return 1; }
    echo "${d%/}"; return 0
  done
  echo "utb_agg_provenance: no aggregator-* provenance under $builds records the binary digest $sum" >&2
  return 1
}

# utb_agg_pins_ok DIR REPO: the bft-core the aggregator was built against is this checkout or an ancestor of it (so a root of this checkout speaks what the
# aggregator speaks: the v3 response and the GetTrustBase wire), read from the provenance's go.mod pins (a pseudo-version ends with the 12-hex commit).
utb_agg_pins_ok() {
  local d=$1 repo=${2:-.} line hex
  line=$(grep -E 'bft-core ' "$d/gomod-pins.txt" | grep -E 'ristik/bft-core' | head -1)
  hex=$(sed -n 's/.*-\([0-9a-f]\{12\}\)$/\1/p' <<<"$line" | head -1)
  [ -n "$hex" ] || { echo "utb_agg_pins_ok: $d/gomod-pins.txt has no ristik/bft-core pseudo-version replace: '$line'" >&2; return 1; }
  git -C "$repo" merge-base --is-ancestor "$hex" HEAD 2>/dev/null || { echo "utb_agg_pins_ok: the aggregator is built on bft-core $hex, which is not this checkout or an ancestor" >&2; return 1; }
  echo "$hex"
}

# The components pinned in the manifest, from what the lane was given: the aggregator's commit and binary digest (from its provenance) and the other
# builds by their environment names.
utb_lane_components() {
  local d out=()
  [ -z "${M2_URETH_COMMIT:-}" ] || out+=("ureth=$M2_URETH_COMMIT")
  if [ -n "${AGG_BIN:-}" ] && d=$(utb_agg_provenance "$AGG_BIN" 2>/dev/null); then
    out+=("aggregator-commit=$(tr -d '[:space:]' <"$d/commit.txt")" "aggregator-binary=sha256:$(shasum -a 256 "$AGG_BIN" | cut -d' ' -f1)")
  fi
  [ -z "${UTB_SDK_JS:-}" ] || ! git -C "$UTB_SDK_JS" rev-parse HEAD >/dev/null 2>&1 || out+=("state-transition-sdk-js=$(git -C "$UTB_SDK_JS" rev-parse HEAD)")
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

# The aggregator takes an entry either from the response that carries it (the message path appends, never fetches) or from its own catch-up worker, which is
# asynchronous, coalesced and also woken by every handshake: which one is first is a race, and it is not a property of the root. U2 asserts what is not racy and records
# the rest: (1) the aggregator received version 3 responses carrying an attachment (the root attached the entry), (2) the aggregator added epoch 2 (tip 2), from a
# response or by a catch-up that ended without error, and (3) which of the two it was, with the log lines (the byte comparison of the held entry with the root's
# captured message is done by the step). utb_u2_evidence JSONL OUT.
utb_u2_evidence() {
  python3 - "$1" "$2" <<'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
app = [i for i, l in enumerate(lines) if l["msg"] == "trust-base entries appended from certification response" and l.get("added", 0) >= 1 and l.get("tip") == 2]
cu = [i for i, l in enumerate(lines) if l["msg"] == "trust-base catch-up finished" and not l.get("error") and l.get("added", 0) >= 1 and l.get("tip") == 2]
rcv = [l for l in lines if l["msg"] == "received CertificationResponseV3" and l.get("trustBaseUpdates", 0) >= 1]
bad = [l for l in lines if l["msg"] == "dropping an invalid trust-base update"]
if bad: raise SystemExit("the aggregator dropped %d attached trust-base updates as invalid: %s" % (len(bad), json.dumps(bad[0])))
if not rcv: raise SystemExit("the aggregator never received a version 3 response carrying an attachment: the root did not attach the entry")
if not app and not cu: raise SystemExit("the aggregator log shows epoch 2 added neither from a response nor by a catch-up")
via = "response" if app and (not cu or app[0] < cu[0]) else "catch-up"
held = [l for l in lines if l["msg"] == "trust-base update already held" and l.get("tip", 0) >= 2]
if via == "catch-up" and not held: raise SystemExit("the catch-up added epoch 2 but no attachment was shown consumed: no 'trust-base update already held' line with tip >= 2 (the aggregator runs at LOG_LEVEL=debug)")
first = lines[min(app + cu)]
how = {"response": "from a certification response (the message path)", "catch-up": "by its catch-up worker from a root over GetTrustBase"}[via]
open(sys.argv[2], "w").write("attached: the aggregator received %d version 3 responses carrying entries (first at line %d with %d)\nadded: epoch 2 (tip 2) was added %s\npath: %s\nconsumed: %s\ninvalid attachments dropped: 0\n%s\n%s\n" % (len(rcv), lines.index(rcv[0]) + 1, rcv[0]["trustBaseUpdates"], how, via, ("%d attachments read after the catch-up and found already held (DEBUG), first: %s" % (len(held), json.dumps(held[0]))) if held else "the response's own append (INFO)", json.dumps(rcv[0]), json.dumps(first)))
PY
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
  cp test-nodes/evm-full-shard-conf-v2.json "$out/manifest/shard-conf.json" && cp "$(agg_conf 1)" "$out/manifest/shard-conf-aggregator.json" || return 1
  utb_ev uc-verify --token "$out/proofs/token.cbor" --bundle "$out/bundle/initial.cbor" --shard-conf "$out/manifest/shard-conf.json,$out/manifest/shard-conf-aggregator.json" | tee "$out/proofs/before-rotation-verify.txt" || return 1
  # the reference client starts from the genesis alone and holds it through the whole rotation
  utb_ev client --url "$(utb_agg_url)" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" | tee "$out/history/client-start.log" || return 1
  echo "U1: the aggregator and the client hold the genesis only; the original proof ($(cut -c1-12 "$out/proofs/original-proof.sha256")...) verifies under it"
}

# The K->J handoff is activated: the aggregator received the signed entry of epoch 2 attached to a certification response (and nothing else could have told it).
utb_step_u2() {
  local out off t n; out=$(utb_dir)
  utb_wait_agg_tip 2 90 || return 1
  t="$out/bundle/after-activation.cbor"
  utb_ev fetch --url "$(utb_agg_url)" --out "$t" && utb_ev verify --bundle "$t" --pin "$(utb_pin)" | tee "$out/bundle/after-activation.verify.txt" || return 1
  utb_ev extract --bundle "$t" --epoch 2 --out "$out/entries/ordinary-handoff.cbor" || return 1
  # the aggregator logs asynchronously: wait for the line which shows epoch 2 added (from a response or by its catch-up) before the log is read
  for n in $(seq 1 60); do utb_agg_lines_since 0 | jq -e -s 'any(.[]; (.msg=="trust-base entries appended from certification response" and .tip==2) or (.msg=="trust-base catch-up finished" and .tip==2 and (.added//0)>=1))' >/dev/null 2>&1 && break; sleep 1; done
  utb_agg_lines_since 0 | jq -c 'select(.msg=="received CertificationResponseV3" or .msg=="trust-base entries appended from certification response" or .msg=="trust-base catch-up started" or .msg=="trust-base catch-up finished" or .msg=="trust-base gap in certification response" or .msg=="trust-base update already held" or .msg=="dropping an invalid trust-base update")' >"$out/handoff/aggregator-ordinary.jsonl"
  utb_u2_evidence "$out/handoff/aggregator-ordinary.jsonl" "$out/handoff/ordinary-ack.log" || return 1
  # the real message the root sent: captured just before it was sent
  local f; f=$(ls test-nodes/utb-ucresp/root*/ucresp-e2-*.cbor 2>/dev/null | head -1)
  [ -n "$f" ] || { echo "no captured version 3 response with the epoch-2 entry under test-nodes/utb-ucresp" >&2; return 1; }
  cp "$f" "$out/ucresp/piggyback-sample.cbor"
  utb_ev ucresp --file "$out/ucresp/piggyback-sample.cbor" --entry "$out/entries/ordinary-handoff.cbor" | tee "$out/ucresp/piggyback-sample.check.txt" || return 1
  echo "U2: the root attached epoch 2 to its responses and the aggregator holds it (tip 2, byte for byte the entry of the captured message); the path that added it is in handoff/ordinary-ack.log"
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
  local i
  local out off; out=$(utb_dir)
  off=$(utb_agg_offset)
  start_agg 1 || return 1
  utb_wait_agg_tip 3 90 || return 1
  # the aggregator logs asynchronously: the history can be served (tip 3) before its catch-up lines reach the file
  for i in $(seq 1 60); do utb_agg_lines_since "$off" | grep -aq '"msg":"trust-base catch-up finished"' && break; sleep 1; done
  utb_agg_lines_since "$off" | jq -c 'select((.msg|startswith("trust-base catch-up")) or .msg=="trust-base gap in certification response" or .msg=="Signed trust-base history loaded" or .msg=="trust-base handshake to the newest held committee" or .msg=="trust-base entries appended from certification response" or .msg=="dropping an invalid trust-base update")' >"$out/catchup/aggregator-repair.jsonl"
  python3 -I "$(dirname "${BASH_SOURCE[0]}")/utb-repair-check.py" "$out/catchup/aggregator-repair.jsonl" "$out/catchup/aggregator-peer-repair.log" || return 1
  # the repaired history authenticates from the pin and holds epoch 2 byte for byte as the root attached it; U4 checks the final bundle is these bytes
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/after-repair.cbor" >/dev/null || return 1
  utb_ev verify --bundle "$out/bundle/after-repair.cbor" --pin "$(utb_pin)" | grep -q '^ok: epochs 1\.\.3, ' || { echo "the repaired history is not epochs 1..3 authenticated from the pin" >&2; return 1; }
  utb_ev extract --bundle "$out/bundle/after-repair.cbor" --epoch 2 --out "$out/entries/repaired-2.cbor" >/dev/null && cmp -s "$out/entries/repaired-2.cbor" "$out/entries/ordinary-handoff.cbor" || { echo "the repaired epoch 2 differs from the entry the root attached" >&2; return 1; }
  echo "U3b: a catch-up from the roots raised the aggregator's tip (the line is in catchup/aggregator-peer-repair.log); the history is epochs 1..3 from the pin"
}

# After the acknowledgement: the post-recovery token (certified under the epoch-3 committee), the client's unknown-epoch gap, the aggregator's second restart.
utb_step_u4() {
  local out i hex; out=$(utb_dir)
  # A certificate issued after the recovery: the aggregator's latest block carries the unicity certificate of its partition (the bridge's lock proofs cannot be made for the
  # successor epoch: the dnb tool's lock proof binds the EVM shard configuration of epoch 1). The aggregator certifies a block every round, so the latest one is of the
  # current root epoch (3) shortly after the aggregator is back on the recovered chain.
  for i in $(seq 1 60); do
    hex=$(curl -fsS -X POST "http://127.0.0.1:$(agg_port 1)/" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_block","params":{"blockNumber":"latest"}}' 2>/dev/null \
      | jq -r '.result.block.unicityCertificate // empty' | sed 's/^0x//')
    if [ -n "$hex" ]; then
      printf '%s' "$hex" | xxd -r -p >"$out/proofs/post-recovery-token.cbor"
      utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/final-probe.cbor" >/dev/null 2>&1 && \
        utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/bundle/final-probe.cbor" --shard-conf "$(agg_conf 1)" 2>&1 | grep -q '^certificate 0: epoch 3 ' && break
    fi
    sleep 2
  done
  rm -f "$out/bundle/final-probe.cbor"
  [ -s "$out/proofs/post-recovery-token.cbor" ] && [ "$i" -lt 60 ] || { echo "the aggregator's latest block certificate is not one of epoch 3 within 120 s of the recovery" >&2; utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$(agg_conf 1)" >&2 || true; return 1; }
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/final.cbor" && cmp -s "$out/bundle/after-repair.cbor" "$out/bundle/final.cbor" && utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | tee "$out/bundle/final.verify.txt" || return 1
  utb_ev extract --bundle "$out/bundle/final.cbor" --epoch 3 --out "$out/entries/recovery.cbor" || return 1
  utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | grep '^epoch 2 ' >"$out/verifier/ordinary.txt" && utb_ev verify --bundle "$out/bundle/final.cbor" --pin "$(utb_pin)" | grep '^epoch 3 ' >"$out/verifier/recovery.txt" || return 1
  # the reference client was last seen at the genesis: the post-recovery certificate names an epoch it does not hold
  utb_ev client --export "$out/history/client-stale.cbor" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" --url "" >/dev/null 2>&1 || true
  if utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/history/client-stale.cbor" --shard-conf "$out/manifest/shard-conf.json,$out/manifest/shard-conf-aggregator.json" >"$out/history/client-before-sync.txt" 2>&1; then
    echo "the stale client verified an epoch-3 certificate: it should have met an unknown epoch" >&2; return 1
  fi
  grep -q "does not hold" "$out/history/client-before-sync.txt" || { echo "the stale client failed for another reason: $(cat "$out/history/client-before-sync.txt")" >&2; return 1; }
  utb_ev client --url "$(utb_agg_url)" --store "$out/client.db" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" --export "$out/history/client-synced.cbor" | tee "$out/catchup/client-gap-two-entries.log" || return 1
  grep -q "appended \[2 3\]" "$out/catchup/client-gap-two-entries.log" || { echo "the client did not fetch both missed entries in one sync" >&2; return 1; }
  utb_ev uc-verify --token "$out/proofs/post-recovery-token.cbor" --bundle "$out/history/client-synced.cbor" --shard-conf "$out/manifest/shard-conf.json,$out/manifest/shard-conf-aggregator.json" | tee "$out/history/client-after-sync.txt" || return 1
  # the aggregator restarts once more from its (repaired) store: unchanged bytes, certification resumes
  restart_agg 1 || return 1
  utb_wait_agg_tip 3 60 || return 1
  utb_ev fetch --url "$(utb_agg_url)" --out "$out/bundle/after-second-restart.cbor" >/dev/null && cmp -s "$out/bundle/final.cbor" "$out/bundle/after-second-restart.cbor" || { echo "the aggregator's history changed across its second restart" >&2; return 1; }
  echo "second restart: unchanged history bytes ($(shasum -a 256 <"$out/bundle/final.cbor" | cut -d' ' -f1))" >>"$out/catchup/restart.log"
  curl -fsS "http://127.0.0.1:$(agg_port 1)/health" >>"$out/catchup/restart.log" 2>&1 || { echo "the aggregator is not healthy after its second restart" >&2; return 1; }
  echo "U4: the stale client met epoch 3, fetched [2 3] in one request and verified; the aggregator restarted twice with unchanged records"
}

# The JS SDK of the fork (UTB_SDK_JS: a built checkout of ristik/state-transition-sdk-js integration/enshrined-evm) is the client: it holds the genesis alone, meets the
# post-recovery certificate's unknown epoch, fetches the entries from the aggregator's GetTrustBase endpoint (the SDK's own fetch-and-retry loop) and verifies it.
utb_step_u4b() {
  local out; out=$(utb_dir); mkdir -p "$out/sdk"
  [ -f "${UTB_SDK_JS:?UTB_SDK_JS (a built state-transition-sdk-js checkout) is not set}/lib/util/TrustBaseUtils.js" ] || { echo "UTB_SDK_JS ($UTB_SDK_JS) is not a built SDK (npm ci && npm run build)" >&2; return 1; }
  git -C "$UTB_SDK_JS" rev-parse HEAD >"$out/sdk/sdk-commit.txt" 2>/dev/null || { echo "UTB_SDK_JS is not a git checkout" >&2; return 1; }
  node "$PWD/scripts/utb-sdk-client/check.mjs" --sdk "$UTB_SDK_JS" --url "http://127.0.0.1:$(agg_port 1)" --genesis test-nodes/utb-genesis.cbor --pin "$(utb_pin)" \
    --uc "$out/proofs/post-recovery-token.cbor" --expect-tip 3 --entry "2=$out/entries/ordinary-handoff.cbor" --entry "3=$out/entries/recovery.cbor" --out "$out/sdk/client.log" || return 1
  grep -q '^sdk client check: PASSED' "$out/sdk/client.log" || { echo "sdk/client.log does not end with the check's PASSED line" >&2; return 1; }
  echo "U4b: the JS SDK client verified the epoch-3 certificate after fetching epochs 2..3 from the aggregator"
}

# The root logs (rev2's asks on #648/#649): each state import (a completed recovery, with its log line: round and time), and the two refusals that must never appear
# (the sentinel text of ErrUTBSuccessor covers both of its causes), counted over every root's log of the run.
utb_root_log_report() { # OUT
  local out=$1 f total_a=0 total_b=0 rec=0 logs=() n m
  # one log per root: debug.log holds everything stdout.log has (counting both would count a line twice)
  for f in test-nodes/root*/; do
    if [ -s "${f}debug.log" ]; then logs+=("${f}debug.log"); elif [ -s "${f}stdout.log" ]; then logs+=("${f}stdout.log"); fi
  done
  [ ${#logs[@]} -gt 0 ] || { echo "no root logs under test-nodes/root*" >&2; return 1; }
  : >"$out"
  for f in "${logs[@]}"; do
    n=$(grep -ac 'V3 freeze rules are not enabled' "$f" || true); total_a=$((total_a + n))
    m=$(grep -ac 'successor trust-base entry cannot be derived' "$f" || true); total_b=$((total_b + m))
    echo "$f: freeze-disabled $n, successor-cannot-be-derived $m, completed-recovery $(grep -ac 'completed recovery' "$f" || true)" >>"$out"
  done
  { echo "root logs inspected: ${#logs[@]}"
    echo "V3 freeze rules are not enabled: $total_a"
    echo "successor trust-base entry cannot be derived: $total_b"
    echo "state imports (completed recovery), each with its log line:"
    for f in "${logs[@]}"; do grep -a 'completed recovery' "$f" | cut -c1-240 | sed "s#^#  $f: #"; done
  } >>"$out"
  rec=$(grep -c '^  .*completed recovery' "$out" || true)
  echo "state imports: $rec" >>"$out"
  [ "$rec" -gt 0 ] && echo "state import exercised: yes" >>"$out" || echo "state import exercised: no" >>"$out"
  [ "$total_a" -eq 0 ] && [ "$total_b" -eq 0 ]
}

# After L1c: the original proof verifies unchanged under its historical committee; the bridge receipt; the exported history reloads exactly.
utb_step_u5() {
  local out got; out=$(utb_dir)
  [ "$(shasum -a 256 <"$out/proofs/token.cbor" | cut -d' ' -f1)" = "$(cat "$out/proofs/original-proof.sha256")" ] || { echo "the original proof changed" >&2; return 1; }
  utb_ev uc-verify --token "$out/proofs/token.cbor" --bundle "$out/bundle/final.cbor" --shard-conf "$out/manifest/shard-conf.json,$out/manifest/shard-conf-aggregator.json" | tee "$out/proofs/historical-verify.log" || return 1
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
  { echo "bft-core $(git rev-parse HEAD) ubft sha256 $(shasum -a 256 "$UBFT" | cut -d' ' -f1)"; echo "utb-evidence sha256 $(shasum -a 256 "$UTB_EVIDENCE" | cut -d' ' -f1)"; echo "aggregator sha256 $(shasum -a 256 "$AGG_BIN" | cut -d' ' -f1)"
    echo "native-bridge-plugins $(git -C "${NBP_DIR:?}" rev-parse HEAD) (prerequisite: its live driver reads the trust-base release bundle, native-bridge-plugins#27; reads trust-base.bundle.cbor: $(grep -c 'trust-base.bundle.cbor' "$NBP_DIR/tests/live/anyage.ts") places)"
    echo "state-transition-sdk-js $(git -C "${UTB_SDK_JS:?}" rev-parse HEAD)"; } >"$out/manifest/build.txt"
  mkdir -p "$out/manifest/aggregator"; cp "$(utb_agg_provenance "$AGG_BIN" "${AGRE_ROOT:-$PWD/..}/builds")"/{commit.txt,gomod-pins.txt,sha256.txt} "$out/manifest/aggregator/" || return 1
  cp "$(agg_dir 1)/logs/aggregator.log" "$out/catchup/aggregator.log" 2>/dev/null || true
  # the recovery's closures, as the lane's own step printed them (both closures before the RecoveryAck, J closed at its closure's anchors)
  grep -a "closed at\|PASS: p85_recovery\|PASS: p85_resolved\|PASS: anyage_step_l2" "${EVIDENCE_LANE_LOG:?}" >"$out/handoff/recovery-closure.log" || true
  grep -q "closed at" "$out/handoff/recovery-closure.log" || { echo "the lane log shows no closure result for the recovery" >&2; return 1; }
  mkdir -p "$out/checks"; utb_root_log_report "$out/checks/root-logs.txt" || { cat "$out/checks/root-logs.txt" >&2; echo "a root log shows a refusal that must be absent" >&2; return 1; }
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
manifest/shard-conf-aggregator.json
manifest/build.txt
manifest/aggregator/commit.txt
manifest/aggregator/gomod-pins.txt
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
proofs/post-recovery-token.cbor
history/client-stale.cbor
history/client-synced.cbor
history/client-before-sync.txt
history/client-after-sync.txt
sdk/client.log
sdk/sdk-commit.txt
checks/root-logs.txt
LIST
}

UTB_EVIDENCE=${UTB_EVIDENCE:-build/utb-evidence}

# utb_check_evidence DIR: every required file exists and is non-empty, and the bytes are what they claim to be, checked by the tools and not by keyword:
#  - the manifest checks out against the trust base and genesis entry inside the pack;
#  - bundle/final.cbor is a tagged history from the manifest's pinned genesis, every record verified from its predecessor (utb-evidence verify);
#  - each verifier output is exactly that tool's line for the record's epoch (2: the K->J handoff, 3: the recovery), and each entries/*.cbor is exactly that history's record for it;
#  - bundle/initial.cbor verifies from the same pin, is shorter, and is a prefix of the final history;
#  - the UCResp sample is a version 3 response whose attachment is byte-identical to entries/ordinary-handoff.cbor;
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
  "$tool" ucresp --file "$dir/ucresp/piggyback-sample.cbor" --entry "$dir/entries/ordinary-handoff.cbor" >/dev/null 2>&1 || { echo "the UCResp sample is not a version 3 response attaching entries/ordinary-handoff.cbor byte for byte" >&2; return 1; }
  want=$(tr -d '[:space:]' <"$dir/proofs/original-proof.sha256" | cut -d' ' -f1)
  [ "$(shasum -a 256 <"$dir/proofs/token.cbor" | cut -d' ' -f1)" = "${want%% *}" ] || { echo "proofs/token.cbor is not the original proof (its digest is not the recorded one)" >&2; return 1; }
  got=$("$tool" uc-verify --token "$dir/proofs/token.cbor" --bundle "$dir/bundle/final.cbor" --shard-conf "$dir/manifest/shard-conf.json,$dir/manifest/shard-conf-aggregator.json" 2>&1) || { echo "the original proof's certificates do not verify under their epochs' committees: $got" >&2; return 1; }
  [ "$(cat "$dir/proofs/historical-verify.log")" = "$got" ] || { echo "proofs/historical-verify.log is not the verifier's output on proofs/token.cbor" >&2; return 1; }
  local tip; tip=$(sed -n 's/^ok: epochs [0-9]*\.\.\([0-9]*\), tip.*/\1/p' <<<"$out")
  have=$(shasum -a 256 <"$dir/bundle/final.cbor" | cut -d' ' -f1)
  grep -q "$have" "$dir/history/client-reload.log" && grep -q "tip now $tip" "$dir/history/client-reload.log" || { echo "history/client-reload.log does not record the final bundle digest $have and tip $tip" >&2; return 1; }
  grep -q "appended \[2 3\]" "$dir/catchup/client-gap-two-entries.log" || { echo "the client gap log does not show epochs 2 and 3 fetched in one sync" >&2; return 1; }
  # the client flow, re-run by the tool: a client that holds the genesis only meets the unknown epoch of the post-recovery certificate; the synced client holds the final history and verifies it
  local confs="$dir/manifest/shard-conf.json,$dir/manifest/shard-conf-aggregator.json" stale
  stale=$("$tool" verify --bundle "$dir/history/client-stale.cbor" --pin "$pin" 2>&1) || { echo "history/client-stale.cbor does not verify from the pin: $stale" >&2; return 1; }
  grep -q '^ok: epochs 1\.\.1,' <<<"$stale" || { echo "history/client-stale.cbor is not the genesis-only history of a client that missed the rotation: $(tail -1 <<<"$stale")" >&2; return 1; }
  got=$("$tool" uc-verify --token "$dir/proofs/post-recovery-token.cbor" --bundle "$dir/history/client-stale.cbor" --shard-conf "$confs" 2>&1) \
    && { echo "the post-recovery certificate verified under the genesis-only history: it must meet an unknown epoch" >&2; return 1; }
  grep -q "which the history does not hold" <<<"$got" || { echo "the stale client fails for another reason than the unknown epoch: $got" >&2; return 1; }
  [ "$(cat "$dir/history/client-before-sync.txt")" = "$got" ] || { echo "history/client-before-sync.txt is not the verifier's refusal on the stale history" >&2; return 1; }
  synced=$("$tool" verify --bundle "$dir/history/client-synced.cbor" --pin "$pin" 2>&1) || { echo "history/client-synced.cbor does not verify from the pin: $synced" >&2; return 1; }
  [ "$(sed -n 's/^ok: epochs [0-9]*\.\.\([0-9]*\), tip.*/\1/p' <<<"$synced")" = "$tip" ] && [ "$tip" = 3 ] || { echo "history/client-synced.cbor does not end at tip 3: $(tail -1 <<<"$synced")" >&2; return 1; }
  got=$("$tool" uc-verify --token "$dir/proofs/post-recovery-token.cbor" --bundle "$dir/history/client-synced.cbor" --shard-conf "$confs" 2>&1) || { echo "the post-recovery certificate does not verify under the synced history: $got" >&2; return 1; }
  grep -q '^certificate 0: epoch 3 ' <<<"$got" || { echo "the post-recovery certificate is not one of epoch 3: $got" >&2; return 1; }
  [ "$(cat "$dir/history/client-after-sync.txt")" = "$got" ] || { echo "history/client-after-sync.txt is not the verifier's output on the synced history" >&2; return 1; }
  grep -q '^sdk client check: PASSED' "$dir/sdk/client.log" && grep -q "tip now $tip" "$dir/sdk/client.log" && grep -q '^before: verdict no_entry_for_epoch' "$dir/sdk/client.log" || { echo "sdk/client.log does not show the SDK client meeting the unknown epoch and verifying at tip $tip after the fetch" >&2; return 1; }
  grep -qE '^[0-9a-f]{40}$' "$dir/sdk/sdk-commit.txt" || { echo "sdk/sdk-commit.txt is not a commit" >&2; return 1; }
  grep -q '^V3 freeze rules are not enabled: 0$' "$dir/checks/root-logs.txt" && grep -q '^successor trust-base entry cannot be derived: 0$' "$dir/checks/root-logs.txt" || { echo "checks/root-logs.txt does not show both refusal counts at 0" >&2; return 1; }
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
  # the aggregator provenance: a binary built from a real commit (it reports its own VCS revision) is found by its digest; an unrecorded binary, a provenance whose
  # commit differs from the one the binary reports, a missing pins file and a commit that is not 40 hex are refused
  local bld="$t/builds" bin="$t/agg-src/agg" commit pd
  mkdir -p "$t/agg-src" "$bld"
  ( cd "$t/agg-src" && git init -q && git config user.email lane@local && git config user.name lane && printf 'module aggprobe\n\ngo 1.24\n' >go.mod \
    && printf 'package main\n\nfunc main() {}\n' >main.go && git add . && git commit -q -m probe && go build -o agg . ) 2>/dev/null
  commit=$(git -C "$t/agg-src" rev-parse HEAD 2>/dev/null); pd="$bld/aggregator-${commit:0:8}"
  mkdir -p "$pd"; printf '%s\n' "$commit" >"$pd/commit.txt"
  printf 'replace github.com/unicitynetwork/bft-core => github.com/ristik/bft-core v1.1.1-0.20261019192856-f4f324197c63\n' >"$pd/gomod-pins.txt"
  ( cd "$pd" && cp "$bin" aggregator && shasum -a 256 aggregator commit.txt gomod-pins.txt >sha256.txt )
  utb_st "the aggregator provenance is found by the binary digest and its reported revision" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(utb_agg_provenance '$bin' '$bld')\" = '$pd' ]"
  utb_st_no "an unrecorded binary is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'other\n' >'$t/other'; utb_agg_provenance '$t/other' '$bld'"
  utb_st_no "a provenance whose commit is not the binary's revision is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf '%s\n' 0123456789012345678901234567890123456789 >'$pd/commit.txt'; utb_agg_provenance '$bin' '$bld'"
  printf '%s\n' "$commit" >"$pd/commit.txt"
  utb_st_no "a commit that is not 40 hex is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'abc\n' >'$pd/commit.txt'; utb_agg_provenance '$bin' '$bld'"
  printf '%s\n' "$commit" >"$pd/commit.txt"
  utb_st_no "a missing pins file is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; rm '$pd/gomod-pins.txt'; utb_agg_provenance '$bin' '$bld'"
  printf 'replace github.com/unicitynetwork/bft-core => github.com/ristik/bft-core v1.1.1-0.20261019192856-f4f324197c63\n' >"$pd/gomod-pins.txt"
  # the pin check: an ancestor of the lane's checkout passes, a commit that is not refuses
  utb_st "the aggregator's bft-core pin is accepted when it is an ancestor of the checkout" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; git -C '$cwd' cat-file -e f4f324197 2>/dev/null || exit 0; git -C '$cwd' merge-base --is-ancestor f4f324197 HEAD || exit 0; [ \"\$(utb_agg_pins_ok '$pd' '$cwd')\" = f4f324197c63 ]"
  utb_st_no "an aggregator pin that is not in the checkout's history is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; printf 'replace github.com/unicitynetwork/bft-core => github.com/ristik/bft-core v1.1.1-0.20261019192856-000000000000\n' >'$pd/gomod-pins.txt'; utb_agg_pins_ok '$pd' '$cwd'"
  utb_st "the aggregator environment carries the genesis, the pin and its own store" bash -c "cd '$t' && source '$cwd/scripts/lib/utb-lib.sh' && env=\$(utb_agg_env 2) && grep -q 'UTB_GENESIS_FILE=$t/test-nodes/utb-genesis.cbor' <<<\"\$env\" && grep -q 'UTB_GENESIS_ID=0x' <<<\"\$env\" && grep -q 'UTB_ENTRIES_DB=$t/test-nodes/utb-agg2.db' <<<\"\$env\""
  utb_st "the history URL follows the aggregator's port" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; [ \"\$(AGG_PORT=3100 utb_agg_history_url 2)\" = http://127.0.0.1:3101/api/v1/trustbases ]"
  # the U3b repair judgement: a catch-up from the roots must raise the tip; responses alone, or a catch-up that only re-appends held entries, do not pass
  local rc="$cwd/scripts/lib/utb-repair-check.py"
  mkdir -p "$t/rep"
  { echo "{\"msg\":\"trust-base catch-up started\",\"from\":2}"
    echo "{\"msg\":\"trust-base catch-up page\",\"from\":2,\"peer\":\"p1\",\"status\":\"OK\",\"entries\":1}"
    echo "{\"msg\":\"trust-base catch-up finished\",\"added\":1,\"tip\":2}"
    echo "{\"msg\":\"trust-base catch-up started\",\"from\":3}"
    echo "{\"msg\":\"trust-base catch-up page\",\"from\":3,\"peer\":\"p1\",\"status\":\"OK\",\"entries\":1}"
    echo "{\"msg\":\"trust-base entries appended from certification response\",\"added\":1,\"tip\":3}"
    echo "{\"msg\":\"trust-base catch-up finished\",\"added\":1,\"tip\":3}"; } >"$t/rep/real.jsonl"
  # responses raise the tip first; the catch-up only re-appends the held entries (its pages are OK and carry entries)
  { echo "{\"msg\":\"trust-base catch-up started\",\"from\":2}"
    echo "{\"msg\":\"trust-base entries appended from certification response\",\"added\":1,\"tip\":2}"
    echo "{\"msg\":\"trust-base entries appended from certification response\",\"added\":1,\"tip\":3}"
    echo "{\"msg\":\"trust-base catch-up page\",\"from\":2,\"peer\":\"p1\",\"status\":\"OK\",\"entries\":2}"
    echo "{\"msg\":\"trust-base catch-up finished\",\"added\":2,\"tip\":3}"; } >"$t/rep/responses-only.jsonl"
  grep -v 'catch-up finished' "$t/rep/real.jsonl" >"$t/rep/no-finish.jsonl"
  { cat "$t/rep/real.jsonl"; echo "{\"msg\":\"dropping an invalid trust-base update\"}"; } >"$t/rep/dropped.jsonl"
  utb_st "a repair by a catch-up that raised the tip, with a response overlapping the last entry, is accepted" python3 -I "$rc" "$t/rep/real.jsonl" "$t/rep/out.log"
  utb_st_no "a repair where only responses raised the tip is refused" python3 -I "$rc" "$t/rep/responses-only.jsonl" "$t/rep/out.log"
  utb_st_no "a repair with no finished catch-up is refused" python3 -I "$rc" "$t/rep/no-finish.jsonl" "$t/rep/out.log"
  utb_st_no "a repair with a dropped invalid update is refused" python3 -I "$rc" "$t/rep/dropped.jsonl" "$t/rep/out.log"
  # the root-log report: clean logs pass and report the counts; each refusal string, alone, fails it
  mkdir -p "$t/rl/test-nodes/root0" "$t/rl/test-nodes/root1"
  printf 'ok line\ncompleted recovery\n' >"$t/rl/test-nodes/root0/debug.log"; printf 'ok line\n' >"$t/rl/test-nodes/root1/debug.log"
  utb_st "the root-log report passes clean logs and counts the recoveries" bash -c "cd '$t/rl' && source '$cwd/scripts/lib/utb-lib.sh' && utb_root_log_report r.txt && grep -q '^V3 freeze rules are not enabled: 0\$' r.txt && grep -q '^successor trust-base entry cannot be derived: 0\$' r.txt && grep -q 'state import exercised: yes' r.txt"
  utb_st_no "a root log with the freeze-disabled refusal fails the report" bash -c "cd '$t/rl' && source '$cwd/scripts/lib/utb-lib.sh' && echo 'x storage: V3 freeze rules are not enabled for this committee' >>test-nodes/root1/debug.log && utb_root_log_report r.txt"
  printf 'ok line\n' >"$t/rl/test-nodes/root1/debug.log"
  utb_st_no "a root log with the not-retained refusal fails the report" bash -c "cd '$t/rl' && source '$cwd/scripts/lib/utb-lib.sh' && echo 'x successor trust-base entry cannot be derived' >>test-nodes/root1/debug.log && utb_root_log_report r.txt"
  utb_st_no "no root logs fails the report" bash -c "mkdir -p '$t/nolog' && cd '$t/nolog' && source '$cwd/scripts/lib/utb-lib.sh' && utb_root_log_report r.txt"
  # U2's evidence: the cases of the real run utb-20261020T014202Z (a catch-up added epoch 2 while responses carried the entry) and of a response that won; each missing
  # property alone is refused
  local u2="$t/u2"; mkdir -p "$u2"
  printf '%s\n' '{"msg":"trust-base catch-up started","from":2}' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":null}' '{"msg":"trust-base update already held","attached":1,"tip":2}' >"$u2/catchup.jsonl"
  printf '%s\n' '{"msg":"trust-base catch-up started","from":2}' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":null}' >"$u2/notconsumed.jsonl"
  printf '%s\n' '{"msg":"trust-base catch-up started","from":2}' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":null}' '{"msg":"trust-base update already held","attached":1,"tip":1}' >"$u2/heldtip1.jsonl"
  printf '%s\n' '{"msg":"trust-base catch-up started","from":2}' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":null}' '{"msg":"trust-base update already held","attached":1,"tip":2}' '{"msg":"dropping an invalid trust-base update","error":"x"}' >"$u2/dropped.jsonl"
  printf '%s\n' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base entries appended from certification response","added":1,"tip":2}' >"$u2/response.jsonl"
  printf '%s\n' '{"msg":"trust-base catch-up started","from":2}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":null}' >"$u2/noattach.jsonl"
  printf '%s\n' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":0,"tip":1,"error":null}' >"$u2/noadd.jsonl"
  printf '%s\n' '{"msg":"received CertificationResponseV3","trustBaseUpdates":1}' '{"msg":"trust-base catch-up finished","added":1,"tip":2,"error":"no peer served the range"}' >"$u2/failedcatchup.jsonl"
  utb_st "U2 evidence: epoch 2 added by the catch-up while responses carried it is accepted and the path is recorded" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/catchup.jsonl' '$u2/o1' && grep -q '^path: catch-up' '$u2/o1' && grep -q '^attached: ' '$u2/o1'"
  utb_st "U2 evidence: epoch 2 added from a response is accepted and the path is recorded" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/response.jsonl' '$u2/o2' && grep -q '^path: response' '$u2/o2'"
  utb_st_no "U2 evidence: the catch-up won and no attachment was shown consumed" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/notconsumed.jsonl' '$u2/o6'"
  utb_st_no "U2 evidence: an 'already held' line below tip 2 does not show epoch 2 consumed" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/heldtip1.jsonl' '$u2/o7'"
  utb_st_no "U2 evidence: an attachment dropped as invalid fails it" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/dropped.jsonl' '$u2/o8'"
  utb_st "U2 evidence: the catch-up case records that the attachments were consumed" bash -c "grep -q '^consumed: 1 attachments read after the catch-up' '$u2/o1'"
  utb_st_no "U2 evidence: no response carried an attachment" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/noattach.jsonl' '$u2/o3'"
  utb_st_no "U2 evidence: epoch 2 was not added" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/noadd.jsonl' '$u2/o4'"
  utb_st_no "U2 evidence: a failed catch-up is not an add" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; utb_u2_evidence '$u2/failedcatchup.jsonl' '$u2/o5'"
  # the evidence checker is exercised on real bytes (a generated chain, a served history, a captured response) by the Go test of scripts/utb-evidence: each bad-byte
  # property is refused by its own check, and a pack of placeholders is refused here
  local ev="$t/ev"
  mkdir -p "$ev"
  while read -r f; do mkdir -p "$ev/$(dirname "$f")"; printf 'x\n' >"$ev/$f"; done < <(utb_evidence_required)
  UBFT=$(realpath "$UBFT") utb_st_no "a pack of placeholders is refused" bash -c "source '$cwd/scripts/lib/utb-lib.sh'; UBFT='$UBFT' UTB_EVIDENCE='${UTB_EVIDENCE:-build/utb-evidence}' utb_check_evidence '$ev'"
  utb_st "the evidence checker accepts a real pack and refuses each bad property (go test ./scripts/utb-evidence -run EvidencePack)" bash -c "cd '$cwd' && UBFT_BIN='$(realpath "$UBFT")' go test -count=1 ./scripts/utb-evidence -run EvidencePack"
  utb_st "the P85 genesis preparation passes the root identity and the caps to p85-genesis.sh (dry run with fakes: bash -c 'source scripts/lib/p85-lib.sh; p85_selftest')" bash -c "cd '$cwd' && source scripts/lib/p85-lib.sh && p85_selftest"
  echo "utb lane self-test: $UTB_ST_BAD failures"
  [ "$UTB_ST_BAD" -eq 0 ]
}
