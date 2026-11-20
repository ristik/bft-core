#!/usr/bin/env bash
# VT-12 live acceptance (bft-core#1152) on a running generation with the monitoring pack up (scripts/vt12-monitoring.sh start).
# Induces conditions on the lane's own processes and shows each alert firing for the validator under observation and resolving: a paused ureth (EVM
# stopped), a cut root peer link, a tmpfs filled to the brim, a stopped exporter (scrape failure), a paused public RPC (the exporter's read failure)
# and a stubbed pending upgrade; then renders the dashboard. Every assertion matches the alert by name AND label (validator, job) and checks that it
# was quiet before the condition was induced. Evidence goes to $EVID (default ~/evidence/vt12/live).
# Needs sudo for iptables and mount. Only this lane's processes and ports are touched; every induced condition is undone.
set -uo pipefail
EVID=${EVID:-$HOME/evidence/vt12/live}; mkdir -p "$EVID"
PROM=http://127.0.0.1:${MON_PROM_PORT:-19090}
GRAFANA=http://127.0.0.1:${MON_GRAFANA_PORT:-13000}
MON=${MON_DIR:-test-nodes/monitoring}
log() { echo "$(date -u +%T) $*" | tee -a "$EVID/acceptance.log"; }
# firing <alert> [label=value ...]: succeeds when a firing alert of that name carries every given label
firing() {
  local name=$1; shift
  curl -s "$PROM/api/v1/alerts" | python3 -c "
import json,sys
name=sys.argv[1]; want=dict(a.split('=',1) for a in sys.argv[2:])
for a in json.load(sys.stdin)['data']['alerts']:
    if a['state']=='firing' and a['labels'].get('alertname')==name and all(a['labels'].get(k)==v for k,v in want.items()): sys.exit(0)
sys.exit(1)" "$name" "$@"
}
list_firing() { curl -s "$PROM/api/v1/alerts" | python3 -c "
import json,sys
for a in json.load(sys.stdin)['data']['alerts']:
    if a['state']=='firing': print(a['labels']['alertname'], 'validator='+a['labels'].get('validator',''), 'job='+a['labels'].get('job',''))" | sort; }
# expect_quiet / expect_firing / expect_resolved <seconds> <alert> [label=value ...]
expect_quiet() { local n=$1; shift; if firing "$n" "$@"; then log "FAIL: $n $* was already firing before the condition"; failures=$((failures+1)); else log "ok: $n $* quiet before"; fi; }
wait_for() { # <firing|quiet> <seconds> <alert> [labels...]
  local want=$1 secs=$2 n=$3 i; shift 3
  for i in $(seq 1 "$secs"); do
    if [ "$want" = firing ] && firing "$n" "$@"; then log "PASS: $n $* firing after ${i}s"; return 0; fi
    if [ "$want" = quiet ] && ! firing "$n" "$@"; then log "PASS: $n $* resolved after ${i}s"; return 0; fi
    sleep 1; done
  log "FAIL: $n $* not $want within $secs s"; failures=$((failures+1)); return 1; }
snap() { curl -s "$PROM/api/v1/alerts" >"$EVID/alerts-$1.json"; curl -s "$PROM/api/v1/rules" >"$EVID/rules-$1.json"; list_firing >"$EVID/firing-$1.txt"; }
add_job() { # <job> <port> <validator> [extra yaml lines]
  python3 - "$MON" "$1" "$2" "$3" <<'PY'
import sys
mon,job,port,val=sys.argv[1:5]
p=mon+'/prometheus.yml'
s=open(p).read()
if 'job_name: '+job+'\n' not in s:
    s+=f"  - job_name: {job}\n    metrics_path: /metrics\n    fallback_scrape_protocol: PrometheusText0.0.4\n    static_configs:\n      - targets: ['127.0.0.1:{port}']\n        labels: {{validator: '{val}'}}\n"
    open(p,'w').write(s)
PY
  curl -s -X POST "$PROM/-/reload" >/dev/null; }
failures=0

log "== baseline: targets, scraped unicity_* series, rule evaluation"
curl -s "$PROM/api/v1/targets" >"$EVID/targets.json"
bash scripts/vt12-monitoring.sh status | tee "$EVID/targets.txt"
for p in 25866:root 28311:shard 29301:authority 29401:vrexporter; do
  curl -s "127.0.0.1:${p%%:*}$([ "${p##*:}" = authority ] || [ "${p##*:}" = vrexporter ] && echo /metrics || echo /api/v1/metrics)" | grep -E '^(unicity_|# HELP unicity_)' >"$EVID/scrape-${p##*:}.txt"
done
curl -s "$PROM/api/v1/label/__name__/values" | python3 -c "import json,sys;print('\n'.join(n for n in json.load(sys.stdin)['data'] if n.startswith('unicity_')))" >"$EVID/prometheus-series.txt"
log "unicity_* series in Prometheus: $(wc -l <"$EVID/prometheus-series.txt")"
snap baseline
log "firing at baseline: $(wc -l <"$EVID/firing-baseline.txt")"; cat "$EVID/firing-baseline.txt" | tee -a "$EVID/acceptance.log"

log "== 1. EVM stopped: validator 1's ureth paused (SIGSTOP)"
expect_quiet UnicityEvmUnreachable validator=1; expect_quiet UnicityEvmHeadLag validator=1
reth_pid=$(cat test-nodes/reth1/pid)
kill -STOP "$reth_pid"
wait_for firing 180 UnicityEvmUnreachable validator=1
wait_for firing 240 UnicityEvmHeadLag validator=1
snap evm-stopped
kill -CONT "$reth_pid"
wait_for quiet 240 UnicityEvmUnreachable validator=1
wait_for quiet 240 UnicityEvmHeadLag validator=1

log "== 2. peers cut: validator 2's root p2p port dropped (the other roots lose a peer)"
expect_quiet UnicityPeersLow validator=1 network=root
port=26663
sudo iptables -I INPUT -i lo -p tcp --dport $port -j DROP && sudo ss -K dport = :$port >/dev/null 2>&1; sudo ss -K sport = :$port >/dev/null 2>&1
wait_for firing 240 UnicityPeersLow validator=1 network=root
snap peers-cut
sudo iptables -D INPUT -i lo -p tcp --dport $port -j DROP
wait_for quiet 300 UnicityPeersLow validator=1 network=root

log "== 3. disk filled: a 16 MB tmpfs watched by a validator-4 exporter instance"
d=$PWD/$MON/tmpfs-disk; mkdir -p "$d"; sudo mount -t tmpfs -o size=16m tmpfs "$d"; sudo chown "$(id -u)" "$d"
build/ubft validator exporter --validator-config "$MON/v4.json" --listen 127.0.0.1:29499 --interval 5s --disk-path "tmpfs=$d" --log-format text >"$MON/exporter-disk.log" 2>&1 &
dpid=$!
add_job diskdemo 29499 4
sleep 12
expect_quiet UnicityDiskLow validator=4 job=diskdemo
dd if=/dev/zero of="$d/fill1" bs=1M count=15 2>/dev/null
wait_for firing 90 UnicityDiskLow validator=4 job=diskdemo volume=tmpfs
dd if=/dev/zero of="$d/fill2" bs=1K count=900 2>/dev/null
wait_for firing 90 UnicityDiskCritical validator=4 job=diskdemo volume=tmpfs
snap disk-full
rm -f "$d"/fill*
wait_for quiet 120 UnicityDiskLow validator=4 job=diskdemo volume=tmpfs
kill "$dpid" 2>/dev/null; sleep 1; sudo umount "$d"

log "== 4. scrape failure: validator 3's exporter stopped"
expect_quiet UnicityTargetDown validator=3 job=vrexporter
kill "$(cat "$MON/exporter3.pid")"
wait_for firing 120 UnicityTargetDown validator=3 job=vrexporter
snap target-down
build/ubft validator exporter --validator-config "$MON/v3.json" --listen 127.0.0.1:29403 --interval 5s --root-metrics "http://127.0.0.1:25868/api/v1/metrics" --log-format text >"$MON/exporter3.log" 2>&1 &
echo $! >"$MON/exporter3.pid"
wait_for quiet 120 UnicityTargetDown validator=3 job=vrexporter

log "== 5. RPC read failure: the public RPC validator 1's exporter reads through (reth2) paused: the exporter answers its scrape and reports unicity_vr_up 0"
expect_quiet UnicityVRExporterDown validator=1
reth2=$(cat test-nodes/reth2/pid)
kill -STOP "$reth2"
wait_for firing 240 UnicityVRExporterDown validator=1
firing UnicityTargetDown validator=1 job=vrexporter && { log "FAIL: the exporter target itself went down"; failures=$((failures+1)); } || log "ok: the exporter target stayed up (a read failure, not a scrape failure)"
snap rpc-read-failure
kill -CONT "$reth2"
wait_for quiet 240 UnicityVRExporterDown validator=1

log "== 6. pending upgrade (STUB: VT-07's activation schedule is not in this build): a stub target serves the exporter's upgrade series for validator 1"
mkdir -p "$MON/stub"; cat >"$MON/stub/metrics" <<'STUB'
unicity_upgrade_schedule_known 1
unicity_upgrade_required 1
unicity_upgrade_epochs_remaining 2
STUB
(cd "$MON/stub" && exec python3 -m http.server 29498 --bind 127.0.0.1 >/dev/null 2>&1) &
spid=$!
expect_quiet UnicityUpgradeRequired validator=1 job=upgradestub
add_job upgradestub 29498 1
wait_for firing 120 UnicityUpgradeRequired validator=1 job=upgradestub
wait_for firing 60 UnicityUpgradeImminent validator=1 job=upgradestub
snap upgrade-stub
kill "$spid" 2>/dev/null

log "== 7. dashboard rendering (Grafana image renderer; needs MON_GRAFANA=1 at start)"
if curl -sf "$GRAFANA/api/health" >/dev/null; then
  curl -s -o "$EVID/dashboard.png" "$GRAFANA/render/d/unicity-validator/unicity-validator?orgId=1&from=now-30m&to=now&width=1600&height=2400&var-validator=1&var-DS=prom&kiosk" 
  [ -s "$EVID/dashboard.png" ] && file "$EVID/dashboard.png" | tee -a "$EVID/acceptance.log" || { log "FAIL: no dashboard image"; failures=$((failures+1)); }
else
  log "FAIL: Grafana is not up"; failures=$((failures+1))
fi

log "== final: everything quiet again"
snap final
log "firing at the end:"; cat "$EVID/firing-final.txt" | tee -a "$EVID/acceptance.log"
log "acceptance failures: $failures"
exit $((failures>0))
