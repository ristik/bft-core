#!/usr/bin/env bash
# VT-12 live acceptance (bft-core#1152) on a running generation with the monitoring pack up (scripts/vt12-monitoring.sh start).
# Induces conditions on the lane's own processes and shows each alert firing in Prometheus and resolving: a paused ureth (EVM stopped), a cut root peer
# link, a tmpfs filled to the brim, a stopped exporter and a stubbed pending upgrade. Evidence goes to $EVID (default ~/evidence/vt12/live).
# Needs sudo for iptables and mount. Only this lane's processes and ports are touched; every induced condition is undone.
set -uo pipefail
EVID=${EVID:-$HOME/evidence/vt12/live}; mkdir -p "$EVID"
PROM=http://127.0.0.1:${MON_PROM_PORT:-19090}
MON=${MON_DIR:-test-nodes/monitoring}
log() { echo "$(date -u +%T) $*" | tee -a "$EVID/acceptance.log"; }
firing() { curl -s "$PROM/api/v1/alerts" | python3 -c "
import json,sys
for a in json.load(sys.stdin)['data']['alerts']:
    if a['state']=='firing': print(a['labels']['alertname'], a['labels'].get('validator',''), a['labels'].get('job',''), a['labels'].get('network',''), a['labels'].get('volume',''))"; }
is_firing() { firing | awk -v n="$1" '$1==n' | grep -q .; }
wait_state() { # <alert> <firing|quiet> <seconds>
  local i; for i in $(seq 1 "$3"); do
    if [ "$2" = firing ] && is_firing "$1"; then log "PASS: $1 firing after ${i}s"; return 0; fi
    if [ "$2" = quiet ] && ! is_firing "$1"; then log "PASS: $1 resolved after ${i}s"; return 0; fi
    sleep 1; done
  log "FAIL: $1 not $2 within $3 s"; failures=$((failures+1)); return 1; }
snap() { curl -s "$PROM/api/v1/alerts" >"$EVID/alerts-$1.json"; curl -s "$PROM/api/v1/rules" >"$EVID/rules-$1.json"; firing | sort >"$EVID/firing-$1.txt"; }
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
reth_pid=$(cat test-nodes/reth1/pid)
kill -STOP "$reth_pid"
wait_state UnicityEvmUnreachable firing 180
wait_state UnicityEvmHeadLag firing 240
snap evm-stopped
kill -CONT "$reth_pid"
wait_state UnicityEvmUnreachable quiet 240
wait_state UnicityEvmHeadLag quiet 240

log "== 2. peers cut: validator 2's root p2p port dropped"
port=26663
sudo iptables -I INPUT -i lo -p tcp --dport $port -j DROP && sudo ss -K dport = :$port >/dev/null 2>&1; sudo ss -K sport = :$port >/dev/null 2>&1
wait_state UnicityPeersLow firing 240
snap peers-cut
sudo iptables -D INPUT -i lo -p tcp --dport $port -j DROP
wait_state UnicityPeersLow quiet 300

log "== 3. disk filled: a 16 MB tmpfs"
d=$PWD/$MON/tmpfs-disk; mkdir -p "$d"; sudo mount -t tmpfs -o size=16m tmpfs "$d"; sudo chown "$(id -u)" "$d"
build/ubft validator exporter --validator-config "$MON/v4.json" --listen 127.0.0.1:29499 --interval 5s --disk-path "tmpfs=$d" --log-format text >"$MON/exporter-disk.log" 2>&1 &
dpid=$!
echo "$dpid" >"$MON/exporter-disk.pid"
curl -s -X POST "$PROM/-/reload" >/dev/null
python3 - "$MON" <<'PY'
import sys
p=sys.argv[1]+'/prometheus.yml'
s=open(p).read()
if 'diskdemo' not in s:
    s+="  - job_name: diskdemo\n    metrics_path: /metrics\n    static_configs:\n      - targets: ['127.0.0.1:29499']\n        labels: {validator: '4'}\n"
    open(p,'w').write(s)
PY
curl -s -X POST "$PROM/-/reload" >/dev/null
sleep 12
dd if=/dev/zero of="$d/fill1" bs=1M count=15 2>/dev/null
wait_state UnicityDiskLow firing 90
dd if=/dev/zero of="$d/fill2" bs=1K count=800 2>/dev/null || true
wait_state UnicityDiskCritical firing 90
snap disk-full
rm -f "$d"/fill*
wait_state UnicityDiskLow quiet 120
kill "$dpid" 2>/dev/null; sleep 1; sudo umount "$d"

log "== 4. target down: validator 3's exporter stopped"
kill "$(cat "$MON/exporter3.pid")"
wait_state UnicityTargetDown firing 120
wait_state UnicityVRExporterDown firing 1 || true
snap target-down
build/ubft validator exporter --validator-config "$MON/v3.json" --listen 127.0.0.1:29403 --interval 5s --root-metrics "http://127.0.0.1:25868/api/v1/metrics" --log-format text >"$MON/exporter3.log" 2>&1 &
echo $! >"$MON/exporter3.pid"
wait_state UnicityTargetDown quiet 120

log "== 5. pending upgrade (STUB: VT-07's activation schedule is not in this build): a stub endpoint serves unicity_upgrade_required"
mkdir -p "$MON/stub"; cat >"$MON/stub/metrics" <<'STUB'
unicity_upgrade_required 1
unicity_upgrade_activation_epoch 9
unicity_root_epoch 8
unicity_build_info{component="stub"} 1
STUB
(cd "$MON/stub" && exec python3 -m http.server 29498 --bind 127.0.0.1 >/dev/null 2>&1) &
spid=$!
python3 - "$MON" <<'PY'
import sys
p=sys.argv[1]+'/prometheus.yml'
s=open(p).read()
if 'upgradestub' not in s:
    s+="  - job_name: upgradestub\n    metrics_path: /metrics\n    fallback_scrape_protocol: PrometheusText0.0.4\n    static_configs:\n      - targets: ['127.0.0.1:29498']\n        labels: {validator: '1'}\n"
    open(p,'w').write(s)
PY
cp "$MON/stub/metrics" "$MON/stub/metrics.txt"
curl -s -X POST "$PROM/-/reload" >/dev/null
wait_state UnicityUpgradeRequired firing 120
wait_state UnicityUpgradeImminent firing 60
snap upgrade-stub
kill "$spid" 2>/dev/null

log "== final: everything quiet again"
snap final
log "acceptance failures: $failures"
exit $((failures>0))
