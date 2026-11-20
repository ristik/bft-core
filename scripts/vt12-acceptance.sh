#!/usr/bin/env bash
# VT-12 live acceptance (bft-core#1152) on a running generation with the monitoring pack up (scripts/vt12-monitoring.sh start).
# Induces conditions on the lane's own processes and shows each alert firing for the validator under observation and resolving: a paused ureth (EVM
# stopped), a cut root peer link, a tmpfs filled to the brim, a stopped exporter (scrape failure), a paused public RPC (the exporter's read failure)
# and a pending upgrade (use VT12_VT07_PORT to scrape VT-07 on this host, otherwise use a stub); then renders the dashboard. Every assertion matches the alert by name AND label (validator, job) and checks that it
# was quiet before the condition was induced. Evidence goes to $EVID (default ~/evidence/vt12/live).
# Needs sudo for iptables and mount. Only this lane's processes and ports are touched; every induced condition is undone.
set -euo pipefail
VT12_SOURCE_ONLY=1 source scripts/vt12-monitoring.sh ""
EVID=${EVID:-$HOME/evidence/vt12/live}
PROM=http://127.0.0.1:${MON_PROM_PORT:-19090}
GRAFANA=http://127.0.0.1:${MON_GRAFANA_PORT:-13000}
MON=${MON_DIR:-test-nodes/monitoring}
api() { curl -fsS --max-time 10 "$PROM/$1"; }
log() { echo "$(date -u +%T) $*" | tee -a "$EVID/acceptance.log"; }
# firing <alert> [label=value ...]: succeeds when a firing alert of that name carries every given label
firing() {
  local name=$1; shift
  local alerts
  alerts=$(api api/v1/alerts) || return 2
  python3 -c "
import json,sys
name=sys.argv[1]; want=dict(a.split('=',1) for a in sys.argv[2:])
try:
    payload=json.load(sys.stdin)
    alerts=payload['data']['alerts']
    if payload['status']!='success' or not isinstance(alerts,list):
        sys.exit(2)
    for alert in alerts:
        labels=alert['labels']
        if alert['state'] not in ('inactive','pending','firing') or not isinstance(labels,dict):
            sys.exit(2)
        if not isinstance(labels['alertname'],str) or any(not isinstance(v,str) for v in labels.values()):
            sys.exit(2)
    for alert in alerts:
        labels=alert['labels']
        if alert['state']=='firing' and labels['alertname']==name and all(labels.get(k)==v for k,v in want.items()):
            sys.exit(0)
except (ValueError, KeyError, TypeError, AttributeError):
    sys.exit(2)
sys.exit(1)" "$name" "$@" <<<"$alerts"
}
list_firing() { api api/v1/alerts | python3 -c "
import json,sys
for a in json.load(sys.stdin)['data']['alerts']:
    if a['state']=='firing': print(a['labels']['alertname'], 'validator='+a['labels'].get('validator',''), 'job='+a['labels'].get('job',''))" | sort; }
expect_quiet() {
  local rc=0
  firing "$@" || rc=$?
  if [ "$rc" = 1 ]; then log "ok: $* quiet before"; return; fi
  log "FAIL: $* fired before the fault, or Prometheus was unavailable"
  return 1
}
wait_for() {
  local want=$1 secs=$2 rc end=$((SECONDS + $2))
  shift 2
  while [ "$SECONDS" -lt "$end" ]; do
    rc=0; firing "$@" || rc=$?
    if { [ "$want" = firing ] && [ "$rc" = 0 ]; } || { [ "$want" = quiet ] && [ "$rc" = 1 ]; }; then
      log "PASS: $* $want"
      return 0
    fi
    sleep 1
  done
  log "FAIL: $* not $want within $secs s"
  snap timeout
  return 1
}
snap() {
  api api/v1/alerts >"$EVID/alerts-$1.json"
  api api/v1/rules >"$EVID/rules-$1.json"
  list_firing >"$EVID/firing-$1.txt"
}
add_job() { # <job> <port> <validator> [metrics path]
  python3 - "$MON" "$1" "$2" "$3" "${4:-/metrics}" <<'PY'
import sys
mon,job,port,val,path=sys.argv[1:]
if not port.isascii() or not port.isdecimal() or not 0 < int(port) < 65536:
    sys.exit("Invalid scrape port")
p=mon+'/prometheus.yml'
s=open(p).read()
if 'job_name: '+job+'\n' not in s:
    s+=f"  - job_name: {job}\n    metrics_path: {path}\n    fallback_scrape_protocol: PrometheusText0.0.4\n    static_configs:\n      - targets: ['127.0.0.1:{port}']\n        labels: {{validator: '{val}'}}\n"
    if job == 'vt07-live':
        s+="    metric_relabel_configs:\n"
        s+="      - source_labels: [__name__]\n        regex: ab_unicity_upgrade_required\n        action: keep\n"
    open(p,'w').write(s)
PY
  curl -fsS --max-time 10 -X POST "$PROM/-/reload" >/dev/null
}
pause_reth() {
  local i=$1
  local pid
  pid=$(cat "test-nodes/reth$i/pid")
  owned_pid "$pid" "reth.* node.*test-nodes/reth$i/" || return 1
  kill -STOP "$pid"
  paused_pid=$pid
}
resume_reth() {
  if [ -n "$paused_pid" ] && owned_pid "$paused_pid" 'reth.* node'; then
    kill -CONT "$paused_pid"
  fi
  paused_pid=
}
unblock_peers() {
  if [ -n "$blocked" ]; then
    sudo -n iptables -D INPUT "${peer_rule[@]}"
    blocked=
  fi
}
restore_scrapes() {
  cat "$work/prometheus.yml" >"$MON/prometheus.yml"
  curl -fsS --max-time 10 -X POST "$PROM/-/reload" >/dev/null
}
restart_stopped_exporter() {
  [ -n "$stopped_exporter_pid" ] || return 0
  local attempt pattern='ubft validator exporter.*v3.json'
  # The trap may run before the original process finishes shutting down.
  if owned_pid "$stopped_exporter_pid" "$pattern"; then
    kill "$stopped_exporter_pid" 2>/dev/null || true
    for attempt in {1..20}; do
      owned_pid "$stopped_exporter_pid" "$pattern" || break
      sleep 0.25
    done
    if owned_pid "$stopped_exporter_pid" "$pattern"; then
      echo "Validator 3 exporter did not stop" >&2
      return 1
    fi
  fi
  start_exporter 3 || return 1
  stopped_exporter_pid=
}
cleanup() {
  trap '' INT TERM HUP
  set +e
  restart_stopped_exporter || echo "Failed to restore validator 3 exporter" >&2
  resume_reth
  unblock_peers
  [ -z "$dpid" ] || kill "$dpid" 2>/dev/null
  [ -z "$spid" ] || kill "$spid" 2>/dev/null
  [ -z "$disk_mount" ] || sudo -n umount "$disk_mount"
  restore_scrapes
  rm -f "$work/prometheus.yml" "$work/stub/metrics"
  rmdir "$work/tmpfs-disk" "$work/stub" 2>/dev/null || true
  rmdir "$work"
}
check_upgrade() {
  log "== pending upgrade: scrape the VT-07 metric"
  if [ -n "${VT12_VT07_PORT:-}" ]; then
    job=vt07-live
    upgrade_validator=${VT12_VT07_VALIDATOR:-4}
    expect_quiet UnicityUpgradePending "validator=$upgrade_validator" "job=$job"
    add_job "$job" "$VT12_VT07_PORT" "$upgrade_validator" /api/v1/metrics
    curl -fsS --max-time 10 "127.0.0.1:$VT12_VT07_PORT/api/v1/metrics" |
      grep '^ab_unicity_upgrade_required' >"$EVID/scrape-vt07.txt"
  else
    job=upgradestub
    upgrade_validator=1
    mkdir "$work/stub"
    cat >"$work/stub/metrics" <<'STUB'
ab_unicity_upgrade_required{state="pending",rule="vt12-test",epoch="3"} 1
unicity_upgrade_schedule_known 1
unicity_upgrade_required 1
unicity_upgrade_epochs_remaining 2
STUB
    (cd "$work/stub" && exec python3 -m http.server 29498 --bind 127.0.0.1) >"$MON/upgrade-stub.log" 2>&1 &
    spid=$!
    expect_quiet UnicityUpgradePending "validator=$upgrade_validator" "job=$job"
    add_job "$job" 29498 "$upgrade_validator"
    wait_for firing 60 UnicityUpgradeRequired "validator=$upgrade_validator" "job=$job"
    wait_for firing 60 UnicityUpgradeImminent "validator=$upgrade_validator" "job=$job"
  fi
  wait_for firing 60 UnicityUpgradePending "validator=$upgrade_validator" "job=$job" state=pending
  snap "$job"
  if [ -n "$spid" ]; then
    kill "$spid"
    wait "$spid" || true
    spid=
  fi
  restore_scrapes
}

check_evm() {
  log "== EVM stopped: validator 1's ureth paused (SIGSTOP)"
  expect_quiet UnicityEvmUnreachable validator=1; expect_quiet UnicityEvmHeadLag validator=1 job=vrexporter
  pause_reth 1
  wait_for firing 180 UnicityEvmUnreachable validator=1
  wait_for firing 240 UnicityEvmHeadLag validator=1 job=vrexporter
  snap evm-stopped
  curl -fsSG --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=unicity_evm_head_lag_blocks{validator="1",job="vrexporter"}' >"$EVID/query-evm-lag.json"
  resume_reth
  wait_for quiet 240 UnicityEvmUnreachable validator=1
  wait_for quiet 240 UnicityEvmHeadLag validator=1 job=vrexporter
}

check_peers() {
  log "== peers cut: validator 2's root p2p port dropped (the other roots lose a peer)"
  expect_quiet UnicityPeersLow validator=1 job=root network=root
  sudo -n iptables -I INPUT "${peer_rule[@]}"
  blocked=1
  sudo -n ss -K "( sport = :$p2p_port or dport = :$p2p_port )" >/dev/null
  wait_for firing 240 UnicityPeersLow validator=1 job=root network=root
  snap peers-cut
  unblock_peers
  wait_for quiet 300 UnicityPeersLow validator=1 job=root network=root
}

check_disk() {
  log "== disk filled: a 16 MB tmpfs watched by a validator-4 exporter instance"
  d=$work/tmpfs-disk
  mkdir "$d"
  sudo -n mount -t tmpfs -o size=16m tmpfs "$d"
  disk_mount=$d
  sudo -n chown "$(id -u)" "$d"
  build/ubft validator exporter --validator-config "$MON/v4.json" --listen 127.0.0.1:29499 --interval 5s --disk-path "tmpfs=$d" --log-format text >"$MON/exporter-disk.log" 2>&1 &
  dpid=$!
  add_job diskdemo 29499 4
  sleep 12
  expect_quiet UnicityDiskLow validator=4 job=diskdemo volume=tmpfs
  expect_quiet UnicityDiskCritical validator=4 job=diskdemo volume=tmpfs
  dd if=/dev/zero of="$d/fill1" bs=1M count=15 2>/dev/null
  wait_for firing 160 UnicityDiskLow validator=4 job=diskdemo volume=tmpfs
  dd if=/dev/zero of="$d/fill2" bs=1K count=900 2>/dev/null
  wait_for firing 90 UnicityDiskCritical validator=4 job=diskdemo volume=tmpfs
  snap disk-full
  rm -f "$d"/fill*
  wait_for quiet 120 UnicityDiskLow validator=4 job=diskdemo volume=tmpfs
  wait_for quiet 120 UnicityDiskCritical validator=4 job=diskdemo volume=tmpfs
  kill "$dpid"
  wait "$dpid" || true
  dpid=
  sudo -n umount "$d"
  disk_mount=
  restore_scrapes
}

check_scrape() {
  log "== scrape failure: validator 3's exporter stopped"
  expect_quiet UnicityTargetDown validator=3 job=vrexporter
  local exporter_pid
  exporter_pid=$(cat "$MON/exporter3.pid")
  owned_pid "$exporter_pid" 'ubft validator exporter.*v3.json'
  stopped_exporter_pid=$exporter_pid
  kill "$exporter_pid"
  wait_for firing 120 UnicityTargetDown validator=3 job=vrexporter
  snap target-down
  restart_stopped_exporter
  wait_for quiet 120 UnicityTargetDown validator=3 job=vrexporter
}

check_rpc() {
  log "== RPC read failure: the public RPC validator 1's exporter reads through (reth2) paused: the exporter answers its scrape and reports unicity_vr_up 0"
  expect_quiet UnicityVRExporterDown validator=1 job=vrexporter
  pause_reth 2
  wait_for firing 240 UnicityVRExporterDown validator=1 job=vrexporter
  expect_quiet UnicityTargetDown validator=1 job=vrexporter
  snap rpc-read-failure
  resume_reth
  wait_for quiet 240 UnicityVRExporterDown validator=1 job=vrexporter
}

check_dashboard() {
  restore_scrapes
  log "== dashboard rendering (Grafana image renderer; needs MON_GRAFANA=1 at start)"
  curl -fsS --max-time 90 -o "$EVID/dashboard.png" "$GRAFANA/render/d/unicity-validator/unicity-validator?orgId=1&from=now-30m&to=now&width=1600&height=2400&var-validator=1&var-DS=prom&kiosk"
  python3 - "$EVID/dashboard.png" <<'PYPNG'
import sys
with open(sys.argv[1], 'rb') as png:
    if png.read(8) != b'\x89PNG\r\n\x1a\n':
        sys.exit('Grafana did not return a PNG')
PYPNG
  log "PASS: Grafana returned a dashboard PNG"
}

# Allow the regression tests to load the checks without touching a live lane.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then return 0; fi

if [ "$#" -eq 0 ]; then
  set -- upgrade evm peers disk scrape rpc dashboard
fi
for scenario in "$@"; do
  case "$scenario" in
    upgrade|evm|peers|disk|scrape|rpc|dashboard) ;;
    *) echo "Unknown acceptance scenario: $scenario" >&2; exit 2 ;;
  esac
done

mkdir -p "$EVID"
paused_pid= dpid= spid= disk_mount= blocked= stopped_exporter_pid=
p2p_port=$(lane_port 26663)
peer_rule=(-i lo -p tcp -m multiport --ports "$p2p_port" -m comment --comment "vt12-$BASHPID" -j DROP)
sudo -n true
work=$(mktemp -d)
test -r "$MON/prometheus.yml"
cp "$MON/prometheus.yml" "$work/prometheus.yml"
trap cleanup EXIT
trap 'exit 143' INT TERM HUP

log "== baseline: targets, scraped unicity_* series, rule evaluation"
api api/v1/targets >"$EVID/targets.json"
bash scripts/vt12-monitoring.sh status | tee "$EVID/targets.txt"
for p in "$(lane_port 25866):root" "$(lane_port 28311):shard" 29301:authority 29401:vrexporter; do
  curl -fsS --max-time 10 "127.0.0.1:${p%%:*}$([ "${p##*:}" = authority ] || [ "${p##*:}" = vrexporter ] && echo /metrics || echo /api/v1/metrics)" | grep -E '^(unicity_|# HELP unicity_)' >"$EVID/scrape-${p##*:}.txt"
done
api api/v1/label/__name__/values | python3 -c "import json,sys;print('\n'.join(n for n in json.load(sys.stdin)['data'] if n.startswith('unicity_')))" >"$EVID/prometheus-series.txt"
log "unicity_* series in Prometheus: $(wc -l <"$EVID/prometheus-series.txt")"
snap baseline
log "firing at baseline: $(wc -l <"$EVID/firing-baseline.txt")"; cat "$EVID/firing-baseline.txt" | tee -a "$EVID/acceptance.log"

for scenario in "$@"; do "check_$scenario"; done
snap final
log "Acceptance passed"
