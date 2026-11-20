#!/usr/bin/env bash
# VT-12 (bft-core#1152): the monitoring pack on a running development generation (a paired-devnet lane started with MONITORING=1).
#
#   scripts/vt12-monitoring.sh start    VR exporters (one per validator), Prometheus with the alert pack, optionally Grafana
#   scripts/vt12-monitoring.sh stop
#   scripts/vt12-monitoring.sh status
#
# Run it from the lane's checkout (the directory holding test-nodes/ and build/ubft). Run on lane slot 0. Ports follow the lane's fixed ports (root RPC 25866+i-1, shard RPC
# 28311+i-1, authority metrics 29301+i-1, reth 18545+i-1); the exporters take 29401+i-1, Prometheus MON_PROM_PORT (default 19090), Grafana MON_GRAFANA_PORT
# (default 13000, only with MON_GRAFANA=1 and an image the host can pull). Only processes this script started (pidfiles under test-nodes/monitoring) are
# stopped. Docker runs Prometheus with host networking, so it scrapes the loopback listeners directly.
set -euo pipefail
source ./helper.sh
if [ "${LANE_SLOT:-0}" != 0 ]; then
  echo "VT-12 monitoring currently requires a slot 0 lane" >&2
  exit 2
fi
MON=${MON_DIR:-test-nodes/monitoring}
PROM_PORT=${MON_PROM_PORT:-19090}
GRAFANA_PORT=${MON_GRAFANA_PORT:-13000}
PROM_IMAGE=${MON_PROM_IMAGE:-prom/prometheus:v3.2.1@sha256:6927e0919a144aa7616fd0137d4816816d42f6b816de3af269ab065250859a62}
GRAFANA_IMAGE=${MON_GRAFANA_IMAGE:-grafana/grafana:11.4.0}
RENDERER_IMAGE=${MON_RENDERER_IMAGE:-grafana/grafana-image-renderer:3.11.6}
NAME=${MON_NAME:-vt12-$(basename "$PWD" | tr -c 'a-zA-Z0-9\n' '-')}
RULES=${MON_RULES:-deploy/testnet/monitoring/validator-alerts.yml}
DASH=${MON_DASH:-deploy/testnet/monitoring/grafana-validator.json}
VR=${MON_VR:-0xff00000000000000000000000000000000000003}

validators() { ls -d test-nodes/root[0-9]* 2>/dev/null | sed 's#.*/root##' | sort -n; }

validator_id() {
  python3 - "${VR_DIR:-test-nodes/vr}" "$1" <<'PYID'
import base64
import json
import sys

vr, node = sys.argv[1:]
with open(f"test-nodes/root{node}/node-info.json") as source:
    root = json.load(source)["nodeId"]
with open(f"{vr}/genesis-identities.json") as source:
    identities = json.load(source)
matches = [identity for identity in identities if identity["rootNodeId"] == root]
if len(matches) != 1:
    sys.exit(f"Root {node} has no unique identity in this lane's genesis")
identity = int.from_bytes(base64.b64decode(matches[0]["stakingId"], validate=True), "big")
if not 0 < identity < (1 << 64):
    sys.exit(f"Root {node} has an invalid validator ID")
print(identity)
PYID
}

start_exporter() {
  local i=$1 custody=
  local -a extra=()
  if [ -r "${VR_DIR:-test-nodes/vr}/contracts/deployment.json" ]; then
    custody=$(jq -r '.custody // empty' "${VR_DIR:-test-nodes/vr}/contracts/deployment.json")
    [ -z "$custody" ] || extra+=(--custody "$custody")
  fi
  nohup build/ubft validator exporter --validator-config "$MON/v$i.json" --listen "127.0.0.1:$((29400 + i))" --interval 5s \
    --root-metrics "http://127.0.0.1:$(lane_port "$((25865 + i))")/api/v1/metrics" --disk-path "ureth=test-nodes/reth$i" "${extra[@]}" \
    --log-format text --log-level info >"$MON/exporter$i.log" 2>&1 </dev/null &
  echo $! >"$MON/exporter$i.pid"
}

start_exporters() {
  local i pub id local_rpc public_rpc
  local -a nodes
  read -r -a nodes <<<"$(validators | paste -sd' ' -)"
  # Set up and validate every identity before starting any exporter.
  for i in "${!nodes[@]}"; do
    pub=${nodes[$(((i + 1) % ${#nodes[@]}))]}
    local_rpc=$(lane_port "$((18544 + nodes[i]))")
    public_rpc=$(lane_port "$((18544 + pub))")
    id=$(validator_id "${nodes[i]}")
    cat >"$MON/v${nodes[i]}.json" <<JSON
{"format":"unicity.validator.config.v1","rpc":"http://127.0.0.1:$public_rpc","localRpc":"http://127.0.0.1:$local_rpc","registry":"$VR","rootKeys":"","evmKeys":"","urethKey":"","jwt":"","operatorKey":"","payee":"0x0000000000000000000000000000000000000000","id":$id}
JSON
  done
  for i in "${nodes[@]}"; do start_exporter "$i"; done
}

scrapes() {
  local job port base
  for spec in "root:$(lane_port 25866):/api/v1/metrics" "shard:$(lane_port 28311):/api/v1/metrics" "authority:29301:/metrics" "vrexporter:29401:/metrics"; do
    IFS=: read -r job base path <<<"$spec"
    echo "  - job_name: $job"
    echo "    metrics_path: $path"
    echo "    static_configs:"
    for i in $(validators); do
      echo "      - targets: ['127.0.0.1:$((base + i - 1))']"
      echo "        labels: {validator: '$i'}"
    done
  done
}

render_prometheus() {
  mkdir -p "$MON/prom"; chmod 777 "$MON/prom"
  cp "$RULES" "$MON/validator-alerts.yml"
  python3 - "$MON" <<'PY'
import sys,subprocess,os
mon=sys.argv[1]
tmpl=open('deploy/testnet/monitoring/prometheus-validator.yml.tmpl').read()
scr=subprocess.run(['bash','-c','source scripts/vt12-monitoring.sh >/dev/null 2>&1; scrapes'],capture_output=True,text=True,check=True,env=dict(os.environ,VT12_SOURCE_ONLY='1')).stdout
open(mon+'/prometheus.yml','w').write(tmpl.replace('@SCRAPES@',scr))
PY
}

case "${1:-}" in
  start)
    mkdir -p "$MON"
    start_exporters
    VT12_SOURCE_ONLY=1 render_prometheus
    docker rm -f "$NAME-prom" >/dev/null 2>&1 || true
    docker run -d --name "$NAME-prom" --network host --user 65534 \
      -v "$PWD/$MON/prometheus.yml:/etc/prometheus/prometheus.yml:ro" -v "$PWD/$MON/validator-alerts.yml:/etc/prometheus/validator-alerts.yml:ro" \
      -v "$PWD/$MON/prom:/prometheus" "$PROM_IMAGE" --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus \
      --web.listen-address="127.0.0.1:$PROM_PORT" --web.enable-lifecycle >/dev/null
    if [ "${MON_GRAFANA:-0}" = 1 ]; then
      mkdir -p "$MON/grafana/provisioning/datasources" "$MON/grafana/provisioning/dashboards" "$MON/grafana/dash"; chmod -R 777 "$MON/grafana"
      cp "$DASH" "$MON/grafana/dash/"
      printf 'apiVersion: 1\ndatasources:\n  - name: prometheus\n    uid: prom\n    type: prometheus\n    url: http://127.0.0.1:%s\n    isDefault: true\n' "$PROM_PORT" >"$MON/grafana/provisioning/datasources/p.yml"
      printf 'apiVersion: 1\nproviders:\n  - name: unicity\n    type: file\n    options: {path: /var/lib/grafana/dash}\n' >"$MON/grafana/provisioning/dashboards/d.yml"
      docker rm -f "$NAME-grafana" "$NAME-renderer" >/dev/null 2>&1 || true
      # the image renderer lets `curl .../render/d/unicity-validator` produce a PNG of the dashboard (the screenshot evidence)
      docker run -d --name "$NAME-renderer" --network host -e HTTP_HOST=127.0.0.1 -e HTTP_PORT="${MON_RENDERER_PORT:-18081}" "$RENDERER_IMAGE" >/dev/null
      docker run -d --name "$NAME-grafana" --network host --user 65534 -e GF_SERVER_HTTP_ADDR=127.0.0.1 -e GF_SERVER_HTTP_PORT="$GRAFANA_PORT" \
        -e GF_RENDERING_SERVER_URL="http://127.0.0.1:${MON_RENDERER_PORT:-18081}/render" -e GF_RENDERING_CALLBACK_URL="http://127.0.0.1:$GRAFANA_PORT/" \
        -e GF_AUTH_ANONYMOUS_ENABLED=true -e GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer \
        -v "$PWD/$MON/grafana/provisioning:/etc/grafana/provisioning:ro" -v "$PWD/$MON/grafana/dash:/var/lib/grafana/dash:ro" "$GRAFANA_IMAGE" >/dev/null
    fi
    echo "monitoring up: Prometheus http://127.0.0.1:$PROM_PORT, exporters 29401.."
    ;;
  stop)
    for f in "$MON"/exporter*.pid; do stop_pidfile "$f" 'ubft validator exporter'; done
    docker rm -f "$NAME-prom" "$NAME-grafana" "$NAME-renderer" >/dev/null 2>&1 || true
    ;;
  status)
    curl -s "127.0.0.1:$PROM_PORT/api/v1/targets" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']['activeTargets']
for t in sorted(d,key=lambda t:(t['labels']['job'],t['labels'].get('validator',''))): print(t['labels']['job'],t['labels'].get('validator'),t['health'],t.get('lastError',''))"
    ;;
  "") [ -n "${VT12_SOURCE_ONLY:-}" ] || { echo "usage: $0 start|stop|status" >&2; exit 2; } ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
