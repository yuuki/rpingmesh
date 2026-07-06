#!/usr/bin/env bash
# Verify the observability stack: Grafana health/provisioning and every
# dashboard panel's PromQL against VictoriaMetrics. Run after `make obs-up`
# and `make obs-seed`.
set -euo pipefail

# Resolve deploy/observability/.env from this script's own location, not the
# caller's cwd, so `make obs-verify` (cwd=rebuild/) and a direct
# `./scripts/verify-observability.sh` invocation both find it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../deploy/observability/.env"

# If `make obs-up` started Grafana with a non-default admin user/password
# from deploy/observability/.env, verify against those same credentials
# instead of silently falling back to admin/admin. Env vars already
# exported by the caller take priority over the .env file.
if [ -f "$ENV_FILE" ]; then
  _preset_user="${GF_SECURITY_ADMIN_USER-}"
  _preset_pass="${GF_SECURITY_ADMIN_PASSWORD-}"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  [ -n "$_preset_user" ] && GF_SECURITY_ADMIN_USER="$_preset_user"
  [ -n "$_preset_pass" ] && GF_SECURITY_ADMIN_PASSWORD="$_preset_pass"
fi

VM_URL="${VM_URL:-http://localhost:8428}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GF_SECURITY_ADMIN_USER:-admin}"
GRAFANA_PASS="${GF_SECURITY_ADMIN_PASSWORD:-admin}"

fail=0

echo "== Grafana health ==" >&2
curl -sf "${GRAFANA_URL}/api/health" | tee /dev/stderr | grep -q '"database": *"ok"' \
  || { echo "!! Grafana health check failed" >&2; fail=1; }
echo >&2

echo "== Provisioned dashboards ==" >&2
search="$(curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" "${GRAFANA_URL}/api/search?type=dash-db")"
echo "$search" | grep -o '"uid":"[^"]*"' >&2
echo "$search" | grep -q '"uid":"rpingmesh-mesh-overview"' || { echo "!! missing rpingmesh-mesh-overview" >&2; fail=1; }
echo "$search" | grep -q '"uid":"rpingmesh-tor-pair"' || { echo "!! missing rpingmesh-tor-pair" >&2; fail=1; }
echo >&2

echo "== Provisioned datasource ==" >&2
curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" "${GRAFANA_URL}/api/datasources" \
  | grep -q '"uid":"victoriametrics"' || { echo "!! missing victoriametrics datasource" >&2; fail=1; }

echo "== Panel queries against VictoriaMetrics ==" >&2
queries=(
  'sum(rate(rpingmesh_probe_total[5m]))'
  '100 * (1 - sum by (source_tor,target_tor)(rate(rpingmesh_probe_success_total[30m])) / (sum by (source_tor,target_tor)(rate(rpingmesh_probe_total[30m])) > 0))'
  'sum by (reason)(rate(rpingmesh_probe_failed_total[5m]))'
  'sum by (kind)(rate(rpingmesh_analyzer_sla_violations_total[5m]))'
  'histogram_quantile(0.99, sum by (le)(rate(rpingmesh_network_rtt_ns_bucket{source_tor="tor-a",target_tor="tor-d"}[5m])))'
  'sum by (le)(rate(rpingmesh_network_rtt_ns_bucket{source_tor="tor-a",target_tor="tor-d"}[5m]))'
  'min(rpingmesh_agent_self_throttle)'
)
for q in "${queries[@]}"; do
  r=$(curl -s -G "${VM_URL}/api/v1/query" --data-urlencode "query=$q")
  echo "$q -> $(echo "$r" | head -c 120)" >&2
  echo "$r" | grep -q '"result":\[{' || { echo "  !! EMPTY/ERROR for: $q" >&2; fail=1; }
done

echo >&2
echo "== label_values(rpingmesh_probe_total) sanity ==" >&2
curl -s "${VM_URL}/api/v1/series?match[]=rpingmesh_probe_total" | head -c 200 >&2
echo >&2

if [ "$fail" -ne 0 ]; then
  echo "!! Verification FAILED" >&2
  exit 1
fi
echo "All checks passed." >&2
