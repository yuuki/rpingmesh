#!/usr/bin/env bash
# Verify the observability stack: Grafana health/provisioning, every
# dashboard query and alert rule against VictoriaMetrics, and vmalert's rule
# health. Run after `make obs-up` and `make obs-seed` (either NAME_STYLE).
set -euo pipefail

# Resolve deploy/observability/.env from this script's own location, not the
# caller's cwd, so `make obs-verify` from the repository root and a direct
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

echo "== Dashboard queries against VictoriaMetrics ==" >&2
# Every panel target and template variable is taken from the committed
# dashboard JSON (not a hand-copied list), with Grafana macros and the
# drilldown variables pinned to a seeded pair, so any name or label drift in a
# dashboard shows up here. Both metric-name styles are covered by the
# {__name__=~"rpingmesh[._]..."} selectors; run with either NAME_STYLE seed.
if ! python3 - "${VM_URL}" "${SCRIPT_DIR}/../dashboards" <<'PY'
import glob, json, os, re, sys, urllib.parse, urllib.request
vm, dash_dir = sys.argv[1], sys.argv[2]
subst = {"$__rate_interval": "5m", "$__range": "30m",
         "$source_tor": "tor-a", "$target_tor": "tor-d"}
def query(expr):
    url = vm + "/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    return json.load(urllib.request.urlopen(url))
failed = 0
for path in sorted(glob.glob(os.path.join(dash_dir, "*.json"))):
    dash = json.load(open(path))
    exprs = []
    for var in dash.get("templating", {}).get("list", []):
        q = var.get("query")
        q = q.get("query", "") if isinstance(q, dict) else (q or "")
        m = re.match(r"label_values\((.*),\s*(\w+)\)$", q)
        if m:  # label_values(selector, label) -> group by the label
            exprs.append(("var " + var["name"], "group by (%s) (%s)" % (m.group(2), m.group(1))))
    for panel in dash.get("panels", []):
        for t in panel.get("targets", []):
            if t.get("expr"):
                exprs.append((panel.get("title", "?"), t["expr"]))
    for title, expr in exprs:
        for k, v in subst.items():
            expr = expr.replace(k, v)
        try:
            res = query(expr)["data"]["result"]
        except Exception as e:  # HTTP 4xx/5xx: bad PromQL
            res, err = [], e
        ok = bool(res)
        failed += not ok
        print("%s %s: %s -> %d series" % ("ok " if ok else "!! ", os.path.basename(path), title, len(res)), file=sys.stderr)
sys.exit(1 if failed else 0)
PY
then
  fail=1
fi
echo >&2

echo "== Alert rule expressions against the seeded data ==" >&2
# The seed has two lossy ToR pairs (tor-a->tor-d 6%, tor-c->tor-e 4%) and
# analyzer SLA violations, and nothing else alert-worthy in its last 10 min.
# Exactly these alerts' expressions must return series; any other firing rule
# is a false positive. (`for:` durations are not evaluated here.)
RULES="${SCRIPT_DIR}/../deploy/observability/alerts/rpingmesh.rules.yml"
if ! python3 - "${VM_URL}" "${RULES}" <<'PY'
import json, re, sys, urllib.parse, urllib.request
vm, rules = sys.argv[1], sys.argv[2]
expected = {"RpingmeshTorPairLoss", "RpingmeshSLAViolation"}
# Minimal parser for this file's layout (avoids a PyYAML dependency):
# "- alert: Name" followed by "expr: |" and an indented block.
alerts, cur, block = {}, None, None
for line in open(rules):
    m = re.match(r"\s*- alert: (\S+)", line)
    if m:
        cur, block = m.group(1), None
        continue
    if cur and re.match(r"\s*expr: \|", line):
        block, alerts[cur] = len(line) - len(line.lstrip()), ""
        continue
    if cur and block is not None:
        if line.strip() and len(line) - len(line.lstrip()) <= block:
            block, cur = None, None
        else:
            alerts[cur] += line.strip() + " "
failed = 0
for name, expr in alerts.items():
    url = vm + "/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    res = json.load(urllib.request.urlopen(url))["data"]["result"]
    firing = bool(res)
    ok = firing == (name in expected)
    failed += not ok
    print("%s %s: %s (%d series)" % ("ok " if ok else "!! ", name,
          "firing" if firing else "quiet", len(res)), file=sys.stderr)
missing = expected - alerts.keys()
if missing:
    print("!! rules missing from %s: %s" % (rules, sorted(missing)), file=sys.stderr)
sys.exit(1 if failed or missing or len(alerts) < 10 else 0)
PY
then
  fail=1
fi
echo >&2

echo "== vmalert rule health ==" >&2
VMALERT_URL="${VMALERT_URL:-http://localhost:8880}"
if rules_json="$(curl -sf "${VMALERT_URL}/api/v1/rules")"; then
  echo "$rules_json" | python3 -c '
import json, sys
groups = json.load(sys.stdin)["data"]["groups"]
rules = [r for g in groups for r in g["rules"]]
bad = [r["name"] for r in rules if r.get("lastError")]
print("%d groups, %d rules, %d with errors %s" % (len(groups), len(rules), len(bad), bad), file=sys.stderr)
sys.exit(1 if bad or len(rules) < 10 else 0)' || { echo "!! vmalert rules missing or erroring" >&2; fail=1; }
else
  echo "!! vmalert not reachable at ${VMALERT_URL}" >&2; fail=1
fi
echo >&2

if [ "$fail" -ne 0 ]; then
  echo "!! Verification FAILED" >&2
  exit 1
fi
echo "All checks passed." >&2
