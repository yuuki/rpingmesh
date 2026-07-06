#!/usr/bin/env bash
# Seed synthetic R-Pingmesh mesh metrics into VictoriaMetrics for dashboard demos.
# Backfills ~30 min of a 6-ToR mesh so that rate()/histogram_quantile() have data.
# Names MUST match the exporter output (translation_strategy=WithoutSuffixes).
set -euo pipefail

VM_URL="${VM_URL:-http://localhost:8428}"
WINDOW="${WINDOW:-1800}"   # seconds of backfill
STEP="${STEP:-15}"         # sample interval seconds
NOW="$(date +%s)"
START="$(( NOW - WINDOW ))"

gen() {
  awk -v start="$START" -v now="$NOW" -v step="$STEP" '
  BEGIN {
    ntor = split("tor-a tor-b tor-c tor-d tor-e tor-f", T, " ")
    nle  = split("100 500 1000 5000 10000 50000 100000 500000 1000000 5000000 10000000", LE, " ")
    # cumulative accumulators, keyed by pair index "i,j"
    # bad pairs: high loss on (a->d) and (c->e); high RTT on (b->f)
    for (t = start; t <= now; t += step) {
      ts = t * 1000
      for (i = 1; i <= ntor; i++) {
        for (j = 1; j <= ntor; j++) {
          if (i == j) continue
          key = i "," j
          # per-pair profile
          loss = 0.001
          modal = 3                      # default modal bucket index (~1us..5us region)
          if (i == 1 && j == 4) { loss = 0.06;  modal = 9 }   # a->d lossy
          if (i == 3 && j == 5) { loss = 0.04;  modal = 8 }   # c->e lossy
          if (i == 2 && j == 6) { loss = 0.002; modal = 10 }  # b->f high RTT (1-5ms)
          per = 30                        # probes attempted per step
          fail = int(per * loss + 0.5)
          succ = per - fail
          # accumulate counters
          tot[key]  += per
          ok[key]   += succ
          # failures: most timeouts, a steady trickle of invalid_rtt
          ftimeout[key] += fail
          finvalid[key] += (( (i+j+t) % 7 == 0) ? 1 : 0)
          # histogram cumulative buckets: put succ obs into modal bucket
          for (b = 1; b <= nle; b++) if (b >= modal) hb[key,b] += succ
          hcount[key] += succ
          hsum[key]   += succ * LE[modal]   # rough sum using modal bucket bound (ns)
          # SLA violations for the bad pairs.
          # NOTE: gated on (t - start), not raw t: STEP (15s) shares a common
          # factor with 60/90/120, so a raw "t % 60 == 0" check only ever
          # fires if the absolute epoch `start` happens to be a multiple of
          # 15 -- true for only 1 in 15 runs depending on wall-clock time at
          # invocation. Anchoring to the loop-relative offset (always a
          # multiple of STEP, starting at 0) makes it fire deterministically
          # regardless of when the script is run.
          if (i == 1 && j == 4) slaloss[key] += (((t - start) % 60 == 0) ? 1 : 0)
          if (i == 3 && j == 5) slaloss[key] += (((t - start) % 90 == 0) ? 1 : 0)
          if (i == 2 && j == 6) slartt[key]  += (((t - start) % 120 == 0) ? 1 : 0)

          lbl = "source_tor=\"" T[i] "\",target_tor=\"" T[j] "\",job=\"rpingmesh-agent\""
          printf "rpingmesh_probe_total{%s} %d %d\n", lbl, tot[key], ts
          printf "rpingmesh_probe_success_total{%s} %d %d\n", lbl, ok[key], ts
          if (ftimeout[key] > 0)
            printf "rpingmesh_probe_failed_total{%s,reason=\"timeout\"} %d %d\n", lbl, ftimeout[key], ts
          if (finvalid[key] > 0)
            printf "rpingmesh_probe_failed_total{%s,reason=\"invalid_rtt\"} %d %d\n", lbl, finvalid[key], ts
          for (b = 1; b <= nle; b++)
            printf "rpingmesh_network_rtt_ns_bucket{%s,le=\"%s\"} %d %d\n", lbl, LE[b], hb[key,b], ts
          printf "rpingmesh_network_rtt_ns_bucket{%s,le=\"+Inf\"} %d %d\n", lbl, hcount[key], ts
          printf "rpingmesh_network_rtt_ns_sum{%s} %d %d\n", lbl, hsum[key], ts
          printf "rpingmesh_network_rtt_ns_count{%s} %d %d\n", lbl, hcount[key], ts
          # reuse the same distribution for prober/responder delay (demo only)
          for (b = 1; b <= nle; b++) {
            printf "rpingmesh_prober_delay_ns_bucket{%s,le=\"%s\"} %d %d\n", lbl, LE[b], hb[key,b], ts
            printf "rpingmesh_responder_delay_ns_bucket{%s,le=\"%s\"} %d %d\n", lbl, LE[b], hb[key,b], ts
          }
          printf "rpingmesh_prober_delay_ns_bucket{%s,le=\"+Inf\"} %d %d\n", lbl, hcount[key], ts
          printf "rpingmesh_prober_delay_ns_sum{%s} %d %d\n", lbl, hsum[key], ts
          printf "rpingmesh_prober_delay_ns_count{%s} %d %d\n", lbl, hcount[key], ts
          printf "rpingmesh_responder_delay_ns_bucket{%s,le=\"+Inf\"} %d %d\n", lbl, hcount[key], ts
          printf "rpingmesh_responder_delay_ns_sum{%s} %d %d\n", lbl, hsum[key], ts
          printf "rpingmesh_responder_delay_ns_count{%s} %d %d\n", lbl, hcount[key], ts
          # analyzer SLA violations (job=rpingmesh-analyzer)
          albl = "source_tor=\"" T[i] "\",target_tor=\"" T[j] "\",job=\"rpingmesh-analyzer\""
          if (slaloss[key] > 0)
            printf "rpingmesh_analyzer_sla_violations_total{%s,kind=\"loss\"} %d %d\n", albl, slaloss[key], ts
          if (slartt[key] > 0)
            printf "rpingmesh_analyzer_sla_violations_total{%s,kind=\"rtt\"} %d %d\n", albl, slartt[key], ts
        }
      }
      # fleet-level analyzer + agent gauges
      psum += ntor * (ntor - 1)
      printf "rpingmesh_analyzer_path_summaries_total{job=\"rpingmesh-analyzer\"} %d %d\n", psum, ts
      # self_throttle: agent-1 dips mid-window, agent-2 stays healthy
      thr = (t > start + 600 && t < start + 900) ? 0.6 : 1.0
      printf "rpingmesh_agent_self_throttle{job=\"rpingmesh-agent\",instance=\"agent-1\"} %.2f %d\n", thr, ts
      printf "rpingmesh_agent_self_throttle{job=\"rpingmesh-agent\",instance=\"agent-2\"} 1.00 %d\n", ts
      # event ring drops on agent-1 during the throttled window
      if (t > start + 600 && t < start + 900) drops += 3
      printf "rpingmesh_event_ring_dropped_total{job=\"rpingmesh-agent\",instance=\"agent-1\",ring=\"prober\"} %d %d\n", drops, ts
    }
  }'
}

echo "Seeding ${WINDOW}s of mesh data (step ${STEP}s) into ${VM_URL} ..." >&2
gen | curl -s --fail --data-binary @- "${VM_URL}/api/v1/import/prometheus"
# flush VM in-memory buffers so queries see the data immediately
curl -s "${VM_URL}/internal/force_flush" >/dev/null || true
echo "Seed complete. Try: curl -s '${VM_URL}/api/v1/label/__name__/values' | tr ',' '\n' | grep rpingmesh" >&2
