#!/usr/bin/env bash
# run-e2e.sh - Set up soft-RoCE devices and run RDMA e2e tests.
#
# Called as the container ENTRYPOINT by docker-compose.e2e.yml.
# Requires a privileged container with NET_ADMIN, SYS_ADMIN, IPC_LOCK,
# and /lib/modules mounted from the host (via docker-compose volumes).
#
# Device layout (veth pair in main namespace with policy routing):
#   rxe0 -> veth0 (prober,    10.200.0.2/24)
#   rxe1 -> veth1 (responder, 10.200.0.1/24)
#   Both in the same network namespace.
#
# The problem with two rxe devices in one namespace:
#   When rdma_rxe (rxe0) sends a UDP probe to 10.200.0.1, the kernel
#   consults the LOCAL routing table first (priority 0). The LOCAL table
#   has 10.200.0.1 as RTN_LOCAL (because it is assigned to veth1), so the
#   packet is delivered via loopback (skb->dev=lo). rdma_rxe's receive
#   handler uses skb->dev to look up the rxe device; since lo has no rxe
#   device, the packet is silently dropped.
#
# Solution: policy routing with iif-based local delivery rules.
#   1. Move the LOCAL table lookup rule from priority 0 to priority 100.
#   2. Add a higher-priority rule (prio 50): "from 10.200.0.2 to 10.200.0.1
#      → look up main table", which has 10.200.0.1 unicast via veth0.
#      This forces OUTGOING probes through veth0 instead of loopback.
#   3. The prio-50 rule also matches INCOMING packets at veth1 (same
#      src/dst). Without correction, the kernel would FORWARD them via veth0
#      instead of delivering locally, causing rxe_udp_encap_recv to be
#      bypassed entirely. Fix: add iif-based rules at prio 48/49 that
#      redirect packets arriving on veth0/veth1 to the LOCAL table FIRST.
#
# First-time host setup (run once from macOS):
#   make setup-colima

set -euo pipefail

log()  { echo "[run-e2e] $*"; }
die()  { echo "[run-e2e] ERROR: $*" >&2; exit 1; }

log "Kernel: $(uname -r)"

# ---------------------------------------------------------------------------
# Load kernel modules
# ---------------------------------------------------------------------------
log "Loading kernel modules..."

if [ -d /sys/module/rdma_rxe ]; then
    log "rdma_rxe module already loaded."
else
    if ! modprobe rdma_rxe 2>/dev/null; then
        KVER=$(uname -r)
        die "rdma_rxe module not found (kernel: ${KVER}).
Run the one-time setup from macOS:
  make setup-colima
This installs linux-modules-extra-${KVER} on the Colima VM and loads rdma_rxe."
    fi
    log "rdma_rxe module loaded."
fi

# ---------------------------------------------------------------------------
# Clean up stale devices from previous runs (idempotent setup)
# ---------------------------------------------------------------------------
# Restore the local table rule to priority 0 if it was moved
if ip rule show | grep -q "lookup local" && ! ip rule show | grep -q "^0:.*lookup local"; then
    ip rule del lookup local 2>/dev/null || true
    ip rule add lookup local prio 0 2>/dev/null || true
    log "Restored local table rule to priority 0."
fi
# Remove all stale rules in our working priority range (48-55, 100).
# Use priority-based deletion to handle any format variation from old runs.
for prio in 48 49 50 51 52 53 54 55 100; do
    while ip rule del prio "${prio}" 2>/dev/null; do
        log "Removed stale rule at prio ${prio}"
    done
done
ip route del 10.200.0.1/32 dev veth0 table main 2>/dev/null && log "Removed stale main-table route (forward)" || true
ip route del 10.200.0.2/32 dev veth1 table main 2>/dev/null && log "Removed stale main-table route (reverse)" || true
rdma link del rxe0 2>/dev/null && log "Removed stale rxe0" || true
rdma link del rxe1 2>/dev/null && log "Removed stale rxe1" || true
ip link del veth0  2>/dev/null && log "Removed stale veth0/veth1" || true
ip link del dummy0 2>/dev/null && log "Removed stale dummy0" || true
# Clean up any stale network namespace from older script versions
if ip netns list 2>/dev/null | grep -q rxe_ns1; then
    ip netns exec rxe_ns1 rdma link del rxe1 2>/dev/null || true
    ip netns del rxe_ns1 2>/dev/null && log "Removed stale rxe_ns1" || true
fi

# ---------------------------------------------------------------------------
# Disable rp_filter (reverse path filtering)
# ---------------------------------------------------------------------------
log "Disabling rp_filter..."
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true

# ---------------------------------------------------------------------------
# Create veth pair (both ends in main namespace)
# ---------------------------------------------------------------------------
log "Creating veth pair (veth0 <-> veth1), both in main namespace..."
ip link add veth0 type veth peer name veth1

# Configure veth0 (prober)
ip addr add 10.200.0.2/24 dev veth0
ip link set veth0 up
sysctl -w net.ipv4.conf.veth0.rp_filter=0 2>/dev/null || true

# Configure veth1 (responder)
ip addr add 10.200.0.1/24 dev veth1
ip link set veth1 up
sysctl -w net.ipv4.conf.veth1.rp_filter=0 2>/dev/null || true

# ---------------------------------------------------------------------------
# Pre-populate ARP entries so ibv_create_ah() can resolve MAC addresses.
# ---------------------------------------------------------------------------
log "Pre-populating ARP entries (permanent, never expire)..."
VETH0_MAC=$(cat /sys/class/net/veth0/address)
VETH1_MAC=$(cat /sys/class/net/veth1/address)
ip neigh replace 10.200.0.1 lladdr "${VETH1_MAC}" dev veth0 nud permanent
ip neigh replace 10.200.0.2 lladdr "${VETH0_MAC}" dev veth1 nud permanent
log "ARP: veth0->10.200.0.1 (${VETH1_MAC}), veth1->10.200.0.2 (${VETH0_MAC})"
log "ARP table state:"
ip neigh show

# ---------------------------------------------------------------------------
# Policy routing: force rxe0->rxe1 probes through the veth pair
#
# Problem 1: outgoing probe hits the LOCAL table (prio 0) first.
#   10.200.0.1 is in the LOCAL table (RTN_LOCAL for veth1), so probes
#   go via lo (loopback) and rdma_rxe drops them (rxe_get_dev_from_net(lo)=NULL).
#   Fix: move LOCAL table to prio 100; add prio-50 rule directing outgoing
#   packets via veth0 (main table unicast route).
#
# Problem 2: the prio-50/51 src/dst rules also match INCOMING packets.
#   When a probe arrives at veth1 (src=10.200.0.2, dst=10.200.0.1), the
#   kernel's FIB lookup also hits prio-50 (same src/dst). Main table has
#   "10.200.0.1/32 dev veth0" as a unicast route, so the kernel FORWARDS
#   the packet back to veth0 instead of delivering it locally. This means
#   rxe_udp_encap_recv is NEVER called (confirmed by ftrace showing 0 calls).
#   Fix: add prio 48/49 rules matching by iif (input interface). When a
#   packet arrives on veth1/veth0, these higher-priority rules redirect to
#   the LOCAL table, which correctly delivers the packet locally.
#
# Final FIB rule order (prio ascending = higher priority first):
#   48: to 10.200.0.2 iif veth0 lookup local  (ACK arrives at veth0 -> local)
#   49: to 10.200.0.1 iif veth1 lookup local  (probe arrives at veth1 -> local)
#   50: from 10.200.0.2 to 10.200.0.1 lookup main  (outgoing probe -> veth0)
#   51: to 10.200.0.2 lookup main  (outgoing ACK or ibv_create_ah() -> veth1)
#  100: lookup local  (all other traffic -> local table)
#
# NOTE on prio 51: No "from" clause because ibv_create_ah() in the kernel
# (rdma_addr_find_l2_eth_by_grh) may call ip_route_output_key() with an
# unspecified source address, preventing "from 10.200.0.1" rules from
# matching. Without matching prio 51, the lookup falls to prio 100 (LOCAL
# table), where 10.200.0.2 is RTN_LOCAL, causing ibv_create_ah() to fail.
# ---------------------------------------------------------------------------
log "Configuring policy routing to bypass LOCAL table for RDMA probes and ACKs..."
ip rule del prio 0 2>/dev/null || true                          # remove default local-table rule
ip rule add lookup local prio 100                               # re-add at lower priority

# Forward: probe from rxe0 (10.200.0.2) to rxe1 (10.200.0.1) via veth0
ip route add 10.200.0.1/32 dev veth0 table main 2>/dev/null || true
ip rule add from 10.200.0.2 to 10.200.0.1 lookup main prio 50
# Reverse: ACK from rxe1 (10.200.0.1) to rxe0 (10.200.0.2) via veth1.
# NOTE: No "from" clause here so ibv_create_ah() also matches this rule.
# The kernel's rdma_addr_find_l2_eth_by_grh() may not always supply the
# source IP when calling ip_route_output_key(), causing "from 10.200.0.1"
# rules to be skipped and falling through to the LOCAL table (where
# 10.200.0.2 is marked RTN_LOCAL) → ibv_create_ah() fails.
ip route add 10.200.0.2/32 dev veth1 table main 2>/dev/null || true
ip rule add to 10.200.0.2 lookup main prio 51

# Fix for incoming packets: the prio-50/51 rules above also match INCOMING
# packets (src/dst identical), causing the kernel to FORWARD them via
# veth0/veth1 (unicast route) rather than deliver them locally. This
# prevents rxe_udp_encap_recv from ever being called (ftrace confirmed).
# Solution: add higher-priority iif-based rules (prio 48/49) that match
# packets arriving on each veth and redirect them to the LOCAL table.
ip rule add to 10.200.0.1 iif veth1 lookup local prio 49
ip rule add to 10.200.0.2 iif veth0 lookup local prio 48

log "Routing rules after policy setup:"
ip rule show

log "Route to 10.200.0.1 from 10.200.0.2 (should go via veth0, NOT loopback):"
ip route get 10.200.0.1 from 10.200.0.2 2>/dev/null || log "WARN: route lookup failed"
log "Route to 10.200.0.2 from 10.200.0.1 (should go via veth1, NOT loopback):"
ip route get 10.200.0.2 from 10.200.0.1 2>/dev/null || log "WARN: route lookup failed"

# ---------------------------------------------------------------------------
# Allow RoCEv2 (UDP 4791) through iptables
# ---------------------------------------------------------------------------
log "Adding iptables ACCEPT rules for RoCEv2 (UDP port 4791)..."
iptables -I INPUT  -p udp --dport 4791 -j ACCEPT 2>&1 || true
iptables -I INPUT  -p udp --sport 4791 -j ACCEPT 2>&1 || true
iptables -I OUTPUT -p udp --dport 4791 -j ACCEPT 2>&1 || true
iptables -I OUTPUT -p udp --sport 4791 -j ACCEPT 2>&1 || true
iptables -I FORWARD -p udp --dport 4791 -j ACCEPT 2>&1 || true
iptables -I FORWARD -p udp --sport 4791 -j ACCEPT 2>&1 || true

# ---------------------------------------------------------------------------
# Create RDMA devices
# Ensure /dev/infiniband/ exists so the kernel can create uverbs device nodes.
# ---------------------------------------------------------------------------
mkdir -p /dev/infiniband

log "Creating rxe0 on veth0 (prober, 10.200.0.2)..."
rdma link add rxe0 type rxe netdev veth0

log "Creating rxe1 on veth1 (responder, 10.200.0.1)..."
rdma link add rxe1 type rxe netdev veth1

# ---------------------------------------------------------------------------
# Verify RDMA device setup
# ---------------------------------------------------------------------------
log "RDMA devices:"
rdma link show

log "Main namespace routing table:"
ip route show

log "Waiting for GID assignments..."
sleep 2

# Ensure uverbs device nodes are present (may not be auto-created in container).
log "Creating uverbs device nodes from sysfs (if missing)..."
for vdir in /sys/class/infiniband_verbs/uverbs*/; do
    [ -d "${vdir}" ] || continue
    vname=$(basename "${vdir}")
    devnum=$(cat "${vdir}/dev" 2>/dev/null) || continue
    MAJOR="${devnum%%:*}"
    MINOR="${devnum##*:}"
    if [ ! -e "/dev/infiniband/${vname}" ]; then
        mknod "/dev/infiniband/${vname}" c "${MAJOR}" "${MINOR}" 2>/dev/null || true
        log "  Created /dev/infiniband/${vname} (${MAJOR}:${MINOR})"
    else
        log "  Exists: /dev/infiniband/${vname} (${MAJOR}:${MINOR})"
    fi
done

log "InfiniBand sysfs devices:"
ls /sys/class/infiniband/ 2>/dev/null || log "WARN: /sys/class/infiniband/ not found"
log "InfiniBand uverbs devices:"
ls /dev/infiniband/ 2>/dev/null || log "WARN: /dev/infiniband/ not found"

# ---------------------------------------------------------------------------
# Check UDP socket binding for rxe devices (port 4791 = 0x12B7)
# ---------------------------------------------------------------------------
log "UDP/UDP6 sockets on port 4791 (main namespace, /proc/net):"
grep -i "12B7" /proc/net/udp  2>/dev/null && true
grep -i "12B7" /proc/net/udp6 2>/dev/null && true
grep -qi "12B7" /proc/net/udp /proc/net/udp6 2>/dev/null || \
    log "WARN: no UDP/UDP6 socket on port 4791 — rdma_rxe may not have started its listener"

log "UDP socket details (ss -ulnp, port 4791):"
ss -ulnp 2>/dev/null | grep -E ":4791|UNCONN.*4791" | head -20 || log "  (no output from ss)"
log "UDP socket count on port 4791: $(ss -ulnp 2>/dev/null | grep -c ':4791' || echo 0)"

log "rdma resource list (QP state):"
rdma resource list qp 2>/dev/null | head -30 || log "  (rdma resource not available)"

log "Kernel messages from rxe/rdma device setup (dmesg, pre-test):"
dmesg 2>/dev/null | grep -iE "rxe|rdma|infiniband|error" | tail -30 || true

# ---------------------------------------------------------------------------
# Enable rdma_rxe dynamic debug and ftrace for rxe_udp_encap_recv
# ---------------------------------------------------------------------------
log "Enabling rdma_rxe dynamic debug and ftrace..."
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
if [ -f /sys/kernel/debug/dynamic_debug/control ]; then
    echo -n 'file rxe_net.c +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null && \
        log "rxe_net.c dynamic debug ENABLED" || log "WARN: failed to enable rxe_net.c debug"
    echo -n 'file rxe_recv.c +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null || true
    echo -n 'file rxe_qp.c +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null || true
else
    log "WARN: /sys/kernel/debug/dynamic_debug/control not found"
fi

# Setup ftrace to count calls to rxe_udp_encap_recv
FTRACE_DIR=/sys/kernel/debug/tracing
if [ -d "${FTRACE_DIR}" ]; then
    # Reset tracer
    echo nop > "${FTRACE_DIR}/current_tracer" 2>/dev/null || true
    # Check if rxe_udp_encap_recv is traceable
    if grep -q "rxe_udp_encap_recv" "${FTRACE_DIR}/available_filter_functions" 2>/dev/null; then
        echo "function" > "${FTRACE_DIR}/current_tracer" 2>/dev/null || true
        echo "rxe_udp_encap_recv" > "${FTRACE_DIR}/set_ftrace_filter" 2>/dev/null || true
        echo 1 > "${FTRACE_DIR}/tracing_on" 2>/dev/null || true
        log "ftrace for rxe_udp_encap_recv ENABLED"
        FTRACE_ENABLED=1
    else
        log "WARN: rxe_udp_encap_recv not found in available_filter_functions"
        FTRACE_ENABLED=0
    fi
else
    log "WARN: ftrace not available (${FTRACE_DIR} not found)"
    FTRACE_ENABLED=0
fi

log "Veth packet counters (baseline):"
log "  veth0 TX: $(cat /sys/class/net/veth0/statistics/tx_packets 2>/dev/null || echo N/A) pkts"
log "  veth0 RX: $(cat /sys/class/net/veth0/statistics/rx_packets 2>/dev/null || echo N/A) pkts"
log "  veth1 TX: $(cat /sys/class/net/veth1/statistics/tx_packets 2>/dev/null || echo N/A) pkts"
log "  veth1 RX: $(cat /sys/class/net/veth1/statistics/rx_packets 2>/dev/null || echo N/A) pkts"

# ---------------------------------------------------------------------------
# Verify IP connectivity via veth pair
# ---------------------------------------------------------------------------
log "Verifying IP connectivity: 10.200.0.1 from veth0..."
if ping -c 3 -W 2 -I veth0 10.200.0.1 >/dev/null 2>&1; then
    log "Ping from veth0 to 10.200.0.1 succeeded."
else
    log "WARN: Ping from veth0 to 10.200.0.1 failed (ICMP may be filtered)."
    log "      Continuing — RDMA uses UDP port 4791, not ICMP."
fi

# Capture any device-setup kernel messages, then clear before test.
log "Kernel messages from device setup (rxe/rdma related):"
dmesg 2>/dev/null | grep -iE "rxe|rdma|infiniband" | tail -20 || true
log "=== clearing dmesg before test ==="
dmesg -c >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Capture UDP/RoCEv2 packets on veth0 and veth1 during the test to verify
# that RDMA packets traverse the veth pair.
# ---------------------------------------------------------------------------
PCAP_VETH0=/tmp/veth0.pcap
PCAP_VETH1=/tmp/veth1.pcap
tcpdump -i veth0 -nn -c 20 udp port 4791 -w "${PCAP_VETH0}" 2>/dev/null &
TCPDUMP_VETH0_PID=$!
tcpdump -i veth1 -nn -c 20 udp port 4791 -w "${PCAP_VETH1}" 2>/dev/null &
TCPDUMP_VETH1_PID=$!
log "tcpdump started (PIDs: veth0=${TCPDUMP_VETH0_PID}, veth1=${TCPDUMP_VETH1_PID})"

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
log "Starting RDMA e2e tests..."
# Temporarily disable exit-on-error so post-test diagnostics always run.
set +e
env RDMA_E2E_ENABLED=1 \
    go test -v -timeout 60s -run "^TestRDMAE2E" ./e2e/
EXIT_CODE=$?
set -e

# Stop tcpdump and show captures
sleep 1
kill "${TCPDUMP_VETH0_PID}" "${TCPDUMP_VETH1_PID}" 2>/dev/null || true
wait "${TCPDUMP_VETH0_PID}" "${TCPDUMP_VETH1_PID}" 2>/dev/null || true
log "tcpdump veth0 (RoCEv2 packets seen on prober interface):"
tcpdump -r "${PCAP_VETH0}" -nn 2>/dev/null | head -20 || log "  (no capture or no packets)"
log "tcpdump veth1 (RoCEv2 packets seen on responder interface):"
tcpdump -r "${PCAP_VETH1}" -nn 2>/dev/null | head -20 || log "  (no capture or no packets)"

# ---------------------------------------------------------------------------
# Post-test diagnostics
# ---------------------------------------------------------------------------
log "Veth packet counters (after test):"
log "  veth0 TX: $(cat /sys/class/net/veth0/statistics/tx_packets 2>/dev/null || echo N/A) pkts"
log "  veth0 RX: $(cat /sys/class/net/veth0/statistics/rx_packets 2>/dev/null || echo N/A) pkts"
log "  veth1 TX: $(cat /sys/class/net/veth1/statistics/tx_packets 2>/dev/null || echo N/A) pkts"
log "  veth1 RX: $(cat /sys/class/net/veth1/statistics/rx_packets 2>/dev/null || echo N/A) pkts"

log "UDP/UDP6 sockets on port 4791 (after test):"
grep -i "12B7" /proc/net/udp  2>/dev/null && true
grep -i "12B7" /proc/net/udp6 2>/dev/null && true

log "All kernel messages since test start (rdma_rxe related - up to 60 lines):"
dmesg 2>/dev/null | grep -iE "rxe|rdma|verbs|infiniband" | tail -60 || true
log "All kernel messages since test start (last 50 lines):"
dmesg 2>/dev/null | tail -50 || true

# ---------------------------------------------------------------------------
# Show ftrace results (how many times rxe_udp_encap_recv was called)
# ---------------------------------------------------------------------------
FTRACE_DIR=/sys/kernel/debug/tracing
if [ "${FTRACE_ENABLED:-0}" = "1" ]; then
    echo 0 > "${FTRACE_DIR}/tracing_on" 2>/dev/null || true
    RECV_COUNT=$(grep -c "rxe_udp_encap_recv" "${FTRACE_DIR}/trace" 2>/dev/null || echo 0)
    log "ftrace: rxe_udp_encap_recv called ${RECV_COUNT} times"
    log "ftrace trace (first 20 lines):"
    grep "rxe_udp_encap_recv" "${FTRACE_DIR}/trace" 2>/dev/null | head -20 || log "  (no entries)"
    # Reset
    echo "" > "${FTRACE_DIR}/set_ftrace_filter" 2>/dev/null || true
    echo nop > "${FTRACE_DIR}/current_tracer" 2>/dev/null || true
fi

log "rdma resource list (QP state, post-test):"
rdma resource list qp 2>/dev/null | head -30 || log "  (rdma resource not available)"

exit "${EXIT_CODE}"
