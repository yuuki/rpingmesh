#!/usr/bin/env bash
# check-glibc-compat.sh - Fail if a dynamically linked ELF binary requires a
# newer glibc than the given floor.
#
# Usage: scripts/check-glibc-compat.sh <binary> <max-glibc-version>
#   e.g. scripts/check-glibc-compat.sh bin/rpingmesh-agent 2.34
#
# The agent is linked with cgo, so every GLIBC_x.y symbol version it
# references must exist on the target host or the dynamic loader refuses to
# start it ("version `GLIBC_2.38' not found"). This reads the version
# requirements (.gnu.version_r) with objdump, falling back to readelf.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <binary> <max-glibc-version>" >&2
    exit 2
fi
bin="$1"
max="$2"

if [ ! -f "$bin" ]; then
    echo "ERROR: $bin not found" >&2
    exit 2
fi

if command -v objdump >/dev/null 2>&1; then
    reqs="$(objdump -p "$bin")"
elif command -v readelf >/dev/null 2>&1; then
    reqs="$(readelf -V "$bin")"
else
    echo "ERROR: neither objdump nor readelf is available" >&2
    exit 2
fi

versions="$(printf '%s\n' "$reqs" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -u -V)"
if [ -z "$versions" ]; then
    echo "OK: $bin has no GLIBC version requirements (statically linked?)"
    exit 0
fi

highest="$(printf '%s\n' "$versions" | tail -n1)"
newest_allowed="$(printf '%s\n%s\n' "$highest" "$max" | sort -V | tail -n1)"
if [ "$newest_allowed" != "$max" ]; then
    echo "ERROR: $bin requires GLIBC_$highest, newer than the supported floor GLIBC_$max" >&2
    echo "Symbols requiring versions above GLIBC_$max:" >&2
    printf '%s\n' "$versions" | while read -r v; do
        if [ "$(printf '%s\n%s\n' "$v" "$max" | sort -V | tail -n1)" != "$max" ]; then
            echo "  GLIBC_$v" >&2
        fi
    done
    exit 1
fi

echo "OK: $bin requires at most GLIBC_$highest (floor GLIBC_$max)"
