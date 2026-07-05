#!/bin/sh
# preremove-agent.sh - stop and disable the service before its unit file is
# removed. Runs on both uninstall and upgrade; on upgrade the postinstall
# script of the new package version re-triggers systemd's daemon-reload, but
# does not re-enable/restart the service (see postinstall-agent.sh), so an
# operator who had it running must restart it manually after an upgrade.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop rpingmesh-agent.service || true
    systemctl disable rpingmesh-agent.service || true
fi

exit 0
