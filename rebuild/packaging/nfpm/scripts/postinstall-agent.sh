#!/bin/sh
# postinstall-agent.sh - create the dedicated system account rpingmesh-agent
# runs as, and reload systemd so it picks up the newly-installed unit.
#
# Runs on both fresh install and upgrade (deb: "configure", rpm: arg 1 or 2).
# It deliberately does NOT enable or start the service: rpingmesh-agent.yaml
# ships only as an .example (tor_id has no default), so an unconfigured
# service would just crash-loop. See rebuild/README.md "Deployment (systemd)"
# for the manual enable/start steps.
set -e

if ! getent group rpingmesh >/dev/null 2>&1; then
    groupadd --system rpingmesh
fi

if ! getent passwd rpingmesh >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid rpingmesh rpingmesh
fi

# /dev/infiniband/* device nodes are typically owned by a distro-provided
# "rdma" group (created by the rdma-core package's udev rules), not by
# rpingmesh. Join it if present; if this host's rdma-core hasn't created it
# yet (or uses ACLs instead), this is a no-op -- see the AmbientCapabilities
# / SupplementaryGroups comment in packaging/systemd/rpingmesh-agent.service.
if getent group rdma >/dev/null 2>&1; then
    usermod -a -G rdma rpingmesh || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
