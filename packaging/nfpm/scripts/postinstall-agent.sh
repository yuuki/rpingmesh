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
# "rdma" group (created by the rdma-core package's udev rules). The unit
# file (packaging/systemd/rpingmesh-agent.service) statically declares
# SupplementaryGroups=rdma, and systemd refuses to even *start* a unit whose
# SupplementaryGroups name doesn't resolve to an existing group -- so this
# group must exist unconditionally after this package is installed. Create
# it if rdma-core hasn't already (harmless if it races with rdma-core's own
# udev-triggered group creation; getent re-checks right before use).
if ! getent group rdma >/dev/null 2>&1; then
    groupadd --system rdma || true
fi
usermod -a -G rdma rpingmesh || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
