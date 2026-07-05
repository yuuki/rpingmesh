#!/bin/sh
# postinstall-controller.sh - create the dedicated system account
# rpingmesh-controller runs as, and reload systemd so it picks up the
# newly-installed unit.
#
# Runs on both fresh install and upgrade (deb: "configure", rpm: arg 1 or 2).
# It deliberately does NOT enable or start the service: controller.yaml
# ships only as an .example, so an unconfigured service would fail to reach
# rqlite. See rebuild/README.md "Deployment (systemd)" for the manual
# enable/start steps.
set -e

if ! getent group rpingmesh >/dev/null 2>&1; then
    groupadd --system rpingmesh
fi

if ! getent passwd rpingmesh >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid rpingmesh rpingmesh
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
