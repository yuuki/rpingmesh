#!/bin/sh
# preremove-agent.sh - stop and disable the agent service, but only on a
# genuine removal -- never on an upgrade, where the old package's preremove
# script runs *before* the new package's files are unpacked. Stopping the
# unit here would leave a monitoring service down until an operator noticed
# and manually restarted it after the upgrade.
#
# deb (prerm) and rpm (%preun) signal "is this an upgrade?" differently, and
# this script has to disambiguate both from a single $1:
#   - deb passes "remove" for a genuine uninstall, and "upgrade <new-version>"
#     (so $1="upgrade") when this is the *old* version's prerm running as
#     part of an in-place upgrade -- see dpkg-deb(1) / Debian policy manual
#     section 6.5, "Summary of ways maintainer scripts are called".
#     "failed-upgrade" is the recovery path if the new package's preinst
#     later fails; treated the same as "upgrade" (don't stop).
#   - rpm passes the *count of package versions that will remain installed
#     after this operation* as $1: "0" on a genuine erase, ">=1" during an
#     upgrade (the incoming version is already counted) -- see rpm(8),
#     "Scriptlets".
set -e

action="$1"

# Default to stopping (matches deb's "remove" and any packager not handled
# below, e.g. apk which doesn't distinguish upgrade from remove here).
should_stop=yes

case "$action" in
    upgrade | failed-upgrade)
        # deb: old version's prerm during an upgrade -- leave it running so
        # the incoming version's unit keeps serving without a gap.
        should_stop=no
        ;;
    remove)
        # deb: genuine removal.
        should_stop=yes
        ;;
    '' | *[!0-9]*)
        # Not a plain non-negative integer, and not one of the deb strings
        # above -- fall through with the "remove" default.
        ;;
    *)
        # rpm: $1 is numeric. 0 = erase, >=1 = upgrade in progress.
        if [ "$action" -ge 1 ]; then
            should_stop=no
        fi
        ;;
esac

if [ "$should_stop" = yes ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop rpingmesh-agent.service || true
    systemctl disable rpingmesh-agent.service || true
fi

exit 0
