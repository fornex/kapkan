#!/bin/sh
# Maintainer script run BEFORE remove and BEFORE the remove half of an upgrade,
# for BOTH .deb and .rpm. Tear the service down only on a *real* removal, never
# on an upgrade, so an `apt`/`dnf` upgrade does not stop mitigation:
#   dpkg passes "remove" on removal, "upgrade" on upgrade;
#   rpm  passes 0       on removal, 1         on upgrade.
set -e

case "${1:-}" in
remove | 0)
	if command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now kapkan >/dev/null 2>&1 || true
	fi
	;;
esac

exit 0
