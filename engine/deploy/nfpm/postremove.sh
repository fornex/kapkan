#!/bin/sh
# Maintainer script run AFTER remove/upgrade for both formats. Always reload
# systemd so the removed unit is forgotten. On a Debian *purge* (rpm has no
# purge concept) also drop the state, config and the system user, matching the
# "remove every trace" contract of `apt purge`.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "${1:-}" = purge ]; then
	rm -rf /var/lib/kapkan /etc/kapkan
	if getent passwd kapkan >/dev/null 2>&1; then
		userdel kapkan >/dev/null 2>&1 || true
	fi
	if getent group kapkan >/dev/null 2>&1; then
		groupdel kapkan >/dev/null 2>&1 || true
	fi
fi

exit 0
