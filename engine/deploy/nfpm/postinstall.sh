#!/bin/sh
# Maintainer script run AFTER install and AFTER upgrade, for BOTH the .deb and
# the .rpm (nfpm runs the same script for both). The package-manager argument in
# $1 differs across formats (dpkg passes "configure"/<old-version>; rpm passes
# 1 on install, 2 on upgrade), so this script avoids it entirely: every action
# is idempotent and keyed off observable state, not the argument.
set -e

USER=kapkan
GROUP=kapkan
CONF_DIR=/etc/kapkan
STATE_DIR=/var/lib/kapkan
CONFIG="$CONF_DIR/config.yaml"
EXAMPLE="$CONF_DIR/config.example.yaml"
ENVFILE="$CONF_DIR/kapkan.env"

# 1) The unprivileged system group + user the daemon runs as (the unit declares
#    User=kapkan / Group=kapkan). getent guards make this a no-op on upgrade.
if ! getent group "$GROUP" >/dev/null 2>&1; then
	groupadd --system "$GROUP"
fi
if ! getent passwd "$USER" >/dev/null 2>&1; then
	useradd --system --gid "$GROUP" --no-create-home \
		--home-dir "$STATE_DIR" --shell /usr/sbin/nologin \
		--comment "Kapkan DDoS mitigation daemon" "$USER"
fi

# 2) Directories. /etc/kapkan is root-owned (the unit mounts it read-only);
#    /var/lib/kapkan is the writable StateDirectory the daemon owns and uses for
#    ban.state_file. systemd also creates the latter via StateDirectory= on
#    start; creating it here makes the layout correct before the first start.
install -d -m 0755 "$CONF_DIR"
install -d -m 0700 -o "$USER" -g "$GROUP" "$STATE_DIR"

# 3) First install only: seed a runnable config from the shipped example
#    (dry_run is true in it, so nothing can be announced). Upgrades never touch
#    the operator's edited config — only config.example.yaml is replaced.
if [ ! -e "$CONFIG" ] && [ -e "$EXAMPLE" ]; then
	cp "$EXAMPLE" "$CONFIG"
	chown "$USER:$GROUP" "$CONFIG"
	chmod 0640 "$CONFIG"
fi

# 4) First install only: a restrictive, empty secrets env file. The unit loads
#    it optionally (EnvironmentFile=-...), so an empty file is fine.
if [ ! -e "$ENVFILE" ]; then
	cat > "$ENVFILE" <<'EOF'
# Kapkan secrets, loaded by the systemd unit (EnvironmentFile). Keep mode 0600.
# Add only the secrets you use; config.yaml references each by env-var name:
#   KAPKAN_API_TOKEN=...   # API bearer token            (api.token_env)
#   KAPKAN_TG_TOKEN=...    # Telegram bot token          (notify.telegram.token_env)
EOF
	chown "$USER:$GROUP" "$ENVFILE"
	chmod 0600 "$ENVFILE"
fi

# 5) systemd: reload unit files, then restart ONLY a service that is already
#    running (the upgrade-of-a-started-service case). A fresh install is left
#    stopped — we never auto-start a mitigation daemon before the operator has
#    reviewed the config — and we print how to start it.
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if systemctl is-active --quiet kapkan 2>/dev/null; then
		echo "kapkan: restarting the running service after upgrade"
		systemctl try-restart kapkan >/dev/null 2>&1 || true
	else
		cat <<'EOF'
kapkan installed. /etc/kapkan/config.yaml ships with dry_run ON (no routes are
announced). Review it, then start the service:
    sudo systemctl enable --now kapkan
Check it:
    systemctl status kapkan
    journalctl -u kapkan -f
EOF
	fi
fi

exit 0
