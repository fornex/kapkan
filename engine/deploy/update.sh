#!/usr/bin/env bash
# update.sh — safely upgrade a systemd-deployed kapkan to a signed release.
#
# Run as root on the kapkan host:
#     sudo ./update.sh v1.3.0          # upgrade to a specific tag
#     sudo ./update.sh                 # upgrade to the latest stable release
#
# It verifies the download (cosign signature + the asset's own SHA-256 line),
# preflights the NEW binary against the LIVE config as the kapkan user (catching
# schema drift before any swap), snapshots the config, swaps the binary
# atomically (keeping the previous one), restarts, and rolls BOTH the binary and
# the config back if /healthz does not report ready. Active mitigation survives
# the restart via BGP Graceful Restart + ban rehydration, so there is no
# "wait for zero bans" gate.
#
# Overridable via env: KAPKAN_REPO, KAPKAN_BIN, KAPKAN_CONFIG, KAPKAN_ENVFILE,
# KAPKAN_SERVICE, KAPKAN_USER, KAPKAN_HEALTH_URL, KAPKAN_HEALTH_DEADLINE.
set -euo pipefail

REPO="${KAPKAN_REPO:-fornex/kapkan}"
BIN="${KAPKAN_BIN:-/usr/local/bin/kapkan}"
CONFIG="${KAPKAN_CONFIG:-/etc/kapkan/config.yaml}"
ENVFILE="${KAPKAN_ENVFILE:-/etc/kapkan/kapkan.env}"
SERVICE="${KAPKAN_SERVICE:-kapkan}"
RUNUSER="${KAPKAN_USER:-kapkan}"
# Health deadline defaults to 60s — comfortably above worst-case startup
# (large GeoIP database + rehydrating/re-announcing many persisted bans), so a
# legitimately slow start is not mistaken for a failure. Raise it for very large
# deployments.
HEALTH_DEADLINE="${KAPKAN_HEALTH_DEADLINE:-60}"
CHANNEL="stable"

COSIGN_IDENTITY_RE="https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v.*"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --channel) CHANNEL="${2:?--channel needs a value}"; shift 2 ;;
    --prerelease) CHANNEL="prerelease"; shift ;;
    -*) die "unknown flag: $1" ;;
    *) VERSION="$1"; shift ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (it writes ${BIN} and restarts the service)"

for c in curl cosign sha256sum tar install runuser systemctl uname mktemp; do
  command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m) (releases ship linux amd64/arm64)" ;;
esac

# Health probe URL: honor an explicit override, else derive host:port from the
# live config's api.listen (the only line under api: that carries an inline
# value — the top-level listen: block has none), rewriting a wildcard bind to
# loopback for the local probe.
if [ -n "${KAPKAN_HEALTH_URL:-}" ]; then
  HEALTH_URL="$KAPKAN_HEALTH_URL"
else
  api_listen="$(grep -vE '^[[:space:]]*#' "$CONFIG" 2>/dev/null \
    | grep -oE '^[[:space:]]+listen:[[:space:]]*"?[^"#[:space:]]+' | head -1 \
    | sed -E 's/.*listen:[[:space:]]*"?//')" || true
  if [ -n "$api_listen" ]; then
    hhost="${api_listen%:*}"; hport="${api_listen##*:}"
    case "$hhost" in ""|"0.0.0.0"|"::"|"[::]") hhost="127.0.0.1" ;; esac
    HEALTH_URL="http://${hhost}:${hport}/healthz"
  else
    HEALTH_URL="http://127.0.0.1:8080/healthz"
    warn "could not read api.listen from ${CONFIG}; probing ${HEALTH_URL} (override with KAPKAN_HEALTH_URL)"
  fi
fi

# Resolve the target version from the releases API when not given.
if [ -z "$VERSION" ]; then
  log "resolving the latest ${CHANNEL} release of ${REPO}"
  if [ "$CHANNEL" = "prerelease" ]; then
    api="https://api.github.com/repos/${REPO}/releases?per_page=10"
  else
    api="https://api.github.com/repos/${REPO}/releases/latest"
  fi
  VERSION="$(curl -fsSL -H 'Accept: application/vnd.github+json' "$api" \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[^"]*"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || die "could not determine the latest release tag"
fi
case "$VERSION" in v*) ;; *) die "version must be a tag like v1.3.0, got: $VERSION" ;; esac

CURRENT="$("$BIN" -version 2>/dev/null | awk '{print $2}')" || CURRENT="(unknown)"
log "current: ${CURRENT}    target: ${VERSION}    arch: linux/${ARCH}    probe: ${HEALTH_URL}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# World-traversable so the preflight (run as the kapkan user) can reach the
# staged binary; the contents are public release artifacts, nothing secret.
chmod 0755 "$WORK"
cd "$WORK"

ASSET="kapkan_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
log "downloading ${ASSET} + checksums"
curl -fsSL -o "$ASSET" "${BASE}/${ASSET}"
curl -fsSL -o checksums.txt "${BASE}/checksums.txt"
curl -fsSL -o checksums.txt.sig "${BASE}/checksums.txt.sig"
curl -fsSL -o checksums.txt.pem "${BASE}/checksums.txt.pem"
[ -s checksums.txt ] || die "checksums.txt is empty"

log "verifying the cosign signature over checksums.txt"
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
  --certificate-oidc-issuer "$COSIGN_ISSUER" \
  >/dev/null || die "signature verification FAILED — refusing to install ${ASSET}"

# Verify the asset's OWN line (fail closed if it is absent — never let
# --ignore-missing-style behavior pass an unlisted/renamed tarball).
log "verifying the SHA-256 of ${ASSET}"
grep -F " ${ASSET}" checksums.txt > asset.sum || die "checksums.txt has no entry for ${ASSET}"
sha256sum -c asset.sum || die "checksum verification FAILED for ${ASSET}"

tar xzf "$ASSET"
NEWBIN="${WORK}/kapkan"
[ -x "$NEWBIN" ] || die "archive did not contain an executable 'kapkan'"
NEWVER="$("$NEWBIN" -version | awk '{print $2}')"
log "new binary reports version: ${NEWVER}"

# Preflight: validate the LIVE config with the NEW binary, AS the kapkan user,
# so schema drift and files the daemon cannot read are caught BEFORE any swap.
# (-check-config validates structure + cross-field rules, not secret values.)
log "preflighting the new binary against ${CONFIG}"
install -m 0755 "$NEWBIN" "$WORK/kapkan.checked"
runuser -u "$RUNUSER" -- "$WORK/kapkan.checked" -check-config "$CONFIG" \
  || die "the new binary REJECTED ${CONFIG} — not upgrading; the running daemon is untouched. Fix the config (see the release's config-change notes) and retry."

# Best-effort heads-up: warn (do NOT block) if an ACTIVE config line references
# an env var that is not defined in the env file — the daemon fails closed on an
# empty token, but the operator should know. Reads KEY=VALUE literally (never
# sources the file, so a value containing shell metacharacters cannot execute).
env_defined() { [ -r "$ENVFILE" ] && grep -qE "^[[:space:]]*${1}=" "$ENVFILE"; }
env_refs="$(grep -vE '^[[:space:]]*#' "$CONFIG" 2>/dev/null \
  | grep -oE '[a-z_]+_env:[[:space:]]*"?[A-Z_][A-Z0-9_]*' \
  | sed -E 's/.*[[:space:]"]([A-Z_][A-Z0-9_]*)$/\1/' | sort -u || true)"
while IFS= read -r var; do
  [ -n "$var" ] || continue
  env_defined "$var" || warn "config references \$${var} but it is not set in ${ENVFILE} (that channel/token will be inactive)"
done <<EOF
${env_refs}
EOF

# Snapshot the config so rollback can restore binary AND config together.
SNAP="${CONFIG}.preupgrade"
cp -a "$CONFIG" "$SNAP"

# Atomic swap: copy the current binary aside FIRST (so a valid binary always
# exists), stage the new one in the same directory, then a single rename(2)
# moves it into place — there is no window where ${BIN} is missing.
log "installing ${VERSION} to ${BIN} (previous kept at ${BIN}.old)"
DIR="$(dirname "$BIN")"
cp -a "$BIN" "${BIN}.old"
TMPBIN="$(mktemp "${DIR}/.kapkan.new.XXXXXX")"
install -m 0755 "$NEWBIN" "$TMPBIN"
mv -f "$TMPBIN" "$BIN"

rollback() {
  warn "rolling back to ${CURRENT}"
  [ -f "${BIN}.old" ] && cp -a "${BIN}.old" "$BIN" || true
  cp -a "$SNAP" "$CONFIG" 2>/dev/null || true
  if runuser -u "$RUNUSER" -- "$BIN" -check-config "$CONFIG" >/dev/null 2>&1; then
    systemctl restart "$SERVICE" || true
    die "upgrade to ${VERSION} failed health-check; rolled back to ${CURRENT} and restarted."
  fi
  die "upgrade to ${VERSION} failed AND the restored config is invalid for ${CURRENT}; the service was NOT restarted. Restore a known-good ${CONFIG} and run: systemctl restart ${SERVICE}"
}

log "restarting ${SERVICE}"
systemctl restart "$SERVICE" || { warn "systemctl restart failed"; rollback; }

# Health-check: poll /healthz (200 only once fully started). Roll back early if
# the unit latches 'failed' (crash-loop guard tripped), else wait the deadline.
log "waiting up to ${HEALTH_DEADLINE}s for ${HEALTH_URL} to report ready"
deadline=$(( $(date +%s) + HEALTH_DEADLINE ))
healthy=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if systemctl is-failed --quiet "$SERVICE"; then
    warn "service entered the failed state"
    break
  fi
  if curl -fsS -o /dev/null --max-time 3 "$HEALTH_URL"; then healthy=1; break; fi
  sleep 1
done

[ "$healthy" -eq 1 ] || rollback

log "upgrade complete: ${CURRENT} -> ${VERSION}. Previous binary kept at ${BIN}.old, previous config at ${SNAP}."
