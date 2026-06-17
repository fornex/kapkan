#!/usr/bin/env bash
#
# Build the static site and release it to the kapkan.io BeAdmin host.
#
# The site is a Next.js static export (frontend/ -> `out/`), served as plain
# files by the nginx vhost on the BeAdmin server (docroot /home/www/kapkan.io).
# Releasing = build -> zip -> push through the panel's file API. No SSH.
#
# Credentials are read from the environment so they never live in git. Set:
#   BEADMIN_URL     panel base URL, e.g. https://304443.fornex.cloud:8080
#   BEADMIN_EMAIL   panel login, e.g. admin@304443.fornex.cloud
#   BEADMIN_PASSWD  panel password
# Optional:
#   BEADMIN_SITE    web-root subdir to deploy into   (default: kapkan.io)
#   SKIP_BUILD=1    deploy the existing frontend/out without rebuilding
#   CLEAN=1         wipe the docroot first (pristine, but the site 404s for a
#                   moment) — use to reclaim stale _next chunks or after slugs
#                   were removed. Default deploys in place with no downtime.
#
# Usage:  BEADMIN_URL=... BEADMIN_EMAIL=... BEADMIN_PASSWD=... ./deploy.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API="${BEADMIN_URL:?set BEADMIN_URL}/api"
ORIGIN="${BEADMIN_URL}"
EMAIL="${BEADMIN_EMAIL:?set BEADMIN_EMAIL}"
PASSWD="${BEADMIN_PASSWD:?set BEADMIN_PASSWD}"
SITE="${BEADMIN_SITE:-kapkan.io}"

# -k: the panel on :8080 may present a cert curl doesn't trust; this only
# relaxes calls to the panel host, never the public-site verification below.
curl_api() { curl -sk -H "Origin: $ORIGIN" -H "Referer: $ORIGIN/" "$@"; }
# Abort unless the captured HTTP status is 2xx (curl -s exits 0 even on 5xx).
need2xx() { case "$1" in 2??) ;; *) echo "ERROR: $2 failed (HTTP $1)"; exit 1 ;; esac; }

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> Building static export (frontend/)"
  ( cd "$ROOT/frontend" && npm run build )
fi
[ -f "$ROOT/frontend/out/index.html" ] || { echo "ERROR: frontend/out is empty — build first"; exit 1; }

# Record the exact source tree being shipped (same hasher the Stop hook uses,
# so the auto-release marker can never drift from what is actually live).
SRC_HASH=""
[ -f "$ROOT/scripts/site-hash.sh" ] && SRC_HASH="$(bash "$ROOT/scripts/site-hash.sh" "$ROOT" 2>/dev/null || true)"

echo "==> Packaging frontend/out"
# Next writes metadata-route outputs (favicon.ico, icon.svg, apple-icon.png,
# opengraph-image.png, twitter-image.png) as mode 600. The nginx worker runs as
# a different user, so those files 403 on the live host while world-readable
# public/ assets serve fine. Normalize to a+rX before packaging so every file
# is served, regardless of how the build wrote it.
chmod -R a+rX "$ROOT/frontend/out"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ZIP="$TMP/release.zip"
( cd "$ROOT/frontend/out" && zip -rqX "$ZIP" . )
echo "    archive $(du -h "$ZIP" | cut -f1)"

echo "==> Authenticating to BeAdmin panel"
LOGIN="$TMP/login.json"
( umask 077; printf '{"email":"%s","passwd":"%s"}' "$EMAIL" "$PASSWD" > "$LOGIN" )
SID="$(curl_api "$API/login" -X POST -H 'Content-Type: application/json' --data @"$LOGIN" -D - -o /dev/null \
  | grep -i '^set-cookie:' | sed -E 's/.*BEADMINSESSION=([^;]+).*/\1/')"
rm -f "$LOGIN"
[ -n "$SID" ] || { echo "ERROR: login failed (check credentials)"; exit 1; }
CSRF="$(curl_api "$API/users/me" -H "Cookie: BEADMINSESSION=$SID" -D - -o /dev/null \
  | grep -i '^set-cookie:' | sed -E 's/.*BEADMINTOKEN_csrf=([^;]+).*/\1/')"
COOKIE="Cookie: BEADMINSESSION=$SID; BEADMINTOKEN_csrf=$CSRF"
AUTH=(-H "$COOKIE" -H "X-CSRF-Token: $CSRF")
WWW="$API/tools/files/www"

# Snapshot current top-level entries (to prune orphans after a successful swap).
BEFORE="$(curl_api "$WWW?cd=$SITE" -H "$COOKIE" | grep -oE '"name":"[^"]+"' | sed -E 's/"name":"(.*)"/\1/' || true)"

if [ "${CLEAN:-0}" = "1" ] && [ -n "$BEFORE" ]; then
  echo "==> CLEAN: wiping /$SITE first (brief downtime)"
  PAYLOAD="$(printf '%s\n' "$BEFORE" | sed '/^$/d' | sed -E "s#.*#\"$SITE/&\"#" | paste -sd, -)"
  code="$(curl_api "$WWW" -X DELETE "${AUTH[@]}" -H 'Content-Type: application/json' --data "[$PAYLOAD]" -o /dev/null -w '%{http_code}')"
  echo "    wipe [$code]"; need2xx "$code" "clean-wipe"
fi

echo "==> Uploading"
code="$(curl_api "$WWW/upload" -X POST "${AUTH[@]}" -F "path=$SITE" -F "file=@$ZIP" -o /dev/null -w '%{http_code}')"
echo "    upload [$code]"; need2xx "$code" "upload"

echo "==> Unzipping into /$SITE (overwrites in place — no empty window)"
code="$(curl_api "$WWW/unzip" -X PUT "${AUTH[@]}" -H 'Content-Type: application/json' --data "{\"file\":\"$SITE/release.zip\"}" -o /dev/null -w '%{http_code}')"
echo "    unzip [$code]"; need2xx "$code" "unzip"

echo "==> Cleanup (remove archive + stale top-level orphans)"
DROP="release.zip"
if [ "${CLEAN:-0}" != "1" ] && [ -n "$BEFORE" ]; then
  ORPH="$(printf '%s\n' "$BEFORE" | sed '/^$/d' | grep -vxF -f <(cd "$ROOT/frontend/out" && ls -1A) 2>/dev/null || true)"
  [ -n "$ORPH" ] && DROP="$DROP
$ORPH"
fi
PAYLOAD="$(printf '%s\n' "$DROP" | sed '/^$/d' | sort -u | sed -E "s#.*#\"$SITE/&\"#" | paste -sd, -)"
curl_api "$WWW" -X DELETE "${AUTH[@]}" -H 'Content-Type: application/json' --data "[$PAYLOAD]" -o /dev/null -w '    cleanup [%{http_code}]\n' || true

echo "==> Verifying https://$SITE/"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "https://$SITE/" || echo 000)"
echo "    GET / -> $CODE"
[ "$CODE" = "200" ] || { echo "ERROR: site did not return 200 after deploy"; exit 1; }

# Record what is now live so the auto-release Stop hook stays quiet next turn.
if [ -n "$SRC_HASH" ] && [ -d "$ROOT/.tooling" ]; then
  ( umask 077; printf '{"hash":"%s","released_at":"%s"}\n' "$SRC_HASH" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/.tooling/release-state.json" )
fi
echo "==> Released: https://$SITE/"
