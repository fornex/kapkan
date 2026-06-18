#!/usr/bin/env bash
# Stop hook for the kapkan.io site repo — automatic release on every change.
#
# After each turn: if the deployable site sources changed since the last
# release AND the production build succeeds, this publishes the site to
# https://kapkan.io via ./deploy.sh. Otherwise it stays completely silent.
#
# "Deployable sources" = frontend/{app,content,components,lib,public} plus the
# build-affecting config files (see scripts/site-hash.sh). Docs live under
# frontend/content/docs, so a /sync-docs run is picked up here too.
#
# Design rules (mirrors docs-sync-check.sh):
#   * ALWAYS exits 0 — never blocks the turn from ending.
#   * Silent when there is nothing to release.
#   * Credentials come from .tooling/release.env (gitignored), never from git.
#   * Pause anytime by creating .tooling/release.disabled.
#
# Gitignored side-files it manages:
#   .tooling/release-state.json   last released source hash (also written by deploy.sh)
#   .tooling/release.log          full build+deploy output of the last run (mode 600)
#   .tooling/.release.lock        self-healing single-flight lock (dir + pid file)
#   .tooling/release.disabled     kill-switch (presence = paused)

set -uo pipefail

# --- read stdin; bail if we are already inside a stop-hook continuation -------
INPUT="$(cat 2>/dev/null || true)"
case "$INPUT" in
  *'"stop_hook_active":true'*|*'"stop_hook_active": true'*) exit 0 ;;
esac

# --- locate the project root --------------------------------------------------
ROOT="${tooling_PROJECT_DIR:-}"
if [ -z "$ROOT" ] || [ ! -d "$ROOT/.tooling" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
fi
[ -n "$ROOT" ] && [ -d "$ROOT/frontend" ] || exit 0

CLA="$ROOT/.tooling"
STATE="$CLA/release-state.json"
LOG="$CLA/release.log"
LOCK="$CLA/.release.lock"
HASHER="$ROOT/scripts/site-hash.sh"

# --- guards -------------------------------------------------------------------
[ -f "$CLA/release.disabled" ] && exit 0   # paused by the user
[ -f "$CLA/release.env" ]      || exit 0   # no credentials → cannot release
[ -f "$HASHER" ]               || exit 0   # no hasher → cannot detect changes

umask 077   # release.log / release-state.json are created owner-only

# --- has anything deployable changed since the last release? ------------------
CUR="$(bash "$HASHER" "$ROOT" 2>/dev/null || true)"
[ -n "$CUR" ] || exit 0
PREV="$(sed -n 's/.*"hash"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATE" 2>/dev/null | head -1)"
[ "$CUR" = "$PREV" ] && exit 0             # nothing changed → stay quiet

# --- self-healing single-flight lock ------------------------------------------
# A bare mkdir lock would wedge releases forever if the hook is ever killed
# (SIGKILL / timeout) mid-run. Reclaim the lock if its owner died or it is old.
if mkdir "$LOCK" 2>/dev/null; then
  echo $$ > "$LOCK/pid"
else
  oldpid="$(cat "$LOCK/pid" 2>/dev/null || true)"
  stale=0
  [ -z "$oldpid" ] && stale=1
  { [ -n "$oldpid" ] && ! kill -0 "$oldpid" 2>/dev/null; } && stale=1
  # NB: find exits 0 even on no match — test its OUTPUT, not its exit code.
  [ -n "$(find "$LOCK" -maxdepth 0 -mmin +20 2>/dev/null)" ] && stale=1
  [ "$stale" = "1" ] || exit 0             # a release is genuinely running
  rm -rf "$LOCK" 2>/dev/null || true
  mkdir "$LOCK" 2>/dev/null || exit 0
  echo $$ > "$LOCK/pid"
fi
trap 'rm -rf "$LOCK" 2>/dev/null || true' EXIT INT TERM HUP

# --- credentials + a sane PATH for node/npm -----------------------------------
set -a; . "$CLA/release.env"; set +a
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

# --- build + deploy -----------------------------------------------------------
rm -f "$LOG"; : > "$LOG"   # recreate under umask 077 so the log is owner-only
printf '=== auto-release %s ===\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
if [ "${RELEASE_DRY_RUN:-0}" = "1" ]; then
  printf '(dry-run) deployable change detected; would run ./deploy.sh\n' >> "$LOG"
  rc=0
  printf '{"hash":"%s","released_at":"%s"}\n' "$CUR" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE"
else
  ( cd "$ROOT" && bash ./deploy.sh ) >> "$LOG" 2>&1
  rc=$?
  # deploy.sh records the marker on success; mirror it here so the hook path is
  # robust even if that write was skipped (prevents a redeploy loop).
  [ "$rc" = "0" ] && printf '{"hash":"%s","released_at":"%s"}\n' "$CUR" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE"
fi

# Single-line, pure-printable-ASCII, quote-free → always valid JSON. Mask the
# panel URL / e-mail so they never reach the transcript via a failure tail.
esc()  { printf '%s' "$1" | LC_ALL=C tr -s '[:cntrl:]' ' ' | LC_ALL=C tr -cd '\40-\176' | tr -d '"\\'; }
mask() { sed -E 's#https?://[^[:space:]]+#<panel>#g; s#[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+#<email>#g'; }

if [ "$rc" = "0" ]; then
  printf '{"systemMessage":"%s","suppressOutput":true}\n' "✅ Auto-released kapkan.io"
else
  line="$(tail -n 4 "$LOG" | mask)"
  printf '{"systemMessage":"%s","suppressOutput":true}\n' \
    "⚠️ Auto-release FAILED (rc=$rc) — will retry next turn. $(esc "$line") (log: .tooling/release.log)"
fi
exit 0
