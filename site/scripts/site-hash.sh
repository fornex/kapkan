#!/usr/bin/env bash
# Canonical content hash of the deployable site sources.
#
# Single source of truth shared by the auto-release Stop hook (change detection)
# and deploy.sh (records exactly what shipped) so the two can never disagree —
# even on macOS's old bash 3.2. Paths are hashed RELATIVE to frontend/, so the
# digest is independent of where the repo lives on disk.
#
# Usage: site-hash.sh [PROJECT_ROOT]   (defaults to the repo root above this file)
set -uo pipefail

ROOT="${1:-}"
[ -n "$ROOT" ] || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
cd "$ROOT/frontend" 2>/dev/null || exit 0

{
  # Deployable source trees (skip editor/OS junk that never affects the build).
  # content/ is omitted: it is a build-time copy of the canonical top-level docs/.
  find app components lib public -type f \
    ! -name '.DS_Store' ! -name 'Thumbs.db' ! -name '*.swp' ! -name '*~' ! -name '.#*' \
    -print0 2>/dev/null
  # Canonical user-facing docs live at the monorepo-root docs/ (../../docs from
  # site/frontend); they render into the site, so a docs change must redeploy.
  find ../../docs -type f \
    ! -name '.DS_Store' ! -name 'Thumbs.db' ! -name '*.swp' ! -name '*~' ! -name '.#*' \
    -print0 2>/dev/null
  # Build-affecting config files at the frontend root.
  for f in mdx-components.tsx next.config.ts package.json package-lock.json \
           tsconfig.json postcss.config.mjs eslint.config.mjs; do
    [ -f "$f" ] && printf '%s\0' "$f"
  done
} | LC_ALL=C sort -z | xargs -0 shasum -a 256 2>/dev/null | shasum -a 256 | awk '{print $1}'
