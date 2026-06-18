#!/usr/bin/env bash
# SessionStart hook for the kapkan.io site repo.
#
# Reminds you to update the documentation when the Kapkan PRODUCT repo has moved
# ahead of the commit the docs were last synced to. The docs live in this repo
# (frontend/content/docs/<lang>); the product is a separate repo. When they
# drift, run /sync-docs.
#
# Design: always exits 0 (never blocks a session) and stays SILENT when the docs
# are in sync. Dependency-light: git + sed + tr only.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
state="$repo_root/.tooling/docs-sync-state.json"
[ -f "$state" ] || exit 0

# Pull product_repo and synced_commit out of the JSON without jq.
product="$(sed -n 's/.*"product_repo"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state" | head -1)"
synced="$(sed -n 's/.*"synced_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state" | head -1)"
product="${product/#\~/$HOME}"   # expand a leading ~

[ -n "$product" ] && [ -d "$product/.git" ] || exit 0
[ -n "$synced" ] || exit 0
git -C "$product" cat-file -e "${synced}^{commit}" 2>/dev/null || exit 0

head_short="$(git -C "$product" rev-parse --short HEAD 2>/dev/null)" || exit 0

if git -C "$product" merge-base --is-ancestor "$synced" HEAD 2>/dev/null; then
  count="$(git -C "$product" rev-list --count "${synced}..HEAD" 2>/dev/null || echo 0)"
else
  count="?"   # history diverged/rewritten — surface it anyway
fi
[ "$count" = "0" ] && exit 0   # in sync → stay quiet

commits="$(git -C "$product" log --format='%h %s' "${synced}..HEAD" 2>/dev/null | head -10 | tr -d '"\\' | tr '\n' ';')"
msg="Kapkan docs sync check: the product repo ($product) is $count commit(s) ahead of the last docs sync (${synced}..${head_short}). The documentation under frontend/content/docs (en/ru/de/fr/es) may be missing new features. Run /sync-docs to bring all languages up to date. New commits since last sync: ${commits}"
msg="$(printf '%s' "$msg" | tr -d '"\\')"   # keep the JSON string valid

printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$msg"
exit 0
