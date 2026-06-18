---
name: release
description: Build and publish the kapkan.io website to production. Use when the user asks to release, deploy, publish, or ship the site (or docs), or to manually trigger a release outside the automatic Stop hook. Builds the Next.js static export and pushes it to the BeAdmin host serving https://kapkan.io.
---

# Release kapkan.io

The site is a Next.js **static export** (`frontend/` → `out/`) served as plain files by
the nginx vhost on the BeAdmin host (docroot `/home/www/kapkan.io`). Releasing = build →
zip → upload through the panel's file API. No SSH. The whole thing lives in
[`deploy.sh`](../../../deploy.sh) at the repo root.

> Most releases happen **automatically**: the `Stop` hook
> (`.tooling/hooks/auto-release.sh`) runs `deploy.sh` whenever deployable sources changed
> and the build passes. Use this skill for an **on-demand** release, or after pausing the
> hook with `.tooling/release.disabled`.

## How to release

1. **Credentials.** `deploy.sh` reads `BEADMIN_URL`, `BEADMIN_EMAIL`, `BEADMIN_PASSWD`
   from the environment. They live in the gitignored `.tooling/release.env`. Run:

   ```bash
   set -a; . .tooling/release.env; set +a
   ./deploy.sh
   ```

   To redeploy the existing `frontend/out` without rebuilding, prepend `SKIP_BUILD=1`.
   For a pristine deploy that wipes the docroot first (reclaims stale `_next`
   chunks, or after doc slugs were removed — brief 404 window), prepend `CLEAN=1`.

2. **Watch the output.** `deploy.sh` builds (which type-checks and lints), clears the
   docroot, uploads, unzips, and verifies `GET https://kapkan.io/` returns `200`. It exits
   non-zero — and prints what failed — if the build breaks or the site does not come back
   `200`. Never report success unless you saw `==> Released: https://kapkan.io/`.

3. **Verify** a couple of routes after a notable change, e.g.:

   ```bash
   for u in / /docs/ /en/docs/introduction/ /ru/docs/introduction/; do
     curl -s -o /dev/null -w "%{http_code}  $u\n" "https://kapkan.io$u"
   done
   ```

## Notes

- `deploy.sh` records the released source hash in `.tooling/release-state.json` (via the
  shared `scripts/site-hash.sh`), so after a manual release the auto-release Stop hook sees
  no change and will not re-deploy the same state.
- The default deploy is **no-downtime**: it uploads and unzips over the live files (the panel
  unzip overwrites in place), then prunes stale top-level entries — the docroot is never
  emptied, and a mid-deploy failure leaves the old site intact.
- Pause auto-release: `touch .tooling/release.disabled`. Resume: `rm .tooling/release.disabled`.
- The full output of the last automatic run is in `.tooling/release.log`.
