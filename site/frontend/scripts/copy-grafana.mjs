// Copy the canonical Grafana dashboard into public/ so the site serves it for
// direct download at https://kapkan.io/kapkan-overview.json. Source of truth is
// engine/deploy/grafana/; the copy in public/ is gitignored (regenerated at
// build, like the wasm assets). Run via predev/prebuild; cwd is site/frontend.
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";

const src = resolve(process.cwd(), "../../engine/deploy/grafana/kapkan-overview.json");
const dest = resolve(process.cwd(), "public/kapkan-overview.json");

if (!existsSync(src)) {
  console.error(`[copy-grafana] source not found: ${src}`);
  process.exit(1);
}

mkdirSync(dirname(dest), { recursive: true });
copyFileSync(src, dest);
console.log(`[copy-grafana] ${src} -> ${dest}`);
