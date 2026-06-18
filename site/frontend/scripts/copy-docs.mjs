// Copy the monorepo's canonical docs/ into frontend/content/docs so Next can
// render them. Turbopack + output:export cannot import MDX from outside the
// frontend root, so the docs are mirrored in at build/dev time (the copy target
// content/docs is gitignored — docs/ is the single source of truth).
//
// Run via npm pre-scripts (predev/prebuild); cwd is site/frontend.
import { cpSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const src = resolve(process.cwd(), "../../docs"); // monorepo-root /docs
const dest = resolve(process.cwd(), "content/docs"); // site/frontend/content/docs

if (!existsSync(src)) {
  console.error(`[copy-docs] source not found: ${src}`);
  process.exit(1);
}

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });
console.log(`[copy-docs] ${src} -> ${dest}`);
