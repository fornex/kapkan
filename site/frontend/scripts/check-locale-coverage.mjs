// Fail the build when a slug the sidebar advertises has no page in some locale.
//
// Why this exists: lib/docs-nav.ts is locale-independent — one slug list for all
// five languages — and lib/i18n.ts gives every slug a title in every locale. Add
// a page in English only and the sidebar still shows a titled link in ru/de/fr/es;
// the route is generated, the MDX import misses, and the reader gets a
// "Page not found" shell behind a link that looked real. Nothing else catches it:
// the build succeeds and check-links only follows links whose target page exists.
//
// The gate is the pair the sidebar needs to be honest: for every slug in docsNav,
// a docs/<locale>/<slug>.mdx on disk and a pageTitles entry, in every locale.
// A group with no title is the same failure one level up.
//
// Run via the npm prebuild script (not predev, so a half-translated tree can
// still be previewed); cwd is site/frontend. Node built-ins only, and the two
// lib files are read as text rather than imported — they are TypeScript, and a
// regex scan keeps this script free of a transpile step.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const docsDir = resolve(process.cwd(), "../../docs"); // monorepo-root /docs, the source of truth
const navFile = resolve(process.cwd(), "lib/docs-nav.ts");
const i18nFile = resolve(process.cwd(), "lib/i18n.ts");

for (const f of [navFile, i18nFile]) {
  if (!existsSync(f)) {
    console.error(`[check-locale-coverage] not found: ${f}`);
    process.exit(1);
  }
}

const navSrc = readFileSync(navFile, "utf8");
const i18nSrc = readFileSync(i18nFile, "utf8");

/** The locales the site builds, from i18n's own list. */
const locales = [...(/export const locales = \[([^\]]*)\]/.exec(i18nSrc)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
  (m) => m[1],
);

/** Every group key and its slugs, from the locale-independent nav. */
const groups = [...navSrc.matchAll(/\{\s*key:\s*"([^"]+)",\s*slugs:\s*\[([^\]]*)\]\s*\}/g)].map(([, key, list]) => ({
  key,
  slugs: [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]),
}));

if (locales.length === 0 || groups.length === 0) {
  console.error("[check-locale-coverage] could not read the locales or the nav — has the shape of lib/ changed?");
  process.exit(1);
}

/**
 * The keys of one `Record<Locale, Record<string, string>>` export, per locale.
 * Returns a Map of locale -> Set of keys.
 */
function recordKeys(exportName) {
  const start = i18nSrc.indexOf(`export const ${exportName}`);
  if (start === -1) return new Map();
  // Up to the next top-level export, or the end of the file.
  const rest = i18nSrc.slice(start + 1);
  const end = rest.indexOf("\nexport const ");
  const body = end === -1 ? rest : rest.slice(0, end);
  const out = new Map();
  for (const loc of locales) {
    // `  ru: {` … the matching `\n  },` — the entries are one locale per block,
    // indented two spaces, which is how this file has always been written.
    const open = new RegExp(`\\n {2}${loc}: \\{`).exec(body);
    if (!open) continue;
    const from = open.index + open[0].length;
    const closeAt = body.indexOf("\n  },", from);
    const block = body.slice(from, closeAt === -1 ? undefined : closeAt);
    out.set(loc, new Set([...block.matchAll(/^\s*"?([A-Za-z0-9_-]+)"?:/gm)].map((m) => m[1])));
  }
  return out;
}

const pageTitles = recordKeys("pageTitles");
const groupTitles = recordKeys("groupTitles");

const problems = [];
for (const { key, slugs } of groups) {
  for (const loc of locales) {
    if (!groupTitles.get(loc)?.has(key)) {
      problems.push(`group "${key}": no ${loc} title in lib/i18n.ts groupTitles`);
    }
    for (const slug of slugs) {
      if (!existsSync(resolve(docsDir, loc, `${slug}.mdx`))) {
        problems.push(`slug "${slug}": docs/${loc}/${slug}.mdx is missing (the ${loc} sidebar would link to an empty page)`);
      }
      if (!pageTitles.get(loc)?.has(slug)) {
        problems.push(`slug "${slug}": no ${loc} title in lib/i18n.ts pageTitles`);
      }
    }
  }
}

const slugCount = groups.reduce((n, g) => n + g.slugs.length, 0);

if (problems.length > 0) {
  console.error(`[check-locale-coverage] ${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  console.error(
    "\nEvery slug in lib/docs-nav.ts is advertised in all locales. Add the missing page (or\n" +
      "take the slug out of the nav until its translations land).",
  );
  process.exit(1);
}

console.log(`[check-locale-coverage] ${slugCount} slugs × ${locales.length} locales, all present`);
