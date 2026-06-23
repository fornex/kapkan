// Sidebar structure: the order of groups and the slugs within each. Display
// titles (group + page) are resolved per locale from lib/i18n.ts; this file
// only carries the language-agnostic structure and slug ordering.

export type DocGroup = {
  key: string;
  slugs: string[];
};

export const docsNav: DocGroup[] = [
  { key: "getting-started", slugs: ["introduction", "quickstart", "how-it-works", "cli"] },
  { key: "configuration", slugs: ["configuration", "detection", "hostgroups", "baselines"] },
  { key: "mitigation", slugs: ["mitigation", "flowspec", "scrubbing", "escalation", "safety", "going-live"] },
  { key: "operating", slugs: ["api", "dashboard", "authentication", "multi-tenancy", "audit", "notifications", "metrics", "storage"] },
  { key: "deployment", slugs: ["deployment", "upgrading"] },
];

// Flat slug list in sidebar order — used for prev/next and static params.
export const flatSlugs: string[] = docsNav.flatMap((g) => g.slugs);

export function docHref(lang: string, slug: string): string {
  return `/${lang}/docs/${slug}`;
}
