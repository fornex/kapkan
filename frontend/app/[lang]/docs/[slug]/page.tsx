import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { locales, isLocale } from "@/lib/i18n";
import { flatSlugs } from "@/lib/docs-nav";

type Params = { lang: string; slug: string };

// Pre-render every locale × page at build time.
export function generateStaticParams() {
  return locales.flatMap((lang) => flatSlugs.map((slug) => ({ lang, slug })));
}

// Only the locale/slug pairs above are valid; anything else 404s.
export const dynamicParams = false;

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang, slug } = await params;
  try {
    const mod = await import(`@/content/docs/${lang}/${slug}.mdx`);
    return (mod.metadata as Metadata) ?? {};
  } catch {
    return {};
  }
}

export default async function DocPage({ params }: { params: Promise<Params> }) {
  const { lang, slug } = await params;
  if (!isLocale(lang) || !flatSlugs.includes(slug)) notFound();

  let Doc: React.ComponentType;
  try {
    ({ default: Doc } = await import(`@/content/docs/${lang}/${slug}.mdx`));
  } catch {
    notFound();
  }
  return <Doc />;
}
