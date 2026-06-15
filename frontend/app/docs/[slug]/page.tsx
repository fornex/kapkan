import { defaultLocale } from "@/lib/i18n";
import { flatSlugs } from "@/lib/docs-nav";
import { MetaRedirect } from "@/components/MetaRedirect";

// Static export needs the slug set up front; redirect each known slug.
export function generateStaticParams() {
  return flatSlugs.map((slug) => ({ slug }));
}
export const dynamicParams = false;

// Bare /docs/<slug> → default-locale version. Keeps pre-i18n links working.
export default async function DocsSlugRedirect({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return <MetaRedirect to={`/${defaultLocale}/docs/${slug}/`} />;
}
