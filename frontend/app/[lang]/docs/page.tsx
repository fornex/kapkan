import { locales } from "@/lib/i18n";
import { MetaRedirect } from "@/components/MetaRedirect";

// Static export needs the locale set up front; redirect each one.
export function generateStaticParams() {
  return locales.map((lang) => ({ lang }));
}
export const dynamicParams = false;

export default async function LocaleDocsIndex({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  return <MetaRedirect to={`/${lang}/docs/introduction/`} />;
}
