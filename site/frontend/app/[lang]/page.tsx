import type { Metadata } from "next";
import { locales, isLocale, defaultLocale, type Locale } from "@/lib/i18n";
import { landing } from "@/lib/landing-i18n";
import { Landing } from "@/components/Landing";

export function generateStaticParams() {
  return locales.map((lang) => ({ lang }));
}
export const dynamicParams = false;

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang } = await params;
  const loc: Locale = isLocale(lang) ? lang : defaultLocale;
  const t = landing[loc];
  return {
    title: { absolute: t.meta.title },
    description: t.meta.description,
    // "/" is the primary English landing; /en/ points back to it.
    alternates: { canonical: loc === "en" ? "/" : `/${loc}/` },
  };
}

export default async function LocalizedHome({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  const loc: Locale = isLocale(lang) ? lang : defaultLocale;
  return <Landing locale={loc} basePath={`/${loc}`} />;
}
