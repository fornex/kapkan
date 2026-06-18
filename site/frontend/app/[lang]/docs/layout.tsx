import { notFound } from "next/navigation";
import { isLocale } from "@/lib/i18n";
import { DocsChrome } from "@/components/docs/DocsChrome";

export default async function DocsLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();
  return <DocsChrome lang={lang}>{children}</DocsChrome>;
}
