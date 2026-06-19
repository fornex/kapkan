import type { Metadata } from "next";
import Link from "next/link";
import { locales, isLocale, defaultLocale, type Locale } from "@/lib/i18n";
import { wizardChrome } from "@/lib/wizard/strings";
import { site } from "@/lib/site";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";
import { ConfigWizard } from "@/components/ConfigWizard";

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
  const t = wizardChrome[loc];
  return {
    title: t.title,
    description: t.intro,
    alternates: { canonical: `/${loc}/config/` },
  };
}

export default async function ConfigPage({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  const loc: Locale = isLocale(lang) ? lang : defaultLocale;
  const t = wizardChrome[loc];

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-14 items-center justify-between border-b border-border px-6">
        <Logo href={`/${loc}/docs`} />
        <div className="flex items-center gap-4 text-sm">
          <Link
            href={`/${loc}/docs/configuration/`}
            className="text-muted-foreground hover:text-foreground"
          >
            {t.docsCta}
          </Link>
          <a
            href={site.repo}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground"
          >
            GitHub
          </a>
          <ThemeToggle />
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-10">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{t.title}</h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">{t.intro}</p>
        <p className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <span aria-hidden>🔒</span>
          {t.privacy}
        </p>

        <div className="mt-8">
          <ConfigWizard lang={loc} />
        </div>
      </main>
    </div>
  );
}
