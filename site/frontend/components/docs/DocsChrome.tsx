"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { docsNav, flatSlugs, docHref } from "@/lib/docs-nav";
import { site } from "@/lib/site";
import {
  type Locale,
  locales,
  localeNames,
  docsLabel,
  ui,
  groupTitles,
  pageTitles,
} from "@/lib/i18n";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";

function SidebarNav({ lang, onNavigate }: { lang: Locale; onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav className="space-y-7">
      {docsNav.map((group) => (
        <div key={group.key}>
          <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {groupTitles[lang][group.key]}
          </p>
          <ul className="space-y-0.5">
            {group.slugs.map((slug) => {
              const href = docHref(lang, slug);
              const active = pathname === href;
              return (
                <li key={slug}>
                  <Link
                    href={href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={
                      "block rounded-md px-2 py-1.5 text-sm transition-colors " +
                      (active
                        ? "bg-muted font-medium text-foreground"
                        : "text-muted-foreground hover:bg-muted/60 hover:text-foreground")
                    }
                  >
                    {pageTitles[lang][slug]}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function PrevNext({ lang }: { lang: Locale }) {
  const pathname = usePathname();
  const index = flatSlugs.findIndex((slug) => docHref(lang, slug) === pathname);
  if (index === -1) return null;
  const prev = index > 0 ? flatSlugs[index - 1] : null;
  const next = index < flatSlugs.length - 1 ? flatSlugs[index + 1] : null;
  if (!prev && !next) return null;
  return (
    <div className="mt-16 grid grid-cols-1 gap-3 border-t border-border pt-6 sm:grid-cols-2">
      {prev ? (
        <Link
          href={docHref(lang, prev)}
          className="rounded-lg border border-border p-4 transition-colors hover:bg-muted"
        >
          <span className="text-xs text-muted-foreground">{ui[lang].previous}</span>
          <span className="mt-1 block font-medium text-foreground">{pageTitles[lang][prev]}</span>
        </Link>
      ) : (
        <span />
      )}
      {next ? (
        <Link
          href={docHref(lang, next)}
          className="rounded-lg border border-border p-4 text-right transition-colors hover:bg-muted"
        >
          <span className="text-xs text-muted-foreground">{ui[lang].next}</span>
          <span className="mt-1 block font-medium text-foreground">{pageTitles[lang][next]}</span>
        </Link>
      ) : (
        <span />
      )}
    </div>
  );
}

function LanguageSwitcher({ lang }: { lang: Locale }) {
  const pathname = usePathname();
  const router = useRouter();

  function onChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const next = e.target.value;
    const parts = pathname.split("/");
    parts[1] = next; // swap the leading locale segment
    router.push(parts.join("/"));
  }

  return (
    <label className="flex items-center">
      <span className="sr-only">{ui[lang].language}</span>
      <select
        value={lang}
        onChange={onChange}
        aria-label={ui[lang].language}
        className="rounded-md border border-border bg-background px-2 py-1 text-sm text-muted-foreground hover:text-foreground focus:outline-none focus:ring-1 focus:ring-accent"
      >
        {locales.map((l) => (
          <option key={l} value={l}>
            {localeNames[l]}
          </option>
        ))}
      </select>
    </label>
  );
}

export function DocsChrome({ lang, children }: { lang: Locale; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);

  // Reflect the active locale on the document for accessibility/SEO.
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-screen-xl items-center gap-3 px-4 sm:px-6">
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
            className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground lg:hidden"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M3 6h18M3 12h18M3 18h18" />
            </svg>
          </button>
          <Logo href="/" label={docsLabel} />
          <div className="ml-auto flex items-center gap-3 text-sm">
            <LanguageSwitcher lang={lang} />
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
        </div>
      </header>

      <div className="mx-auto flex max-w-screen-xl">
        {/* Desktop sidebar */}
        <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-64 shrink-0 overflow-y-auto border-r border-border px-4 py-8 lg:block">
          <SidebarNav lang={lang} />
        </aside>

        {/* Mobile drawer */}
        {open ? (
          <div className="fixed inset-0 z-50 lg:hidden">
            <div
              className="absolute inset-0 bg-black/40"
              onClick={() => setOpen(false)}
              aria-hidden="true"
            />
            <div className="absolute left-0 top-0 h-full w-72 overflow-y-auto border-r border-border bg-background px-4 py-6">
              <div className="mb-6 flex items-center justify-between">
                {/* Plain brand label, not a link — the top bar already has the
                    home link; a second same-target link in the open drawer is a
                    needless duplicate for keyboard/screen-reader users. */}
                <Logo label={docsLabel} />
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  aria-label="Close navigation"
                  className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                    <path d="M18 6 6 18M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <SidebarNav lang={lang} onNavigate={() => setOpen(false)} />
            </div>
          </div>
        ) : null}

        <main className="min-w-0 flex-1 px-4 py-10 sm:px-8">
          <article className="mx-auto max-w-3xl">
            {children}
            <PrevNext lang={lang} />
          </article>
        </main>
      </div>
    </div>
  );
}
