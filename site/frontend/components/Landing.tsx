import Link from "next/link";
import { site } from "@/lib/site";
import type { Locale } from "@/lib/i18n";
import { landing } from "@/lib/landing-i18n";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { ConsoleShowcase } from "@/components/ConsoleShowcase";
import { MobileNav, type NavLink } from "@/components/MobileNav";

/* ------------------------------------------------------------------ icons */
// Minimal inline stroke icons (lucide-style) so the landing carries no
// FontAwesome/icon-font dependency. 24×24, inherit currentColor.
type IconName =
  | "share" | "bolt" | "filter" | "search" | "activity" | "shield" | "grid"
  | "bell" | "users" | "antenna" | "target" | "shieldCheck" | "cpu" | "clock"
  | "route" | "terminal" | "arrowRight" | "check" | "x" | "minus" | "star" | "github";

function Icon({ name, className }: { name: IconName; className?: string }) {
  const s = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  const c = { viewBox: "0 0 24 24", className, "aria-hidden": true, focusable: false } as const;
  switch (name) {
    case "github":
      return (
        <svg {...c} fill="currentColor">
          <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
        </svg>
      );
    case "star":
      return <svg {...c} fill="currentColor"><path d="M12 2.5l2.95 5.98 6.6.96-4.77 4.65 1.13 6.57L12 17.56l-5.91 3.1 1.13-6.57L2.45 9.44l6.6-.96L12 2.5z" /></svg>;
    case "share":
      return <svg {...c} {...s}><circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" /><path d="M8.6 13.5l6.8 3.99M15.4 6.51l-6.8 3.98" /></svg>;
    case "bolt":
      return <svg {...c} {...s}><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>;
    case "filter":
      return <svg {...c} {...s}><path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z" /></svg>;
    case "search":
      return <svg {...c} {...s}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></svg>;
    case "activity":
      return <svg {...c} {...s}><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>;
    case "shield":
      return <svg {...c} {...s}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
    case "shieldCheck":
      return <svg {...c} {...s}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></svg>;
    case "grid":
      return <svg {...c} {...s}><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /></svg>;
    case "bell":
      return <svg {...c} {...s}><path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9z" /><path d="M10.3 21a1.94 1.94 0 003.4 0" /></svg>;
    case "users":
      return <svg {...c} {...s}><path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" /></svg>;
    case "antenna":
      return <svg {...c} {...s}><path d="M5 12.55a11 11 0 0114.08 0M1.42 9a16 16 0 0121.16 0M8.53 16.11a6 6 0 016.95 0" /><path d="M12 20h.01" /></svg>;
    case "target":
      return <svg {...c} {...s}><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" /></svg>;
    case "cpu":
      return <svg {...c} {...s}><rect x="5" y="5" width="14" height="14" rx="2" /><rect x="9" y="9" width="6" height="6" rx="1" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></svg>;
    case "clock":
      return <svg {...c} {...s}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>;
    case "route":
      return <svg {...c} {...s}><circle cx="6" cy="19" r="2.5" /><circle cx="18" cy="5" r="2.5" /><path d="M8.5 19H15a3 3 0 003-3V7.5" /></svg>;
    case "terminal":
      return <svg {...c} {...s}><path d="M4 17l6-5-6-5" /><path d="M12 19h8" /></svg>;
    case "arrowRight":
      return <svg {...c} {...s}><path d="M5 12h14M13 6l6 6-6 6" /></svg>;
    case "check":
      return <svg {...c} {...s}><path d="M20 6L9 17l-5-5" /></svg>;
    case "x":
      return <svg {...c} {...s}><path d="M18 6L6 18M6 6l12 12" /></svg>;
    case "minus":
      return <svg {...c} {...s}><path d="M5 12h14" /></svg>;
  }
}

const STAT_ICONS: IconName[] = ["cpu", "clock", "route", "filter", "terminal"];
const STEP_ICONS: { icon: IconName; color: string }[] = [
  { icon: "antenna", color: "text-accent" },
  { icon: "target", color: "text-red-500" },
  { icon: "shieldCheck", color: "text-green-500" },
];
const FEATURE_ICONS: IconName[] = ["share", "bolt", "filter", "search", "activity", "shield", "grid", "bell", "users"];
const SAFETY_CARD_INDEX = 5;
const THEM_ICONS: ("x" | "minus")[] = ["x", "x", "minus", "minus", "minus", "x"];

/* ------------------------------------------------------------------- page */
export function Landing({ locale, basePath = "" }: { locale: Locale; basePath?: string }) {
  const t = landing[locale];
  const docsHref = `${basePath}/docs`;
  const configHref = `${basePath}/config`;

  const navLinks: NavLink[] = [
    { label: t.nav.features, href: "#features" },
    { label: t.nav.how, href: "#how-it-works" },
    { label: t.nav.compare, href: "#compare" },
    { label: t.nav.docs, href: docsHref },
  ];
  const mobileLinks: NavLink[] = [
    ...navLinks,
    { label: t.nav.viewGithub, href: site.repo, external: true },
    { label: t.nav.buildConfig, href: configHref },
  ];

  return (
    <div className="flex min-h-screen flex-col">
      {/* ---------------------------------------------------------- header */}
      <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <Logo href={basePath || "/"} />
          <nav className="hidden items-center gap-8 text-sm font-medium text-muted-foreground md:flex">
            {navLinks.map((l) =>
              l.href.startsWith("#") ? (
                <a key={l.label} href={l.href} className="transition-colors hover:text-foreground">{l.label}</a>
              ) : (
                <Link key={l.label} href={l.href} className="transition-colors hover:text-foreground">{l.label}</Link>
              )
            )}
          </nav>
          <div className="flex items-center gap-3">
            <a
              href={site.repo}
              target="_blank"
              rel="noopener noreferrer"
              className="hidden items-center gap-2 rounded-full border border-border bg-surface px-3 py-1.5 font-mono text-xs text-muted-foreground transition-colors hover:text-foreground lg:flex"
            >
              <Icon name="star" className="h-3.5 w-3.5 text-amber-400" /> {t.nav.star}
            </a>
            <div className="hidden sm:block">
              <LanguageSwitcher lang={locale} />
            </div>
            <ThemeToggle />
            <Link
              href={docsHref}
              className="hidden rounded-full bg-accent px-5 py-2 text-sm font-medium text-accent-foreground transition-opacity hover:opacity-90 sm:inline-flex"
            >
              {t.nav.readDocs}
            </Link>
            <MobileNav links={mobileLinks} cta={{ label: t.nav.readDocs, href: docsHref }} menuLabel={t.nav.menu}>
              <LanguageSwitcher lang={locale} />
              <ThemeToggle />
            </MobileNav>
          </div>
        </div>
      </header>

      <main>
        {/* ------------------------------------------------------------ hero */}
        <section className="relative overflow-hidden">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[600px]"
            style={{ background: "radial-gradient(60% 60% at 50% -10%, rgba(37,99,235,0.16) 0%, rgba(37,99,235,0) 60%)" }}
          />
          <div className="mx-auto max-w-7xl px-6 pb-16 pt-20 lg:pb-24 lg:pt-28">
            <div className="grid grid-cols-1 items-center gap-12 lg:grid-cols-12">
              <div className="flex flex-col items-start lg:col-span-5">
                <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-border bg-surface/60 px-3 py-1 backdrop-blur-sm">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
                    {t.hero.eyebrow}
                  </span>
                </div>
                <h1 className="mb-6 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl lg:text-6xl">
                  {t.hero.h1a} <span className="text-accent">{t.hero.h1b}</span>
                </h1>
                <p className="mb-8 max-w-xl text-lg leading-relaxed text-muted-foreground">{t.hero.sub}</p>
                <div className="mb-8 flex flex-wrap items-center gap-3">
                  <Link href={docsHref} className="rounded-full bg-accent px-6 py-3 font-medium text-accent-foreground transition-opacity hover:opacity-90">
                    {t.nav.readDocs}
                  </Link>
                  <a href={site.repo} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border border-border bg-surface px-6 py-3 font-medium transition-colors hover:bg-muted">
                    <Icon name="github" className="h-5 w-5" /> {t.nav.viewGithub}
                  </a>
                  <Link href={configHref} className="group ml-1 flex items-center gap-1 text-sm font-medium text-accent transition-colors hover:opacity-80">
                    {t.nav.buildConfig}
                    <Icon name="arrowRight" className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                  </Link>
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2 font-mono text-sm text-muted-foreground">
                  {t.hero.trust.map((item, i) => (
                    <span key={item} className="flex items-center gap-1.5">
                      {i > 0 && <span className="mr-2 text-border">•</span>}
                      <Icon name="check" className="h-3.5 w-3.5 text-accent/70" /> {item}
                    </span>
                  ))}
                </div>
              </div>

              <div className="lg:col-span-7">
                <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl ring-1 ring-black/5">
                  <div className="flex h-11 items-center gap-4 border-b border-border bg-muted px-4">
                    <div className="flex gap-2">
                      <span className="h-3 w-3 rounded-full bg-border" />
                      <span className="h-3 w-3 rounded-full bg-border" />
                      <span className="h-3 w-3 rounded-full bg-border" />
                    </div>
                    <div className="flex flex-1 justify-center">
                      <span className="rounded-md border border-border bg-background px-4 py-1 text-center font-mono text-xs text-muted-foreground">
                        kapkan.local:8080/ui
                      </span>
                    </div>
                  </div>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src="/assets/screenshots/console-overview.png"
                    alt="Kapkan operator console — Overview dashboard with active incidents and global traffic"
                    width={1440}
                    height={1021}
                    className="h-auto w-full"
                  />
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------------- stat bar */}
        <section className="border-y border-border bg-muted/30">
          <div className="mx-auto max-w-7xl px-6 py-6">
            <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3 font-mono text-sm text-muted-foreground md:justify-between">
              {t.stats.map((label, i) => (
                <div key={label} className="flex items-center gap-2">
                  <Icon name={STAT_ICONS[i]} className="h-4 w-4 text-accent/60" /> {label}
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* --------------------------------------------------- how it works */}
        <section id="how-it-works" className="mx-auto max-w-7xl px-6 py-24">
          <div className="mb-16 text-center">
            <h2 className="mb-4 text-3xl font-bold tracking-tight">{t.how.heading}</h2>
            <p className="mx-auto max-w-2xl text-muted-foreground">{t.how.sub}</p>
          </div>
          <div className="relative grid grid-cols-1 gap-12 md:grid-cols-3">
            <div className="absolute left-[16%] right-[16%] top-8 hidden h-px bg-gradient-to-r from-transparent via-border to-transparent md:block" />
            {t.how.steps.map((step, i) => (
              <div key={step.title} className="group relative z-10 flex flex-col items-center text-center">
                <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl border border-border bg-surface shadow-lg transition-colors group-hover:border-accent">
                  <Icon name={STEP_ICONS[i].icon} className={`h-7 w-7 ${STEP_ICONS[i].color}`} />
                </div>
                <div className={`mb-2 font-mono text-lg tracking-widest ${STEP_ICONS[i].color}`}>
                  0{i + 1} {step.title}
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground">{step.body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ---------------------------------------------------- features */}
        <section id="features" className="border-y border-border bg-muted/20 py-24">
          <div className="mx-auto max-w-7xl px-6">
            <div className="mb-16">
              <h2 className="mb-4 text-3xl font-bold tracking-tight">{t.features.heading}</h2>
              <p className="max-w-2xl text-muted-foreground">{t.features.sub}</p>
            </div>
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
              {t.features.cards.map((f, i) => (
                <div key={f.title} className="relative overflow-hidden rounded-2xl border border-border bg-surface p-6 transition-colors hover:border-muted-foreground/40">
                  {i === SAFETY_CARD_INDEX && (
                    <div className="absolute right-0 top-0 rounded-bl-lg bg-accent/10 px-2 py-1 font-mono text-[10px] font-bold text-accent">
                      {t.features.safetyTag}
                    </div>
                  )}
                  <Icon name={FEATURE_ICONS[i]} className="mb-4 h-6 w-6 text-accent" />
                  <h3 className="mb-2 font-semibold">{f.title}</h3>
                  <p className="text-sm leading-relaxed text-muted-foreground">{f.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* --------------------------------------------- product showcase */}
        <section className="mx-auto max-w-7xl px-6 py-24">
          <div className="mb-12 text-center">
            <h2 className="mb-4 text-3xl font-bold tracking-tight">{t.showcase.heading}</h2>
            <p className="mx-auto max-w-2xl text-muted-foreground">{t.showcase.sub}</p>
          </div>
          <ConsoleShowcase />
        </section>

        {/* ------------------------------------------------------- compare */}
        <section id="compare" className="mx-auto max-w-5xl px-6 py-24">
          <div className="mb-12 text-center">
            <h2 className="mb-4 text-3xl font-bold tracking-tight">{t.compare.heading}</h2>
            <p className="text-muted-foreground">{t.compare.sub}</p>
          </div>
          <div className="overflow-hidden rounded-2xl border border-border bg-surface">
            <table className="w-full text-left">
              <thead>
                <tr className="text-sm sm:text-base">
                  <th className="w-1/3 border-b border-border p-4 font-semibold sm:p-6">{t.compare.colFeature}</th>
                  <th className="w-1/3 border-b border-l border-border bg-accent/5 p-4 font-semibold text-accent sm:p-6">{t.compare.colKapkan}</th>
                  <th className="w-1/3 border-b border-l border-border p-4 font-semibold text-muted-foreground sm:p-6">{t.compare.colThem}</th>
                </tr>
              </thead>
              <tbody className="text-sm">
                {t.compare.rows.map((row, i) => {
                  const last = i === t.compare.rows.length - 1;
                  const themIcon = THEM_ICONS[i];
                  return (
                    <tr key={row.feature}>
                      <td className={`p-4 text-muted-foreground ${last ? "" : "border-b border-border"}`}>{row.feature}</td>
                      <td className={`border-l border-border bg-accent/5 p-4 font-medium ${last ? "" : "border-b"}`}>
                        <span className="flex items-center gap-2">
                          <Icon name="check" className="h-4 w-4 shrink-0 text-green-500" /> {row.kapkan}
                        </span>
                      </td>
                      <td className={`border-l border-border p-4 text-muted-foreground ${last ? "" : "border-b"}`}>
                        <span className="flex items-center gap-2">
                          <Icon name={themIcon} className={`h-4 w-4 shrink-0 ${themIcon === "x" ? "text-red-400/70" : "text-muted-foreground/60"}`} />
                          {row.them}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ----------------------------------------------------- quickstart */}
        <section id="quickstart" className="border-t border-border bg-muted/10 py-24">
          <div className="mx-auto max-w-7xl px-6">
            <div className="grid grid-cols-1 items-center gap-16 lg:grid-cols-2">
              <div>
                <h2 className="mb-6 text-3xl font-bold tracking-tight">{t.quickstart.heading}</h2>
                <p className="mb-6 text-lg leading-relaxed text-muted-foreground">
                  {t.quickstart.bodyBefore}
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-accent">dry_run: false</code>
                  {t.quickstart.bodyAfter}
                </p>
                <Link href={docsHref} className="inline-flex items-center gap-2 border-b border-accent/30 pb-0.5 font-medium transition-colors hover:border-accent">
                  {t.quickstart.cta} <Icon name="arrowRight" className="h-4 w-4" />
                </Link>
              </div>
              <div className="overflow-hidden rounded-xl border border-border bg-surface shadow-2xl">
                <div className="flex h-10 items-center gap-2 border-b border-border bg-muted px-4">
                  <span className="h-3 w-3 rounded-full bg-red-500/70" />
                  <span className="h-3 w-3 rounded-full bg-amber-500/70" />
                  <span className="h-3 w-3 rounded-full bg-green-500/70" />
                  <span className="ml-3 font-mono text-xs text-muted-foreground">config.yaml</span>
                </div>
                <pre className="overflow-x-auto p-5 font-mono text-sm leading-relaxed">
                  <code>
                    <span className="text-muted-foreground">$</span> make build{"\n"}
                    <span className="text-muted-foreground">$</span> ./kapkan -config config.yaml{"\n"}
                    <span className="text-muted-foreground">---</span>{"\n"}
                    <span className="text-accent">dry_run</span>: <span className="text-amber-500">true</span>{"\n"}
                    <span className="text-accent">networks</span>: [<span className="text-green-500">&quot;203.0.113.0/24&quot;</span>]{"\n"}
                    <span className="text-accent">thresholds</span>: {"{ "}pps: <span className="text-purple-400">80000</span>, mbps: <span className="text-purple-400">1000</span>{" }"}{"\n"}
                    <span className="text-accent">bgp</span>: {"{ "}local_asn: <span className="text-purple-400">65010</span>, community: <span className="text-green-500">&quot;65010:666&quot;</span>{" }"}
                  </code>
                </pre>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------------ final CTA */}
        <section className="relative overflow-hidden border-t border-border py-28">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 -z-10"
            style={{ background: "radial-gradient(50% 80% at 50% 50%, rgba(37,99,235,0.12) 0%, rgba(37,99,235,0) 70%)" }}
          />
          <div className="mx-auto max-w-4xl px-6 text-center">
            <h2 className="mb-6 text-4xl font-bold tracking-tight sm:text-5xl">{t.cta.heading}</h2>
            <p className="mb-10 text-xl text-muted-foreground">{t.cta.sub}</p>
            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link href={docsHref} className="rounded-full bg-accent px-8 py-4 text-lg font-medium text-accent-foreground transition-opacity hover:opacity-90">
                {t.nav.readDocs}
              </Link>
              <a href={site.repo} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border border-border bg-surface px-8 py-4 text-lg font-medium transition-colors hover:bg-muted">
                <Icon name="star" className="h-5 w-5 text-amber-400" /> {t.nav.star}
              </a>
              <Link href={configHref} className="rounded-full px-8 py-4 text-lg font-medium text-muted-foreground transition-colors hover:text-foreground">
                {t.nav.buildConfig}
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* --------------------------------------------------------- footer */}
      <footer className="border-t border-border bg-background pb-8 pt-16">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid grid-cols-2 gap-8 md:grid-cols-4">
            <div className="col-span-2 md:col-span-1">
              <Logo href={basePath || "/"} />
              <p className="mt-4 max-w-xs text-sm text-muted-foreground">{t.footer.tagline}</p>
            </div>
            <div>
              <h3 className="mb-3 text-sm font-semibold">{t.footer.product}</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href="#features" className="hover:text-foreground">{t.footer.features}</a></li>
                <li><a href="#compare" className="hover:text-foreground">{t.footer.compare}</a></li>
                <li><Link href={configHref} className="hover:text-foreground">{t.footer.configBuilder}</Link></li>
              </ul>
            </div>
            <div>
              <h3 className="mb-3 text-sm font-semibold">{t.footer.docsCol}</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><Link href={`${docsHref}/quickstart`} className="hover:text-foreground">{t.footer.quickstart}</Link></li>
                <li><Link href={`${docsHref}/configuration`} className="hover:text-foreground">{t.footer.configuration}</Link></li>
                <li><Link href={`${docsHref}/api`} className="hover:text-foreground">{t.footer.api}</Link></li>
                <li><Link href={`${docsHref}/safety`} className="hover:text-foreground">{t.footer.safety}</Link></li>
              </ul>
            </div>
            <div>
              <h3 className="mb-3 text-sm font-semibold">{t.footer.project}</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href={site.repo} target="_blank" rel="noopener noreferrer" className="hover:text-foreground">{t.footer.github}</a></li>
                <li><a href={`${site.repo}/releases`} target="_blank" rel="noopener noreferrer" className="hover:text-foreground">{t.footer.releases}</a></li>
                <li><a href={`${site.repo}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer" className="hover:text-foreground">{t.footer.license}</a></li>
              </ul>
            </div>
          </div>
          <div className="mt-12 border-t border-border pt-6 text-sm text-muted-foreground">
            © {site.name} · kapkan.io · Apache 2.0
          </div>
        </div>
      </footer>
    </div>
  );
}
