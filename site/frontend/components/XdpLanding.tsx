import Link from "next/link";
import { site } from "@/lib/site";
import type { Locale } from "@/lib/i18n";
import { xdp } from "@/lib/xdp-i18n";
import { landing } from "@/lib/landing-i18n";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { MobileNav, type NavLink } from "@/components/MobileNav";

/* ------------------------------------------------------------------ icons */
// Same lucide-style inline set the main landing uses, trimmed to this page.
type IconName =
  | "cpu" | "route" | "gauge" | "shieldCheck" | "clock" | "lock" | "check"
  | "arrowRight" | "arrowDown" | "x" | "layers" | "zap" | "terminal" | "star";

function Icon({ name, className }: { name: IconName; className?: string }) {
  const s = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  const c = { viewBox: "0 0 24 24", className, "aria-hidden": true, focusable: false } as const;
  switch (name) {
    case "cpu":
      return <svg {...c} {...s}><rect x="5" y="5" width="14" height="14" rx="2" /><rect x="9" y="9" width="6" height="6" rx="1" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></svg>;
    case "route":
      return <svg {...c} {...s}><circle cx="6" cy="19" r="2.5" /><circle cx="18" cy="5" r="2.5" /><path d="M8.5 19H15a3 3 0 003-3V7.5" /></svg>;
    case "gauge":
      return <svg {...c} {...s}><path d="M12 14l4-4" /><path d="M5.5 18a9 9 0 1113 0" /></svg>;
    case "shieldCheck":
      return <svg {...c} {...s}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></svg>;
    case "clock":
      return <svg {...c} {...s}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>;
    case "lock":
      return <svg {...c} {...s}><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 018 0v4" /></svg>;
    case "check":
      return <svg {...c} {...s}><path d="M20 6L9 17l-5-5" /></svg>;
    case "arrowRight":
      return <svg {...c} {...s}><path d="M5 12h14M13 6l6 6-6 6" /></svg>;
    case "arrowDown":
      return <svg {...c} {...s}><path d="M12 5v14M6 13l6 6 6-6" /></svg>;
    case "x":
      return <svg {...c} {...s}><path d="M18 6L6 18M6 6l12 12" /></svg>;
    case "layers":
      return <svg {...c} {...s}><path d="M12 2l9 5-9 5-9-5 9-5z" /><path d="M3 12l9 5 9-5M3 17l9 5 9-5" /></svg>;
    case "zap":
      return <svg {...c} {...s}><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>;
    case "terminal":
      return <svg {...c} {...s}><path d="M4 17l6-5-6-5" /><path d="M12 19h8" /></svg>;
    case "star":
      return <svg {...c} fill="currentColor"><path d="M12 2.5l2.95 5.98 6.6.96-4.77 4.65 1.13 6.57L12 17.56l-5.91 3.1 1.13-6.57L2.45 9.44l6.6-.96L12 2.5z" /></svg>;
  }
}

const HOW_ICONS: IconName[] = ["zap", "layers", "cpu", "shieldCheck"];
const SAFETY_ICONS: IconName[] = ["gauge", "clock", "lock", "check"];

/* ---------------------------------------------------- pipeline diagram */
// Inline SVG, theme-aware through currentColor and the token stroke/fill
// classes. It shows the one thing that changes versus an announcement: the
// encoded rules go into kernel maps, and the XDP program returns a verdict per
// packet with pass as the default.
// The pipeline as an HTML flow rather than a fixed-geometry SVG: real text
// layout means labels size to their own length in every locale (no glyph
// stretching), the row wraps cleanly on narrow screens, and it stays
// theme-aware through the same token classes as the rest of the page.
function Pipeline({ t }: { t: (typeof xdp)[Locale]["how"]["diagram"] }) {
  const steps = [t.detect, t.compile, t.maps, t.verdict];
  return (
    <figure className="mt-14">
      <div className="flex flex-wrap items-stretch justify-center gap-x-2 gap-y-3 sm:gap-x-3">
        {steps.map((label) => (
          <div key={label} className="flex items-stretch gap-2 sm:gap-3">
            <div className="flex items-center rounded-xl border border-border bg-surface px-4 py-3 text-center text-sm font-semibold shadow-sm">
              {label}
            </div>
            <Icon name="arrowRight" className="h-4 w-4 shrink-0 self-center text-muted-foreground" />
          </div>
        ))}
        {/* The XDP program returns exactly one of these two verdicts. */}
        <div className="flex flex-col justify-center gap-2">
          <span className="rounded-lg border border-green-500/40 bg-green-500/10 px-3 py-1.5 text-center text-xs font-semibold text-green-600 dark:text-green-400">
            {t.pass}
          </span>
          <span className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-center text-xs font-semibold text-red-600 dark:text-red-400">
            {t.drop}
          </span>
        </div>
      </div>
      <figcaption className="mx-auto mt-6 max-w-2xl text-center text-sm text-muted-foreground">{t.caption}</figcaption>
    </figure>
  );
}

/* ------------------------------------------------------------------ frame */
function Shot({ src, alt, w, h }: { src: string; alt: string; w: number; h: number }) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={src} alt={alt} width={w} height={h} className="h-auto w-full" />
    </div>
  );
}

/* ------------------------------------------------------------------- page */
export function XdpLanding({ locale, basePath }: { locale: Locale; basePath: string }) {
  const t = xdp[locale];
  const docsHref = `${basePath}/docs/dataplane`;
  const configHref = `${basePath}/config`;
  const homeHref = basePath || "/";
  const docsIndexHref = `${basePath}/docs`;

  // Same top menu as the home page — the site's global nav, not a page-specific
  // one — so it does not visibly change when you land here. The section links
  // resolve to those sections on the home page; XDP is this page. Labels come
  // from the landing dictionary so the two headers can never drift apart.
  const nt = landing[locale].nav;
  const navLinks: NavLink[] = [
    { label: nt.features, href: `${homeHref}#features` },
    { label: nt.how, href: `${homeHref}#how-it-works` },
    { label: "XDP", href: `${basePath}/xdp` },
    { label: nt.compare, href: `${homeHref}#compare` },
    { label: nt.docs, href: docsIndexHref },
  ];
  const mobileLinks: NavLink[] = [
    ...navLinks,
    { label: nt.viewGithub, href: site.repo, external: true },
    { label: nt.buildConfig, href: configHref },
  ];

  return (
    <div className="flex min-h-screen flex-col">
      {/* ---------------------------------------------------------- header */}
      <header className="sticky top-0 z-50 border-b border-border bg-background">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <Logo href={homeHref} />
          <nav className="hidden items-center gap-8 text-sm font-medium text-muted-foreground md:flex">
            {navLinks.map((l) => (
              <Link
                key={l.label}
                href={l.href}
                aria-current={l.label === "XDP" ? "page" : undefined}
                className={`transition-colors hover:text-foreground ${l.label === "XDP" ? "text-foreground" : ""}`}
              >
                {l.label}
              </Link>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <a
              href={site.repo}
              target="_blank"
              rel="noopener noreferrer"
              className="hidden items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground lg:flex"
            >
              GitHub
            </a>
            <div className="hidden sm:block"><LanguageSwitcher lang={locale} /></div>
            <ThemeToggle />
            <Link href={docsIndexHref} className="hidden rounded-md bg-foreground px-5 py-2 text-sm font-medium text-background transition-opacity hover:opacity-90 sm:inline-flex">
              {nt.readDocs}
            </Link>
            <MobileNav links={mobileLinks} cta={{ label: nt.readDocs, href: docsIndexHref }} menuLabel={nt.menu}>
              <LanguageSwitcher lang={locale} />
              <ThemeToggle />
            </MobileNav>
          </div>
        </div>
      </header>

      <main>
        {/* ------------------------------------------------------------ hero */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-7xl px-6 pb-16 pt-16 lg:pb-20 lg:pt-20">
            <p className="mb-6 font-mono text-xs text-muted-foreground">{t.hero.eyebrow}</p>
            <div className="grid grid-cols-1 items-start gap-12 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <h1 className="mb-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
                  {t.hero.h1a} {t.hero.h1b}
                </h1>
                <p className="mb-8 max-w-xl text-lg leading-relaxed text-muted-foreground">{t.hero.sub}</p>
                <div className="mb-8 flex flex-wrap items-center gap-3">
                  <Link href={docsHref} className="rounded-md bg-foreground px-5 py-2.5 text-sm font-medium text-background transition-opacity hover:opacity-90">{t.hero.ctaDocs}</Link>
                  <Link href={configHref} className="rounded-md border border-border bg-surface px-5 py-2.5 text-sm font-medium transition-colors hover:bg-muted">
                    {t.hero.ctaConfig}
                  </Link>
                </div>
                <p className="font-mono text-sm text-muted-foreground">{t.hero.trust.join(" · ")}</p>
              </div>
              <div className="lg:col-span-7">
                <Shot src="/assets/screenshots/xdp/attacks-xdp-method.png" alt={t.hero.shotAlt} w={1440} h={644} />
                <p className="mt-4 text-center text-sm text-muted-foreground">{t.hero.shotCaption}</p>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------- announce vs drop */}
        <section className="border-y border-border bg-muted/20 py-24">
          <div className="mx-auto max-w-6xl px-6">
            <div className="mb-14 max-w-3xl">
              <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.contrast.heading}</h2>
              <p className="text-muted-foreground">{t.contrast.sub}</p>
            </div>
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
              {[
                { icon: "route" as IconName, tone: "text-accent", d: t.contrast.announce },
                { icon: "cpu" as IconName, tone: "text-amber-400", d: t.contrast.drop },
              ].map((col) => (
                <div key={col.d.title} className="rounded-lg border border-border bg-surface p-7">
                  <div className="mb-4 flex items-center gap-3">
                    <span className={`flex h-11 w-11 items-center justify-center rounded-xl border border-border bg-background ${col.tone}`}>
                      <Icon name={col.icon} className="h-6 w-6" />
                    </span>
                    <h3 className="text-lg font-semibold">{col.d.title}</h3>
                  </div>
                  <p className="mb-5 text-sm leading-relaxed text-muted-foreground">{col.d.body}</p>
                  <ul className="space-y-2.5">
                    {col.d.points.map((p) => (
                      <li key={p} className="flex gap-2.5 text-sm leading-relaxed">
                        <Icon name="arrowRight" className={`mt-1 h-3.5 w-3.5 shrink-0 ${col.tone}`} />
                        <span className="text-muted-foreground">{p}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* --------------------------------------------------- how it works */}
        <section className="mx-auto max-w-7xl px-6 py-24">
          <div className="mb-4 max-w-3xl">
            <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.how.heading}</h2>
            <p className="text-muted-foreground">{t.how.sub}</p>
          </div>
          <div className="mt-12 grid grid-cols-1 gap-8 md:grid-cols-2 lg:grid-cols-4">
            {t.how.steps.map((step, i) => (
              <div key={step.title} className="relative rounded-lg border border-border bg-surface p-6">
                <div className="mb-4 flex items-center gap-3">
                  <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-background text-amber-400">
                    <Icon name={HOW_ICONS[i]} className="h-5 w-5" />
                  </span>
                  <span className="font-mono text-xs text-muted-foreground">0{i + 1}</span>
                </div>
                <h3 className="mb-2 font-semibold">{step.title}</h3>
                <p className="text-sm leading-relaxed text-muted-foreground">{step.body}</p>
              </div>
            ))}
          </div>
          <Pipeline t={t.how.diagram} />
        </section>

        {/* ------------------------------------------------- rate limiting */}
        <section className="border-y border-border bg-muted/20 py-24">
          <div className="mx-auto grid max-w-6xl grid-cols-1 gap-10 px-6 lg:grid-cols-12">
            <div className="lg:col-span-1">
              <span className="flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface text-amber-400">
                <Icon name="gauge" className="h-6 w-6" />
              </span>
            </div>
            <div className="lg:col-span-11">
              <h2 className="mb-4 max-w-3xl text-3xl font-semibold tracking-tight">{t.ratelimit.heading}</h2>
              <p className="mb-6 max-w-3xl text-lg leading-relaxed text-muted-foreground">{t.ratelimit.body}</p>
              <p className="max-w-3xl border-l-2 border-amber-400/40 pl-4 text-sm italic leading-relaxed text-muted-foreground">{t.ratelimit.aside}</p>
            </div>
          </div>
        </section>

        {/* ---------------------------------------------------------- safety */}
        <section className="mx-auto max-w-7xl px-6 py-24">
          <div className="mb-14 max-w-3xl">
            <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.safety.heading}</h2>
            <p className="text-muted-foreground">{t.safety.sub}</p>
          </div>
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            {t.safety.cards.map((card, i) => (
              <div key={card.title} className="rounded-lg border border-border bg-surface p-6">
                <Icon name={SAFETY_ICONS[i]} className="mb-4 h-6 w-6 text-green-500" />
                <h3 className="mb-2 font-semibold">{card.title}</h3>
                <p className="text-sm leading-relaxed text-muted-foreground">{card.body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* -------------------------------------------------------- measured */}
        <section className="border-y border-border bg-muted/20 py-24">
          <div className="mx-auto max-w-6xl px-6">
            <div className="mb-12 max-w-3xl">
              <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.measured.heading}</h2>
              <p className="text-muted-foreground">{t.measured.sub}</p>
            </div>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {t.measured.stats.map((s) => (
                <div key={s.label} className="rounded-lg border border-border bg-surface p-6">
                  <div className="mb-2 font-mono text-3xl font-bold text-amber-400">{s.value}</div>
                  <p className="text-sm leading-relaxed text-muted-foreground">{s.label}</p>
                </div>
              ))}
            </div>
            <p className="mx-auto mt-8 max-w-3xl text-sm leading-relaxed text-muted-foreground">{t.measured.caveat}</p>
          </div>
        </section>

        {/* --------------------------------------------------------- showcase */}
        <section className="mx-auto max-w-5xl px-6 py-24">
          <Shot src="/assets/screenshots/xdp/attack-detail-xdp.png" alt={t.showcaseCaption} w={1440} h={962} />
          <p className="mx-auto mt-5 max-w-2xl text-center text-sm text-muted-foreground">{t.showcaseCaption}</p>
        </section>

        {/* ---------------------------------------------------------- limits */}
        <section className="border-y border-border bg-muted/20 py-24">
          <div className="mx-auto max-w-5xl px-6">
            <div className="mb-12 max-w-3xl">
              <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.limits.heading}</h2>
              <p className="text-muted-foreground">{t.limits.sub}</p>
            </div>
            <div className="space-y-5">
              {t.limits.items.map((it) => (
                <div key={it.title} className="rounded-lg border border-border bg-surface p-6">
                  <h3 className="mb-2 font-semibold">{it.title}</h3>
                  <p className="text-sm leading-relaxed text-muted-foreground">{it.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* --------------------------------------------------- requirements */}
        <section className="mx-auto max-w-5xl px-6 py-24">
          <div className="mb-10 max-w-3xl">
            <h2 className="mb-4 text-3xl font-semibold tracking-tight">{t.requirements.heading}</h2>
            <p className="text-muted-foreground">{t.requirements.sub}</p>
          </div>
          <ul className="space-y-3">
            {t.requirements.items.map((item) => (
              <li key={item} className="flex gap-3 rounded-xl border border-border bg-surface p-4">
                <Icon name="terminal" className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
                <span className="text-sm leading-relaxed text-muted-foreground">{item}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* -------------------------------------------------------------- cta */}
        <section className="border-t border-border">
          <div className="mx-auto max-w-4xl px-6 py-24 text-center">
            <h2 className="mb-4 text-3xl font-semibold tracking-tight sm:text-4xl">{t.cta.heading}</h2>
            <p className="mx-auto mb-8 max-w-xl text-muted-foreground">{t.cta.sub}</p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Link href={docsHref} className="rounded-md bg-foreground px-5 py-2.5 text-sm font-medium text-background transition-opacity hover:opacity-90">{t.cta.primary}</Link>
              <Link href={configHref} className="rounded-md border border-border bg-surface px-5 py-2.5 text-sm font-medium transition-colors hover:bg-muted">{t.cta.secondary}</Link>
            </div>
          </div>
        </section>
      </main>

      {/* --------------------------------------------------------------- foot */}
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 py-10 text-sm text-muted-foreground sm:flex-row">
          <Logo href={homeHref} />
          <div className="flex items-center gap-6">
            <Link href={homeHref} className="hover:text-foreground">{t.nav.home}</Link>
            <Link href={docsHref} className="hover:text-foreground">{t.nav.docs}</Link>
            <a href={site.repo} target="_blank" rel="noopener noreferrer" className="hover:text-foreground">GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
