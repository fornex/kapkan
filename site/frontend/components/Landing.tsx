import Link from "next/link";
import { site } from "@/lib/site";
import type { Locale } from "@/lib/i18n";
import { landing } from "@/lib/landing-i18n";
import { latestReleasedVersion } from "@/lib/version.server";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { ConsoleShowcase } from "@/components/ConsoleShowcase";
import { MobileNav, type NavLink } from "@/components/MobileNav";

/* ------------------------------------------------------------------ icons */
// The two glyphs the page still needs. Everything decorative (a lucide icon
// per feature card, per step, per stat) is gone on purpose: those grids of
// generic outline icons are the first thing that reads as a template.
function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden fill="currentColor">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

function ArrowIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

/* ---------------------------------------------------------------- styles */
// One radius, one button vocabulary, no shadows. Primary is ink-on-paper
// rather than the accent blue: the blue is kept for links and for the Kapkan
// column of the comparison, where it means something.
const BTN = "inline-flex items-center gap-2 rounded-md px-5 py-2.5 text-sm font-medium transition-colors";
const BTN_PRIMARY = `${BTN} bg-foreground text-background hover:opacity-90`;
const BTN_SECONDARY = `${BTN} border border-border bg-surface hover:bg-muted`;
const BTN_DANGER = `${BTN} border border-red-700/30 text-red-700 hover:bg-red-700/5 dark:border-red-400/30 dark:text-red-400 dark:hover:bg-red-400/10`;

// Section header: left-aligned, one size everywhere. The heading and its
// lede share a measure so long locales wrap the same way.
function SectionHead({ heading, sub, id }: { heading: string; sub: string; id?: string }) {
  return (
    <div className="mb-10 max-w-2xl">
      <h2 id={id} className="mb-3 text-2xl font-semibold tracking-tight sm:text-3xl">{heading}</h2>
      <p className="text-base leading-relaxed text-muted-foreground">{sub}</p>
    </div>
  );
}

// A screenshot in a plain 1px frame. No browser chrome, no traffic lights,
// no fake URL bar: the image is the real console, and it does not need a
// costume to prove it.
function Frame({ children }: { children: React.ReactNode }) {
  return <div className="overflow-hidden rounded-lg border border-border bg-surface">{children}</div>;
}

// The architecture in one figure: flows in from the routers, Kapkan in the
// middle, and the two ways a verdict leaves it. HTML rather than SVG so labels
// lay out at their real length in every locale and the row wraps on phones.
function HowDiagram({ d }: { d: (typeof landing)[Locale]["how"]["diagram"] }) {
  const node = "rounded-md border border-border bg-surface px-4 py-3";
  return (
    <figure className="mb-10 flex flex-wrap items-center gap-3 text-sm">
      <div className={node}>
        <div className="font-medium">{d.routers}</div>
        <div className="font-mono text-xs text-muted-foreground">{d.flows}</div>
      </div>
      <ArrowIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
      <div className={`${node} border-foreground font-semibold`}>Kapkan</div>
      <ArrowIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
      <div className="flex flex-col gap-2">
        <div className={node}>
          <div className="font-medium">{d.announce}</div>
          <div className="text-xs text-muted-foreground">{d.announceNote}</div>
        </div>
        <div className={node}>
          <div className="font-medium">{d.drop}</div>
          <div className="text-xs text-muted-foreground">{d.dropNote}</div>
        </div>
      </div>
    </figure>
  );
}

// The in-kernel card is last in `features.cards`; it gets the "see how" link.
const XDP_CARD_INDEX = 9;

/* ------------------------------------------------------------------- page */
export function Landing({ locale, basePath = "" }: { locale: Locale; basePath?: string }) {
  const t = landing[locale];
  const version = latestReleasedVersion();
  const docsHref = `${basePath}/docs`;
  const configHref = `${basePath}/config`;
  const underAttackHref = `${docsHref}/under-attack`;

  const navLinks: NavLink[] = [
    { label: t.nav.features, href: "#features" },
    { label: t.nav.how, href: "#how-it-works" },
    // "XDP" is an acronym — the same in every locale, so it carries no t.nav
    // entry. It is a page link (like Docs), not an in-page anchor.
    { label: "XDP", href: `${basePath}/xdp` },
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
      <header className="sticky top-0 z-50 border-b border-border bg-background">
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
              className="hidden items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground lg:flex"
            >
              <GithubIcon className="h-4 w-4" /> GitHub
            </a>
            <div className="hidden sm:block">
              <LanguageSwitcher lang={locale} />
            </div>
            <ThemeToggle />
            <Link href={docsHref} className={`hidden sm:inline-flex ${BTN_PRIMARY} py-2`}>
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
        <section className="border-b border-border">
          <div className="mx-auto max-w-7xl px-6 pb-16 pt-16 lg:pb-20 lg:pt-20">
            <div className="grid grid-cols-1 items-start gap-12 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <p className="mb-6 font-mono text-xs text-muted-foreground">
                  {t.hero.eyebrow} · v{version}
                </p>
                <h1 className="mb-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
                  {t.hero.h1a} {t.hero.h1b}
                </h1>
                <p className="mb-8 max-w-xl text-lg leading-relaxed text-muted-foreground">{t.hero.sub}</p>
                <div className="mb-8 flex flex-wrap items-center gap-3">
                  <Link href={docsHref} className={BTN_PRIMARY}>{t.nav.readDocs}</Link>
                  <a href={site.repo} target="_blank" rel="noopener noreferrer" className={BTN_SECONDARY}>
                    <GithubIcon className="h-4 w-4" /> {t.nav.viewGithub}
                  </a>
                  {/* Emergency lane: the one on-ramp a panicking operator needs.
                      No competitor surfaces an "under attack right now" path — we
                      already have the runbook, so we point straight at it. */}
                  <Link href={underAttackHref} className={BTN_DANGER}>{t.nav.underAttack}</Link>
                </div>
                <p className="font-mono text-sm text-muted-foreground">
                  {t.hero.trust.join(" · ")}
                </p>
              </div>

              <div className="min-w-0 lg:col-span-7">
                <Frame>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src="/assets/screenshots/console-overview.png"
                    alt="Kapkan operator console — Overview dashboard with active incidents and global traffic"
                    width={1440}
                    height={1049}
                    className="h-auto w-full"
                  />
                </Frame>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------------- stat bar */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-7xl px-6 py-4">
            <ul className="flex flex-wrap items-center gap-x-8 gap-y-2 font-mono text-sm text-muted-foreground md:justify-between">
              {t.stats.map((label) => (
                <li key={label}>{label}</li>
              ))}
            </ul>
          </div>
        </section>

        {/* --------------------------------------------------- how it works */}
        <section id="how-it-works" className="mx-auto max-w-7xl px-6 py-20">
          <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
            <div className="lg:col-span-4">
              <SectionHead heading={t.how.heading} sub={t.how.sub} />
            </div>
            <div className="min-w-0 lg:col-span-8">
              <HowDiagram d={t.how.diagram} />
              <ol>
                {t.how.steps.map((step, i) => (
                  <li key={step.title} className="grid grid-cols-[3rem_1fr] gap-4 border-t border-border py-6 last:border-b sm:grid-cols-[4rem_1fr]">
                    <span className="font-mono text-sm text-muted-foreground">0{i + 1}</span>
                    <div>
                      <h3 className="mb-2 font-semibold">{step.title}</h3>
                      <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">{step.body}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </section>

        {/* ---------------------------------------------------- features */}
        <section id="features" className="border-y border-border bg-muted/40 py-20">
          <div className="mx-auto max-w-7xl px-6">
            <SectionHead heading={t.features.heading} sub={t.features.sub} />
            <dl className="grid grid-cols-1 gap-x-12 md:grid-cols-2">
              {t.features.cards.map((f, i) => (
                <div
                  key={f.title}
                  className={`border-t border-border py-6 ${i === XDP_CARD_INDEX ? "md:col-span-2" : ""}`}
                >
                  <dt className="mb-2 font-semibold">{f.title}</dt>
                  <dd className={`text-sm leading-relaxed text-muted-foreground ${i === XDP_CARD_INDEX ? "max-w-3xl" : ""}`}>
                    {f.body}
                    {i === XDP_CARD_INDEX && (
                      <>
                        {" "}
                        <Link href={`${basePath}/xdp`} className="inline-flex items-center gap-1 whitespace-nowrap font-medium text-accent hover:underline">
                          {t.features.learnMore}
                          <ArrowIcon className="h-3.5 w-3.5" />
                        </Link>
                      </>
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* --------------------------------------------- product showcase */}
        <section className="mx-auto max-w-7xl px-6 py-20">
          <SectionHead heading={t.showcase.heading} sub={t.showcase.sub} />
          <ConsoleShowcase />
        </section>

        {/* ------------------------------------------------------- compare */}
        <section id="compare" className="border-t border-border">
          <div className="mx-auto max-w-7xl px-6 py-20">
            <SectionHead heading={t.compare.heading} sub={t.compare.sub} />
            <div className="overflow-x-auto">
              <table className="w-full min-w-[40rem] text-left text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="w-1/3 py-3 pr-4 font-medium text-muted-foreground">{t.compare.colFeature}</th>
                    <th className="w-1/3 py-3 pr-4 font-semibold text-accent">{t.compare.colKapkan}</th>
                    <th className="w-1/3 py-3 font-medium text-muted-foreground">{t.compare.colThem}</th>
                  </tr>
                </thead>
                <tbody>
                  {t.compare.rows.map((row) => (
                    <tr key={row.feature} className="border-b border-border">
                      <td className="py-3 pr-4 text-muted-foreground">{row.feature}</td>
                      <td className="py-3 pr-4 font-medium">{row.kapkan}</td>
                      <td className="py-3 text-muted-foreground">{row.them}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* ----------------------------------------------------- quickstart */}
        <section id="quickstart" className="border-t border-border bg-muted/40 py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="grid grid-cols-1 items-start gap-12 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <h2 className="mb-4 text-2xl font-semibold tracking-tight sm:text-3xl">{t.quickstart.heading}</h2>
                <p className="mb-6 leading-relaxed text-muted-foreground">
                  {t.quickstart.bodyBefore}
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.9em] text-foreground">dry_run: false</code>
                  {t.quickstart.bodyAfter}
                </p>
                <Link href={docsHref} className="inline-flex items-center gap-1.5 font-medium text-accent hover:underline">
                  {t.quickstart.cta} <ArrowIcon className="h-4 w-4" />
                </Link>
              </div>
              <div className="min-w-0 lg:col-span-7">
                <Frame>
                  <div className="border-b border-border px-4 py-2 font-mono text-xs text-muted-foreground">config.yaml</div>
                  <pre className="overflow-x-auto p-5 font-mono text-sm leading-relaxed">
                    <code>
                      <span className="text-muted-foreground">$</span> kapkan -config config.yaml{"\n"}
                      <span className="text-muted-foreground">---</span>{"\n"}
                      dry_run: <span className="text-accent">true</span>{"\n"}
                      networks: [<span className="text-accent">&quot;203.0.113.0/24&quot;</span>]{"\n"}
                      thresholds: {"{ "}pps: <span className="text-accent">80000</span>, mbps: <span className="text-accent">1000</span>{" }"}{"\n"}
                      bgp: {"{ "}local_asn: <span className="text-accent">65010</span>, community: <span className="text-accent">&quot;65010:666&quot;</span>{" }"}
                    </code>
                  </pre>
                </Frame>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------------ final CTA */}
        <section className="border-t border-border py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="grid grid-cols-1 items-start gap-12 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <h2 className="mb-4 text-3xl font-semibold tracking-tight sm:text-4xl">{t.cta.heading}</h2>
                <p className="mb-8 text-lg leading-relaxed text-muted-foreground">{t.cta.sub}</p>
                <div className="flex flex-wrap items-center gap-3">
                  <Link href={`${docsHref}/quickstart`} className={BTN_PRIMARY}>{t.footer.quickstart}</Link>
                  <Link href={configHref} className={BTN_SECONDARY}>{t.nav.buildConfig}</Link>
                </div>
              </div>
              <div className="min-w-0 lg:col-span-7">
                {/* The real install, with the real current version baked in at
                    build time (see lib/version.server.ts), so this can never
                    lag a release the way a hand-typed example does. */}
                <Frame>
                  <div className="border-b border-border px-4 py-2 font-mono text-xs text-muted-foreground">Debian / Ubuntu</div>
                  <pre className="overflow-x-auto p-5 font-mono text-sm leading-relaxed">
                    <code>
                      VER=v{version}{"\n"}
                      curl -fLO \{"\n"}
                      {"  "}&quot;{site.repo}/releases/download/$VER/kapkan_${"{"}VER#v{"}"}_linux_amd64.deb&quot;{"\n"}
                      sudo apt install &quot;./kapkan_${"{"}VER#v{"}"}_linux_amd64.deb&quot;
                    </code>
                  </pre>
                </Frame>
              </div>
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
          <div className="mt-12 border-t border-border pt-6 font-mono text-xs text-muted-foreground">
            © {site.name} · kapkan.io · Apache 2.0 · v{version}
          </div>
        </div>
      </footer>
    </div>
  );
}
