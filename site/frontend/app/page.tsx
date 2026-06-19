import Link from "next/link";
import { site } from "@/lib/site";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/components/ThemeToggle";

// Placeholder home page. The real landing comes with the design handoff —
// this is a neutral, restylable stand-in that just points at the docs.
export default function Home() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-14 items-center justify-between border-b border-border px-6">
        <Logo href="/" />
        <div className="flex items-center gap-4 text-sm">
          <Link href="/docs" className="text-muted-foreground hover:text-foreground">
            Docs
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

      <main className="flex flex-1 flex-col items-center justify-center px-6 text-center">
        <p className="mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Open source · Apache 2.0
        </p>
        <h1 className="max-w-2xl text-4xl font-bold tracking-tight sm:text-5xl">
          DDoS detection & RTBH mitigation in a single Go binary
        </h1>
        <p className="mt-5 max-w-xl text-lg leading-8 text-muted-foreground">
          Kapkan ingests NetFlow, IPFIX and sFlow telemetry, detects volumetric attacks in
          seconds, and triggers automated BGP blackhole mitigation — dry-run by default.
        </p>
        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Link
            href="/docs"
            className="flex h-11 items-center justify-center rounded-full bg-accent px-6 font-medium text-accent-foreground transition-opacity hover:opacity-90"
          >
            Read the docs
          </Link>
          <Link
            href="/config"
            className="flex h-11 items-center justify-center rounded-full border border-border px-6 font-medium transition-colors hover:bg-muted"
          >
            Build a config
          </Link>
          <a
            href={site.repo}
            target="_blank"
            rel="noopener noreferrer"
            className="flex h-11 items-center justify-center rounded-full border border-border px-6 font-medium transition-colors hover:bg-muted"
          >
            View on GitHub
          </a>
        </div>
        <p className="mt-12 text-xs text-muted-foreground">
          Landing page coming soon — this is a placeholder.
        </p>
      </main>
    </div>
  );
}
