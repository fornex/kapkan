import Link from "next/link";
import { Logo } from "@/components/Logo";

// Branded 404. The root layout renders no chrome, so this carries the mark
// itself. Static export emits this as out/404.html.
export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-6 text-center">
      <Logo href="/" />
      <p className="mt-10 font-mono text-xs uppercase tracking-widest text-muted-foreground">
        404
      </p>
      <h1 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">Page not found</h1>
      <p className="mt-4 max-w-md text-muted-foreground">
        The page you’re looking for doesn’t exist or may have moved.
      </p>
      <div className="mt-8 flex flex-col gap-3 sm:flex-row">
        <Link
          href="/"
          className="flex h-11 items-center justify-center rounded-full bg-accent px-6 font-medium text-accent-foreground transition-opacity hover:opacity-90"
        >
          Back home
        </Link>
        <Link
          href="/docs"
          className="flex h-11 items-center justify-center rounded-full border border-border px-6 font-medium transition-colors hover:bg-muted"
        >
          Read the docs
        </Link>
      </div>
    </div>
  );
}
