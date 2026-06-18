import Link from "next/link";

// The tile mark — escalation-ramp motif (detect → escalate → mitigate). Colors
// are constant on both themes per the brand guide; only the wordmark flips
// (see .kapkan-word in globals.css). Decorative: the visible "kapkan" text
// carries the accessible name, so the SVG is aria-hidden.
function KapkanMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true" focusable="false">
      <rect x="1" y="1" width="62" height="62" rx="15.4" fill="#141a21" stroke="#2a323d" strokeWidth="1.5" />
      <rect x="40.32" y="15.36" width="6.82" height="6.82" rx="1.08" fill="#9cccff" />
      <rect x="32" y="23.68" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff" />
      <rect x="40.32" y="23.68" width="6.82" height="6.82" rx="1.08" fill="#9cccff" />
      <rect x="23.68" y="32" width="6.82" height="6.82" rx="1.08" fill="#3f8fe0" />
      <rect x="32" y="32" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff" />
      <rect x="40.32" y="32" width="6.82" height="6.82" rx="1.08" fill="#9cccff" />
      <rect x="15.36" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#2f6dab" />
      <rect x="23.68" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#3f8fe0" />
      <rect x="32" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#4ea1ff" />
      <rect x="40.32" y="40.32" width="6.82" height="6.82" rx="1.08" fill="#9cccff" />
    </svg>
  );
}

type LogoProps = {
  /** When set, the lockup is a link (typically "/"). Omit for a plain brand label. */
  href?: string;
  /** Small muted suffix after the wordmark, e.g. "docs". */
  label?: string;
  className?: string;
};

/**
 * Kapkan brand lockup: the tile mark + lowercase two-tone "kapkan" wordmark.
 * Resize the whole thing by setting a font-size on the wrapper — the mark and
 * gap scale in em units (see .kapkan-logo in globals.css). Min legible size per
 * the brand guide: ~18px mark height.
 */
export function Logo({ href, label, className }: LogoProps) {
  const inner = (
    <>
      <KapkanMark className="h-[1.5em] w-[1.5em] shrink-0" />
      <span className="kapkan-word lowercase">
        <span className="kw-front">kap</span>
        <span className="kw-tail">kan</span>
      </span>
      {label ? (
        <span className="text-sm font-normal lowercase text-muted-foreground">{label}</span>
      ) : null}
    </>
  );

  const base = "kapkan-logo inline-flex items-center text-[1.125rem] leading-none";

  if (href) {
    return (
      <Link
        href={href}
        className={`${base} rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background ${className ?? ""}`.trim()}
      >
        {inner}
      </Link>
    );
  }
  return <span className={`${base} ${className ?? ""}`.trim()}>{inner}</span>;
}
