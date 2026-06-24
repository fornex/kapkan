"use client";

import { useState } from "react";
import Link from "next/link";

export type NavLink = { label: string; href: string; external?: boolean };

// Hamburger menu shown below the md breakpoint, where the inline nav is hidden.
// Links + the primary CTA collapse into a slide-down panel; `children` (e.g. a
// language switcher) render at the panel's foot.
export function MobileNav({
  links,
  cta,
  menuLabel,
  children,
}: {
  links: NavLink[];
  cta: NavLink;
  menuLabel: string;
  children?: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  const renderLink = (l: NavLink, className: string) => {
    if (l.external) {
      return (
        <a href={l.href} target="_blank" rel="noopener noreferrer" onClick={close} className={className}>
          {l.label}
        </a>
      );
    }
    if (l.href.startsWith("#")) {
      return (
        <a href={l.href} onClick={close} className={className}>
          {l.label}
        </a>
      );
    }
    return (
      <Link href={l.href} onClick={close} className={className}>
        {l.label}
      </Link>
    );
  };

  const itemCls =
    "block rounded-lg px-3 py-2.5 text-base font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground";

  return (
    <div className="md:hidden">
      <button
        type="button"
        aria-label={menuLabel}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      >
        {open ? (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
            <path d="M18 6 6 18M6 6l12 12" />
          </svg>
        ) : (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
            <path d="M4 7h16M4 12h16M4 17h16" />
          </svg>
        )}
      </button>

      {open && (
        <>
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            onClick={close}
            className="fixed inset-0 top-16 z-40 cursor-default bg-background/60 backdrop-blur-sm"
          />
          <nav className="fixed inset-x-0 top-16 z-50 border-b border-border bg-background p-4 shadow-xl">
            <ul className="flex flex-col gap-1">
              {links.map((l) => (
                <li key={l.label + l.href}>{renderLink(l, itemCls)}</li>
              ))}
            </ul>
            <div className="mt-3 border-t border-border pt-3">
              {renderLink(
                cta,
                "block rounded-full bg-accent px-4 py-2.5 text-center text-base font-medium text-accent-foreground transition-opacity hover:opacity-90"
              )}
            </div>
            {children && <div className="mt-4 flex items-center justify-between border-t border-border pt-4">{children}</div>}
          </nav>
        </>
      )}
    </div>
  );
}
