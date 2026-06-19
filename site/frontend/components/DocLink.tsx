"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ComponentPropsWithoutRef } from "react";
import { defaultLocale, isLocale } from "@/lib/i18n";

const className =
  "font-medium text-accent underline underline-offset-4 decoration-accent/40 hover:decoration-accent";

// Anchor used for all links inside MDX content. Content authors write
// locale-agnostic links like `/docs/safety`; this component prefixes the
// active locale (read from the URL) so the same content works in every
// language. External links open in a new tab.
export function DocLink({ href = "", children, ...props }: ComponentPropsWithoutRef<"a">) {
  const pathname = usePathname();

  if (/^https?:\/\//.test(href)) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={className} {...props}>
        {children}
      </a>
    );
  }

  let target = href;
  if (href === "/docs" || href.startsWith("/docs/") || href === "/config") {
    const seg = pathname.split("/")[1] ?? "";
    const lang = isLocale(seg) ? seg : defaultLocale;
    target = `/${lang}${href}`;
  }

  return (
    <Link href={target} className={className} {...props}>
      {children}
    </Link>
  );
}
