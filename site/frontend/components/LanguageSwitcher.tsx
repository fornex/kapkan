"use client";

import { usePathname, useRouter } from "next/navigation";
import { type Locale, locales, localeNames, ui } from "@/lib/i18n";

// Locale dropdown that swaps the leading /<lang>/ path segment, so it works on
// any localized route (docs, config builder, …). Mirrors the docs chrome.
export function LanguageSwitcher({ lang }: { lang: Locale }) {
  const pathname = usePathname();
  const router = useRouter();

  function onChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const parts = pathname.split("/");
    parts[1] = e.target.value;
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
