"use client";

import { useParams } from "next/navigation";
import { defaultLocale, isLocale } from "@/lib/i18n";

// The document's <html>, with lang taken from the route's [lang] param. The
// root layout sits above that segment and, as a Server Component, never sees
// the param; useParams does, also while each page is prerendered, so every
// locale ships its own lang in the HTML. Not a root layout under app/[lang]:
// React would re-create <html> on every locale switch, dropping the `dark`
// class the inline theme script set, and app/'s social-card images would fall
// out of the pages' metadata. Routes without a locale prefix (/, the /docs,
// /config and /xdp redirects, the 404) are English.
export function LocaleHtml(props: Omit<React.ComponentProps<"html">, "lang">) {
  const { lang } = useParams();
  const loc = typeof lang === "string" && isLocale(lang) ? lang : defaultLocale;
  return <html {...props} lang={loc} />;
}
