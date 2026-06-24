import type { Metadata } from "next";
import { landing } from "@/lib/landing-i18n";
import { Landing } from "@/components/Landing";

// English landing lives at "/". Localized variants are under /[lang].
export const metadata: Metadata = {
  title: { absolute: landing.en.meta.title },
  description: landing.en.meta.description,
  alternates: { canonical: "/" },
};

export default function Home() {
  return <Landing locale="en" />;
}
