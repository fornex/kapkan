import { defaultLocale } from "@/lib/i18n";
import { MetaRedirect } from "@/components/MetaRedirect";

// Bare /docs → default-locale introduction. Keeps pre-i18n links working.
export default function DocsIndexRedirect() {
  return <MetaRedirect to={`/${defaultLocale}/docs/introduction/`} />;
}
