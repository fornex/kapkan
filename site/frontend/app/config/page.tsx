import { defaultLocale } from "@/lib/i18n";
import { MetaRedirect } from "@/components/MetaRedirect";

// Bare /config → default-locale config builder. Lets the landing page and any
// non-localized link reach the wizard.
export default function ConfigIndexRedirect() {
  return <MetaRedirect to={`/${defaultLocale}/config/`} />;
}
