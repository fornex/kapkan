// Page-level chrome for the config builder, per locale. Field labels themselves
// stay in English — they are the YAML keys (dry_run, pps, networks, bgp…) and
// the docs reference uses them verbatim.

import type { Locale } from "@/lib/i18n";

export type WizardChrome = {
  title: string;
  intro: string;
  privacy: string;
  basic: string;
  advanced: string;
  output: string;
  copy: string;
  copied: string;
  download: string;
  checkHint: string;
  docsCta: string;
};

export const wizardChrome: Record<Locale, WizardChrome> = {
  en: {
    title: "Config builder",
    intro: "Assemble a Kapkan configuration file step by step. Sensible, dry-run-safe defaults are filled in — adjust them to your network.",
    privacy: "Runs entirely in your browser. Nothing you enter is sent anywhere.",
    basic: "Basic",
    advanced: "Advanced",
    output: "Generated config",
    copy: "Copy",
    copied: "Copied",
    download: "Download kapkan.yaml",
    checkHint: "Validate on your host before going live:",
    docsCta: "Configuration reference",
  },
  ru: {
    title: "Конструктор конфигурации",
    intro: "Соберите конфиг Kapkan по шагам. Безопасные значения по умолчанию (dry-run включён) уже подставлены — подгоните под свою сеть.",
    privacy: "Работает полностью в браузере. Ничего из введённого никуда не отправляется.",
    basic: "Основное",
    advanced: "Дополнительно",
    output: "Готовый конфиг",
    copy: "Копировать",
    copied: "Скопировано",
    download: "Скачать kapkan.yaml",
    checkHint: "Проверьте на своём хосте перед запуском в продакшн:",
    docsCta: "Справочник конфигурации",
  },
  de: {
    title: "Konfigurations-Builder",
    intro: "Erstellen Sie eine Kapkan-Konfiguration Schritt für Schritt. Sichere Standardwerte (Dry-Run aktiv) sind vorausgefüllt — passen Sie sie an Ihr Netz an.",
    privacy: "Läuft vollständig im Browser. Nichts von dem, was Sie eingeben, wird übertragen.",
    basic: "Basis",
    advanced: "Erweitert",
    output: "Erzeugte Konfiguration",
    copy: "Kopieren",
    copied: "Kopiert",
    download: "kapkan.yaml herunterladen",
    checkHint: "Vor dem Live-Betrieb auf Ihrem Host prüfen:",
    docsCta: "Konfigurationsreferenz",
  },
  fr: {
    title: "Générateur de configuration",
    intro: "Composez un fichier de configuration Kapkan étape par étape. Des valeurs par défaut sûres (dry-run activé) sont pré-remplies — adaptez-les à votre réseau.",
    privacy: "Fonctionne entièrement dans votre navigateur. Rien de ce que vous saisissez n'est envoyé.",
    basic: "Essentiel",
    advanced: "Avancé",
    output: "Configuration générée",
    copy: "Copier",
    copied: "Copié",
    download: "Télécharger kapkan.yaml",
    checkHint: "Validez sur votre hôte avant la mise en production :",
    docsCta: "Référence de configuration",
  },
  es: {
    title: "Generador de configuración",
    intro: "Arma un archivo de configuración de Kapkan paso a paso. Se rellenan valores por defecto seguros (dry-run activado) — ajústalos a tu red.",
    privacy: "Se ejecuta por completo en tu navegador. Nada de lo que introduces se envía a ningún sitio.",
    basic: "Básico",
    advanced: "Avanzado",
    output: "Configuración generada",
    copy: "Copiar",
    copied: "Copiado",
    download: "Descargar kapkan.yaml",
    checkHint: "Valida en tu host antes de pasar a producción:",
    docsCta: "Referencia de configuración",
  },
};
