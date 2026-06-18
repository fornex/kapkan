// Locales and all UI/nav translations for the docs site. Page body content
// lives in content/docs/<lang>/<slug>.mdx; this file holds the chrome strings
// (sidebar group + page titles, prev/next labels, language names).

export const locales = ["en", "ru", "de", "fr", "es"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "en";

export function isLocale(value: string): value is Locale {
  return (locales as readonly string[]).includes(value);
}

export const localeNames: Record<Locale, string> = {
  en: "English",
  ru: "Русский",
  de: "Deutsch",
  fr: "Français",
  es: "Español",
};

// Short label shown after the wordmark in the docs top bar.
export const docsLabel = "docs";

export const ui: Record<Locale, { previous: string; next: string; language: string }> = {
  en: { previous: "Previous", next: "Next", language: "Language" },
  ru: { previous: "Назад", next: "Далее", language: "Язык" },
  de: { previous: "Zurück", next: "Weiter", language: "Sprache" },
  fr: { previous: "Précédent", next: "Suivant", language: "Langue" },
  es: { previous: "Anterior", next: "Siguiente", language: "Idioma" },
};

export const groupTitles: Record<Locale, Record<string, string>> = {
  en: {
    "getting-started": "Getting Started",
    configuration: "Configuration",
    mitigation: "Mitigation",
    operating: "Operating",
    deployment: "Deployment",
  },
  ru: {
    "getting-started": "Начало работы",
    configuration: "Конфигурация",
    mitigation: "Митигация",
    operating: "Эксплуатация",
    deployment: "Развёртывание",
  },
  de: {
    "getting-started": "Erste Schritte",
    configuration: "Konfiguration",
    mitigation: "Mitigation",
    operating: "Betrieb",
    deployment: "Deployment",
  },
  fr: {
    "getting-started": "Premiers pas",
    configuration: "Configuration",
    mitigation: "Atténuation",
    operating: "Exploitation",
    deployment: "Déploiement",
  },
  es: {
    "getting-started": "Primeros pasos",
    configuration: "Configuración",
    mitigation: "Mitigación",
    operating: "Operación",
    deployment: "Despliegue",
  },
};

// Per-locale page titles, keyed by slug. These are the canonical titles used in
// the sidebar AND must match each page's H1 / metadata.title (translators are
// given these verbatim).
export const pageTitles: Record<Locale, Record<string, string>> = {
  en: {
    introduction: "Introduction",
    quickstart: "Quickstart",
    "how-it-works": "How it works",
    configuration: "Configuration reference",
    detection: "Detection & thresholds",
    hostgroups: "Hostgroups",
    baselines: "Baselines",
    mitigation: "RTBH mitigation",
    flowspec: "FlowSpec mitigation",
    scrubbing: "Traffic diversion (scrubbing)",
    escalation: "Escalation ladders",
    storage: "Storage (ClickHouse)",
    safety: "Safety model",
    "going-live": "Going live",
    api: "REST API",
    dashboard: "Dashboard",
    authentication: "Authentication",
    "multi-tenancy": "Multi-tenancy",
    notifications: "Notifications",
    metrics: "Metrics",
    deployment: "Production deployment",
  },
  ru: {
    introduction: "Введение",
    quickstart: "Быстрый старт",
    "how-it-works": "Как это работает",
    configuration: "Справочник конфигурации",
    detection: "Детектирование и пороги",
    hostgroups: "Хост-группы",
    baselines: "Базовые уровни",
    mitigation: "RTBH-митигация",
    flowspec: "FlowSpec-митигация",
    scrubbing: "Отвод трафика (scrubbing)",
    escalation: "Лестницы эскалации",
    storage: "Хранилище (ClickHouse)",
    safety: "Модель безопасности",
    "going-live": "Запуск в продакшн",
    api: "REST API",
    dashboard: "Дашборд",
    authentication: "Аутентификация",
    "multi-tenancy": "Мультиарендность",
    notifications: "Уведомления",
    metrics: "Метрики",
    deployment: "Развёртывание в продакшене",
  },
  de: {
    introduction: "Einführung",
    quickstart: "Schnellstart",
    "how-it-works": "Funktionsweise",
    configuration: "Konfigurationsreferenz",
    detection: "Erkennung & Schwellenwerte",
    hostgroups: "Hostgruppen",
    baselines: "Baselines",
    mitigation: "RTBH-Mitigation",
    flowspec: "FlowSpec-Mitigation",
    scrubbing: "Traffic-Umleitung (Scrubbing)",
    escalation: "Eskalationsstufen",
    storage: "Speicherung (ClickHouse)",
    safety: "Sicherheitsmodell",
    "going-live": "Inbetriebnahme",
    api: "REST-API",
    dashboard: "Dashboard",
    authentication: "Authentifizierung",
    "multi-tenancy": "Mandantenfähigkeit",
    notifications: "Benachrichtigungen",
    metrics: "Metriken",
    deployment: "Produktiv-Deployment",
  },
  fr: {
    introduction: "Introduction",
    quickstart: "Démarrage rapide",
    "how-it-works": "Fonctionnement",
    configuration: "Référence de configuration",
    detection: "Détection et seuils",
    hostgroups: "Groupes d'hôtes",
    baselines: "Lignes de base",
    mitigation: "Atténuation RTBH",
    flowspec: "Atténuation FlowSpec",
    scrubbing: "Déviation du trafic (scrubbing)",
    escalation: "Paliers d'escalade",
    storage: "Stockage (ClickHouse)",
    safety: "Modèle de sécurité",
    "going-live": "Mise en production",
    api: "API REST",
    dashboard: "Tableau de bord",
    authentication: "Authentification",
    "multi-tenancy": "Multi-tenant",
    notifications: "Notifications",
    metrics: "Métriques",
    deployment: "Déploiement en production",
  },
  es: {
    introduction: "Introducción",
    quickstart: "Inicio rápido",
    "how-it-works": "Cómo funciona",
    configuration: "Referencia de configuración",
    detection: "Detección y umbrales",
    hostgroups: "Grupos de hosts",
    baselines: "Líneas base",
    mitigation: "Mitigación RTBH",
    flowspec: "Mitigación FlowSpec",
    scrubbing: "Desvío de tráfico (scrubbing)",
    escalation: "Escalado progresivo",
    storage: "Almacenamiento (ClickHouse)",
    safety: "Modelo de seguridad",
    "going-live": "Puesta en producción",
    api: "API REST",
    dashboard: "Panel de control",
    authentication: "Autenticación",
    "multi-tenancy": "Multi-tenencia",
    notifications: "Notificaciones",
    metrics: "Métricas",
    deployment: "Despliegue en producción",
  },
};
