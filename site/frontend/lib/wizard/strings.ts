// Localized strings for the config builder, per locale. Field LABELS stay as
// the YAML keys (dry_run, pps, networks, bgp…) — they are what you write in the
// file and what the docs reference verbatim — but every surrounding string
// (page chrome, section titles, field help, validation messages, the engine
// panel) is translated. EN field help is not duplicated here: it falls back to
// the overlay's `description` (see helpText in ConfigWizard).

import type { Locale } from "@/lib/i18n";

export type WizardValidation = {
  required: string;
  enum: string; // "{allowed}" placeholder
  identifier: string; // regex-pattern failure (env/db/group names)
  notNumber: string;
  min: string; // "{min}" placeholder
  max: string; // "{max}" placeholder
  formats: Record<string, string>; // keyed by overlay `format`: ipv4/ipv6/ip/cidr/hostport/community/url
};

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
  accepts: string; // engine-accepts panel label
  liveWarning: string;
  addItem: string;
  addNeighbor: string;
  steps: string[];
  back: string;
  next: string;
  reviewTitle: string;
  reviewIntro: string;
  sections: {
    mode: string;
    telemetry: string;
    networks: string;
    thresholds: string;
    bgp: string;
    mitigationMethod: string;
    perProtocol: string;
    ban: string;
    notify: string;
    api: string;
    updates: string;
  };
  validation: WizardValidation;
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
    accepts: "Engine accepts this config",
    liveWarning: "LIVE mode: real BGP blackhole announcements will be sent. Keep dry-run on until detection is validated.",
    addItem: "+ Add",
    addNeighbor: "+ Add neighbor",
    steps: ["Mode & telemetry", "Networks", "Thresholds", "Mitigation & BGP", "Ban, alerts & API", "Review & export"],
    back: "Back",
    next: "Next",
    reviewTitle: "Review & export",
    reviewIntro: "Check the engine result below, then copy or download your config.",
    sections: {
      mode: "Mode",
      telemetry: "Telemetry",
      networks: "Protected networks",
      thresholds: "Thresholds",
      bgp: "BGP / mitigation",
      mitigationMethod: "Mitigation method",
      perProtocol: "Per-protocol thresholds (optional)",
      ban: "Ban lifecycle",
      notify: "Notifications (Telegram)",
      api: "API",
      updates: "Updates",
    },
    validation: {
      required: "required",
      enum: "must be one of: {allowed}",
      identifier: 'invalid value (allowed: letters, digits, "_", "-", ".")',
      notNumber: "must be a number",
      min: "must be ≥ {min}",
      max: "must be ≤ {max}",
      formats: {
        ipv4: "must be an IPv4 address (e.g. 192.0.2.1)",
        ipv6: "must be an IPv6 address (e.g. 2001:db8::1)",
        ip: "must be an IP address",
        cidr: "must be a CIDR prefix (e.g. 203.0.113.0/24)",
        hostport: "must be host:port (e.g. :6343 or 127.0.0.1:8080)",
        community: "must be a BGP community ASN:value (e.g. 65000:666)",
        url: "must be an http(s) URL",
      },
    },
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
    accepts: "Движок принимает этот конфиг",
    liveWarning: "Боевой режим: реальные BGP-анонсы blackhole будут отправлены. Держите dry-run включённым, пока детект не выверен.",
    addItem: "+ Добавить",
    addNeighbor: "+ Добавить соседа",
    steps: ["Режим и телеметрия", "Сети", "Пороги", "Митигация и BGP", "Бан, алерты, API", "Обзор и экспорт"],
    back: "Назад",
    next: "Далее",
    reviewTitle: "Обзор и экспорт",
    reviewIntro: "Проверьте результат движка ниже, затем скопируйте или скачайте конфиг.",
    sections: {
      mode: "Режим",
      telemetry: "Телеметрия",
      networks: "Защищаемые сети",
      thresholds: "Пороги",
      bgp: "BGP / митигация",
      mitigationMethod: "Метод митигации",
      perProtocol: "Пороги по протоколам (опц.)",
      ban: "Жизненный цикл бана",
      notify: "Уведомления (Telegram)",
      api: "API",
      updates: "Обновления",
    },
    validation: {
      required: "обязательно",
      enum: "должно быть одним из: {allowed}",
      identifier: 'недопустимое значение (разрешены: буквы, цифры, "_", "-", ".")',
      notNumber: "должно быть числом",
      min: "должно быть ≥ {min}",
      max: "должно быть ≤ {max}",
      formats: {
        ipv4: "должно быть IPv4-адресом (напр. 192.0.2.1)",
        ipv6: "должно быть IPv6-адресом (напр. 2001:db8::1)",
        ip: "должно быть IP-адресом",
        cidr: "должно быть CIDR-префиксом (напр. 203.0.113.0/24)",
        hostport: "должно быть host:port (напр. :6343 или 127.0.0.1:8080)",
        community: "должно быть BGP-community вида ASN:value (напр. 65000:666)",
        url: "должно быть http(s)-URL",
      },
    },
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
    accepts: "Engine akzeptiert diese Konfiguration",
    liveWarning: "LIVE-Modus: echte BGP-Blackhole-Ankündigungen werden gesendet. Lassen Sie Dry-Run an, bis die Erkennung validiert ist.",
    addItem: "+ Hinzufügen",
    addNeighbor: "+ Nachbarn hinzufügen",
    steps: ["Modus & Telemetrie", "Netze", "Schwellen", "Mitigation & BGP", "Ban, Alerts, API", "Prüfen & Export"],
    back: "Zurück",
    next: "Weiter",
    reviewTitle: "Prüfen & exportieren",
    reviewIntro: "Prüfen Sie das Engine-Ergebnis unten, dann kopieren oder laden Sie die Konfiguration herunter.",
    sections: {
      mode: "Modus",
      telemetry: "Telemetrie",
      networks: "Geschützte Netze",
      thresholds: "Schwellenwerte",
      bgp: "BGP / Mitigation",
      mitigationMethod: "Mitigationsmethode",
      perProtocol: "Schwellen pro Protokoll (optional)",
      ban: "Ban-Lebenszyklus",
      notify: "Benachrichtigungen (Telegram)",
      api: "API",
      updates: "Updates",
    },
    validation: {
      required: "erforderlich",
      enum: "muss eines von: {allowed} sein",
      identifier: 'ungültiger Wert (erlaubt: Buchstaben, Ziffern, "_", "-", ".")',
      notNumber: "muss eine Zahl sein",
      min: "muss ≥ {min} sein",
      max: "muss ≤ {max} sein",
      formats: {
        ipv4: "muss eine IPv4-Adresse sein (z. B. 192.0.2.1)",
        ipv6: "muss eine IPv6-Adresse sein (z. B. 2001:db8::1)",
        ip: "muss eine IP-Adresse sein",
        cidr: "muss ein CIDR-Präfix sein (z. B. 203.0.113.0/24)",
        hostport: "muss host:port sein (z. B. :6343 oder 127.0.0.1:8080)",
        community: "muss eine BGP-Community ASN:Wert sein (z. B. 65000:666)",
        url: "muss eine http(s)-URL sein",
      },
    },
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
    accepts: "Le moteur accepte cette configuration",
    liveWarning: "Mode LIVE : de vraies annonces BGP blackhole seront envoyées. Gardez le dry-run activé jusqu'à validation de la détection.",
    addItem: "+ Ajouter",
    addNeighbor: "+ Ajouter un voisin",
    steps: ["Mode & télémétrie", "Réseaux", "Seuils", "Atténuation & BGP", "Ban, alertes, API", "Vérifier & exporter"],
    back: "Précédent",
    next: "Suivant",
    reviewTitle: "Vérifier & exporter",
    reviewIntro: "Vérifiez le résultat du moteur ci-dessous, puis copiez ou téléchargez votre configuration.",
    sections: {
      mode: "Mode",
      telemetry: "Télémétrie",
      networks: "Réseaux protégés",
      thresholds: "Seuils",
      bgp: "BGP / atténuation",
      mitigationMethod: "Méthode d'atténuation",
      perProtocol: "Seuils par protocole (option.)",
      ban: "Cycle de vie du ban",
      notify: "Notifications (Telegram)",
      api: "API",
      updates: "Mises à jour",
    },
    validation: {
      required: "requis",
      enum: "doit être l'un de : {allowed}",
      identifier: 'valeur invalide (autorisés : lettres, chiffres, "_", "-", ".")',
      notNumber: "doit être un nombre",
      min: "doit être ≥ {min}",
      max: "doit être ≤ {max}",
      formats: {
        ipv4: "doit être une adresse IPv4 (p. ex. 192.0.2.1)",
        ipv6: "doit être une adresse IPv6 (p. ex. 2001:db8::1)",
        ip: "doit être une adresse IP",
        cidr: "doit être un préfixe CIDR (p. ex. 203.0.113.0/24)",
        hostport: "doit être host:port (p. ex. :6343 ou 127.0.0.1:8080)",
        community: "doit être une communauté BGP ASN:valeur (p. ex. 65000:666)",
        url: "doit être une URL http(s)",
      },
    },
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
    accepts: "El motor acepta esta configuración",
    liveWarning: "Modo LIVE: se enviarán anuncios BGP blackhole reales. Mantén dry-run activado hasta validar la detección.",
    addItem: "+ Añadir",
    addNeighbor: "+ Añadir vecino",
    steps: ["Modo y telemetría", "Redes", "Umbrales", "Mitigación y BGP", "Ban, alertas, API", "Revisar y exportar"],
    back: "Atrás",
    next: "Siguiente",
    reviewTitle: "Revisar y exportar",
    reviewIntro: "Revisa el resultado del motor abajo y luego copia o descarga tu configuración.",
    sections: {
      mode: "Modo",
      telemetry: "Telemetría",
      networks: "Redes protegidas",
      thresholds: "Umbrales",
      bgp: "BGP / mitigación",
      mitigationMethod: "Método de mitigación",
      perProtocol: "Umbrales por protocolo (opc.)",
      ban: "Ciclo de vida del baneo",
      notify: "Notificaciones (Telegram)",
      api: "API",
      updates: "Actualizaciones",
    },
    validation: {
      required: "obligatorio",
      enum: "debe ser uno de: {allowed}",
      identifier: 'valor no válido (permitidos: letras, dígitos, "_", "-", ".")',
      notNumber: "debe ser un número",
      min: "debe ser ≥ {min}",
      max: "debe ser ≤ {max}",
      formats: {
        ipv4: "debe ser una dirección IPv4 (p. ej. 192.0.2.1)",
        ipv6: "debe ser una dirección IPv6 (p. ej. 2001:db8::1)",
        ip: "debe ser una dirección IP",
        cidr: "debe ser un prefijo CIDR (p. ej. 203.0.113.0/24)",
        hostport: "debe ser host:port (p. ej. :6343 o 127.0.0.1:8080)",
        community: "debe ser una comunidad BGP ASN:valor (p. ej. 65000:666)",
        url: "debe ser una URL http(s)",
      },
    },
  },
};

// Localized field help, keyed by yaml path. EN is intentionally absent — it
// falls back to the overlay's `description` (the single English source).
export const wizardHelp: Partial<Record<Locale, Record<string, string>>> = {
  ru: {
    dry_run: "Если включено (по умолчанию, в т.ч. при отсутствии ключа), митигация имитируется и никогда не анонсируется. Держите включённым, пока детект не выверен на живой телеметрии.",
    "listen.sflow": 'UDP-адрес для приёма sFlow, напр. ":6343". Нужен хотя бы один из sflow/netflow.',
    "listen.netflow": 'UDP-адрес для NetFlow v5/v9 и IPFIX (общий сокет), напр. ":2055".',
    "sampling.default_rate": "Частота сэмплирования, когда экспортёр не сообщает свою. Ошибка здесь масштабирует ВСЕ пороги — ставьте значение, которое реально экспортируют роутеры.",
    networks: "Защищаемые префиксы. Детект применяется только внутри них; они не должны пересекаться.",
    protected_whitelist: "Адреса, которые никогда не банятся независимо от трафика (шлюзы, NS).",
    "thresholds.pps": "Порог пакетов/с на хост (реальные, несэмплированные единицы). Обязателен, > 0.",
    "thresholds.mbps": "Порог мегабит/с на хост. Обязателен, > 0.",
    "thresholds.flows_per_sec": "Порог потоков/с на хост. Обязателен, > 0.",
    "thresholds.tcp_syn_pps": "Необязательный лимит чистых SYN-пакетов/с; 0 или отсутствие отключает.",
    "thresholds.udp_pps": "Необязательный лимит UDP-пакетов/с; 0 или отсутствие отключает.",
    mitigation: "Метод митигации по умолчанию. blackhole отбрасывает весь трафик жертвы; flowspec — точечно; divert уводит трафик в центр очистки.",
    "bgp.local_asn": "Локальный BGP AS-номер Kapkan.",
    "bgp.router_id": "BGP router ID; должен быть IPv4 в формате a.b.c.d.",
    "bgp.next_hop": "IPv4 next-hop для blackhole (discard).",
    "bgp.next_hop6": "IPv6 next-hop для blackhole (нужен, если защищается и блэкхолится IPv6).",
    "bgp.community": "RTBH-community, которое принимает ваш аплинк, вида ASN:value.",
    "bgp.neighbors.address": "Адрес eBGP-соседа.",
    "ban.ttl_seconds": "Каждый анонс автоматически снимается через столько секунд. Постоянных банов нет.",
    "ban.unban_hysteresis_seconds": "Трафик должен держаться ниже порога столько времени до снятия бана (антифлап).",
    "ban.max_active_bans": "Жёсткий лимит одновременных банов; сверх лимита новые отклоняются.",
    "notify.telegram.token_env": "Имя переменной окружения с токеном Telegram-бота (не сам токен).",
    "notify.telegram.chat_id": "ID чата Telegram для отправки алертов.",
    "api.listen": "Адрес прослушивания REST API и метрик (по умолчанию 127.0.0.1:8080).",
    "api.token_env": "Имя переменной окружения с операторским bearer-токеном.",
  },
  de: {
    dry_run: "Wenn aktiv (Standard, auch bei fehlendem Schlüssel), wird Mitigation simuliert und nie angekündigt. Lassen Sie es an, bis die Erkennung an Live-Telemetrie validiert ist.",
    "listen.sflow": 'UDP-Adresse für sFlow, z. B. ":6343". Mindestens eines von sflow/netflow ist nötig.',
    "listen.netflow": 'UDP-Adresse für NetFlow v5/v9 und IPFIX (gemeinsamer Socket), z. B. ":2055".',
    "sampling.default_rate": "Sampling-Rate, wenn ein Exporter seine eigene nicht meldet. Ein Fehler hier skaliert JEDEN Schwellenwert — setzen Sie, was Ihre Router tatsächlich exportieren.",
    networks: "Geschützte Präfixe. Erkennung gilt nur innerhalb davon; sie dürfen sich nicht überlappen.",
    protected_whitelist: "Adressen, die nie gebannt werden, unabhängig vom Verkehr (Gateways, Nameserver).",
    "thresholds.pps": "Pakete/s-Schwelle pro Host (reale, ungesampelte Einheiten). Erforderlich, > 0.",
    "thresholds.mbps": "Megabit/s-Schwelle pro Host. Erforderlich, > 0.",
    "thresholds.flows_per_sec": "Flows/s-Schwelle pro Host. Erforderlich, > 0.",
    "thresholds.tcp_syn_pps": "Optionales Limit für reine SYN-Pakete/s; 0 oder fehlend deaktiviert es.",
    "thresholds.udp_pps": "Optionales Limit für UDP-Pakete/s; 0 oder fehlend deaktiviert es.",
    mitigation: "Standard-Mitigationsmethode. blackhole verwirft den gesamten Opferverkehr; flowspec ist chirurgisch; divert leitet zum Scrubbing-Center um.",
    "bgp.local_asn": "Lokale BGP-AS-Nummer von Kapkan.",
    "bgp.router_id": "BGP-Router-ID; muss eine IPv4 im Format a.b.c.d sein.",
    "bgp.next_hop": "IPv4-Next-Hop für Blackhole (Discard).",
    "bgp.next_hop6": "IPv6-Next-Hop für Blackhole (nötig, wenn IPv6 geschützt und geblackholt wird).",
    "bgp.community": "RTBH-Community, die Ihr Upstream akzeptiert, als ASN:Wert.",
    "bgp.neighbors.address": "Adresse des eBGP-Nachbarn.",
    "ban.ttl_seconds": "Jede Ankündigung wird nach so vielen Sekunden automatisch zurückgezogen. Keine dauerhaften Bans.",
    "ban.unban_hysteresis_seconds": "Der Verkehr muss so lange unter der Schwelle bleiben, bevor ein Ban aufgehoben wird (Anti-Flapping).",
    "ban.max_active_bans": "Hartes Limit gleichzeitiger Bans; darüber hinaus werden neue abgelehnt.",
    "notify.telegram.token_env": "Name der Umgebungsvariable mit dem Telegram-Bot-Token (nicht das Token selbst).",
    "notify.telegram.chat_id": "Telegram-Chat-ID für Alerts.",
    "api.listen": "Listen-Adresse für REST-API und Metriken (Standard 127.0.0.1:8080).",
    "api.token_env": "Name der Umgebungsvariable mit einem Operator-Bearer-Token.",
  },
  fr: {
    dry_run: "Si activé (par défaut, y compris clé absente), l'atténuation est simulée et jamais annoncée. Gardez-le activé jusqu'à validation de la détection sur la télémétrie réelle.",
    "listen.sflow": 'Adresse UDP d\'écoute pour sFlow, p. ex. ":6343". Au moins un de sflow/netflow est requis.',
    "listen.netflow": 'Adresse UDP pour NetFlow v5/v9 et IPFIX (socket partagé), p. ex. ":2055".',
    "sampling.default_rate": "Taux d'échantillonnage supposé quand un exporteur ne signale pas le sien. Une erreur ici met à l'échelle TOUS les seuils — mettez ce que vos routeurs exportent réellement.",
    networks: "Préfixes protégés. La détection ne s'applique qu'à l'intérieur ; ils ne doivent pas se chevaucher.",
    protected_whitelist: "Adresses jamais bannies, quel que soit le trafic (passerelles, serveurs de noms).",
    "thresholds.pps": "Seuil paquets/s par hôte (unités réelles, non échantillonnées). Requis, > 0.",
    "thresholds.mbps": "Seuil mégabits/s par hôte. Requis, > 0.",
    "thresholds.flows_per_sec": "Seuil flux/s par hôte. Requis, > 0.",
    "thresholds.tcp_syn_pps": "Limite optionnelle de paquets SYN purs/s ; 0 ou absent la désactive.",
    "thresholds.udp_pps": "Limite optionnelle de paquets UDP/s ; 0 ou absent la désactive.",
    mitigation: "Méthode d'atténuation par défaut. blackhole supprime tout le trafic de la victime ; flowspec est chirurgical ; divert envoie vers un centre de nettoyage.",
    "bgp.local_asn": "Numéro d'AS BGP local de Kapkan.",
    "bgp.router_id": "Router ID BGP ; doit être une IPv4 au format a.b.c.d.",
    "bgp.next_hop": "Next-hop IPv4 pour le blackhole (discard).",
    "bgp.next_hop6": "Next-hop IPv6 pour le blackhole (requis si de l'IPv6 est protégé et blackholé).",
    "bgp.community": "Communauté RTBH acceptée par votre transit, sous forme ASN:valeur.",
    "bgp.neighbors.address": "Adresse du voisin eBGP.",
    "ban.ttl_seconds": "Chaque annonce se retire automatiquement après ce nombre de secondes. Pas de bans permanents.",
    "ban.unban_hysteresis_seconds": "Le trafic doit rester sous le seuil pendant ce temps avant la levée d'un ban (anti-battement).",
    "ban.max_active_bans": "Plafond strict de bans simultanés ; au-delà, les nouveaux sont refusés.",
    "notify.telegram.token_env": "Nom de la variable d'environnement contenant le token du bot Telegram (jamais le token).",
    "notify.telegram.chat_id": "ID de chat Telegram où poster les alertes.",
    "api.listen": "Adresse d'écoute de l'API REST et des métriques (défaut 127.0.0.1:8080).",
    "api.token_env": "Nom de la variable d'environnement contenant un token bearer opérateur.",
  },
  es: {
    dry_run: "Si está activo (por defecto, incluso sin la clave), la mitigación se simula y nunca se anuncia. Mantenlo activado hasta validar la detección con telemetría real.",
    "listen.sflow": 'Dirección UDP de escucha para sFlow, p. ej. ":6343". Se requiere al menos uno de sflow/netflow.',
    "listen.netflow": 'Dirección UDP para NetFlow v5/v9 e IPFIX (socket compartido), p. ej. ":2055".',
    "sampling.default_rate": "Tasa de muestreo asumida cuando un exportador no informa la suya. Un error aquí escala TODOS los umbrales — pon lo que tus routers exportan realmente.",
    networks: "Prefijos protegidos. La detección solo aplica dentro de ellos; no deben solaparse.",
    protected_whitelist: "Direcciones que nunca se banean, sin importar el tráfico (gateways, servidores de nombres).",
    "thresholds.pps": "Umbral de paquetes/s por host (unidades reales, sin muestrear). Obligatorio, > 0.",
    "thresholds.mbps": "Umbral de megabits/s por host. Obligatorio, > 0.",
    "thresholds.flows_per_sec": "Umbral de flujos/s por host. Obligatorio, > 0.",
    "thresholds.tcp_syn_pps": "Límite opcional de paquetes SYN puros/s; 0 o ausente lo desactiva.",
    "thresholds.udp_pps": "Límite opcional de paquetes UDP/s; 0 o ausente lo desactiva.",
    mitigation: "Método de mitigación por defecto. blackhole descarta todo el tráfico de la víctima; flowspec es quirúrgico; divert lo desvía a un centro de limpieza.",
    "bgp.local_asn": "Número de AS BGP local de Kapkan.",
    "bgp.router_id": "Router ID de BGP; debe ser una IPv4 en formato a.b.c.d.",
    "bgp.next_hop": "Next-hop IPv4 para el blackhole (descarte).",
    "bgp.next_hop6": "Next-hop IPv6 para el blackhole (necesario si se protege y blackholea IPv6).",
    "bgp.community": "Comunidad RTBH que acepta tu upstream, como ASN:valor.",
    "bgp.neighbors.address": "Dirección del vecino eBGP.",
    "ban.ttl_seconds": "Cada anuncio se retira automáticamente tras estos segundos. No hay baneos permanentes.",
    "ban.unban_hysteresis_seconds": "El tráfico debe quedar bajo el umbral este tiempo antes de retirar un baneo (anti-aleteo).",
    "ban.max_active_bans": "Tope estricto de baneos simultáneos; por encima, los nuevos se rechazan.",
    "notify.telegram.token_env": "Nombre de la variable de entorno con el token del bot de Telegram (nunca el token).",
    "notify.telegram.chat_id": "ID del chat de Telegram donde publicar alertas.",
    "api.listen": "Dirección de escucha de la API REST y métricas (por defecto 127.0.0.1:8080).",
    "api.token_env": "Nombre de la variable de entorno con un token bearer de operador.",
  },
};
