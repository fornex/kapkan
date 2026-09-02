// All translatable copy for the marketing landing page, per locale. The page
// chrome/structure lives in components/Landing.tsx; this file holds only the
// strings. Technical terms (NetFlow, IPFIX, sFlow, BGP, RTBH, FlowSpec, pps,
// Mbps, Gbps, API, Apache 2.0, …) are intentionally left untranslated.

import type { Locale } from "@/lib/i18n";

export type LandingDict = {
  meta: { title: string; description: string };
  nav: {
    features: string;
    how: string;
    compare: string;
    docs: string;
    star: string;
    readDocs: string;
    buildConfig: string;
    viewGithub: string;
    menu: string;
    docFull: string;
    underAttack: string;
  };
  hero: { eyebrow: string; h1a: string; h1b: string; sub: string; trust: string[] };
  stats: string[];
  how: { heading: string; sub: string; steps: { title: string; body: string }[] };
  features: { heading: string; sub: string; learnMore: string; cards: { title: string; body: string }[] };
  showcase: { heading: string; sub: string };
  compare: {
    heading: string;
    sub: string;
    colFeature: string;
    colKapkan: string;
    colThem: string;
    rows: { feature: string; kapkan: string; them: string }[];
  };
  quickstart: { heading: string; bodyBefore: string; bodyAfter: string; cta: string };
  cta: { heading: string; sub: string };
  footer: {
    tagline: string;
    product: string;
    docsCol: string;
    project: string;
    features: string;
    compare: string;
    configBuilder: string;
    quickstart: string;
    configuration: string;
    api: string;
    safety: string;
    github: string;
    releases: string;
    license: string;
  };
};

const en: LandingDict = {
  meta: {
    title: "Kapkan — Free, open-source DDoS detection & mitigation",
    description:
      "Kapkan is one Go binary. It reads the traffic stats your routers already export (NetFlow, IPFIX, sFlow), spots a DDoS flood against the IPs you protect in seconds, and stops it — by telling your router to drop it (BGP RTBH/FlowSpec) or by dropping it itself in the Linux kernel (XDP). Free and open source.",
  },
  nav: {
    features: "Features",
    how: "How it works",
    compare: "Compare",
    docs: "Docs",
    star: "Star on GitHub",
    readDocs: "Read the docs",
    buildConfig: "Build a config",
    viewGithub: "View on GitHub",
    menu: "Menu",
    docFull: "View full documentation",
    underAttack: "Under attack now?",
  },
  hero: {
    eyebrow: "Open Source · Apache 2.0",
    h1a: "Stop DDoS floods in seconds",
    h1b: "with one binary.",
    sub: "Kapkan reads the traffic stats your routers already export (NetFlow, IPFIX, sFlow), spots a flood against the IPs you protect within seconds, and stops it: by telling your router to drop the attack, or by dropping it itself in the Linux kernel. Free, open source, and in watch-only mode until you say otherwise.",
    trust: ["One Go binary", "Nothing else to install", "Watch-only by default", "IPv4 + IPv6"],
  },
  stats: ["≥20M flows/sec/core", "Detects in seconds", "IPv4 + IPv6 blackhole", "FlowSpec RFC 8955/8956", "One static binary"],
  how: {
    heading: "How it works",
    sub: "One binary, nothing else to run: no extra services, no message queue, no database. Point your routers at it and go.",
    steps: [
      {
        title: "INGEST",
        body: "Point your routers at Kapkan. They already send a summary of every traffic flow (NetFlow, IPFIX or sFlow), so just aim it at Kapkan's port. One process reads it all; there's nothing else to install.",
      },
      {
        title: "DETECT",
        body: "Kapkan counts packets, bits and connections per second for each IP you protect. Cross a limit you set, or one it learned from that host's normal traffic, and that's an attack, flagged within seconds.",
      },
      {
        title: "MITIGATE",
        body: "Kapkan tells your router to drop the attack over BGP. It can null-route the whole target IP (RTBH), or drop only the attack traffic and keep the rest flowing (FlowSpec). Once the flood stops, it removes the rule itself.",
      },
      {
        title: "DROP",
        body: "Or skip the router: if the traffic crosses the machine Kapkan runs on, it can drop the attack itself inside the Linux kernel (XDP), the moment packets arrive. Every rule has an expiry the kernel enforces, so a crashed Kapkan can't keep dropping your traffic.",
      },
    ],
  },
  features: {
    heading: "What it does",
    sub: "Detection, mitigation, an operator console and the safety rails to run it in production, in one Apache 2.0 binary. Commercial flow-DDoS products sell these as separate modules.",
    learnMore: "See how in-kernel drop works",
    cards: [
      { title: "Reads the flows you already export", body: "sFlow v5, NetFlow v5/v9 and IPFIX over UDP, read by Kapkan itself. No extra service to run." },
      { title: "Spots floods in under a second", body: "Packet, bit and flow-per-second limits over a sliding window, corrected for sampling. ≥20M flows/sec per core." },
      { title: "Blackhole, or drop just the attack", body: "Null-route the whole target IP (RTBH), or drop only the attack traffic and keep the rest (FlowSpec). Full IPv6 support, on par with IPv4." },
      { title: "Tells you what kind of attack", body: "Amplification (NTP/DNS/memcached), SYN/UDP/ICMP floods, each with a plain 'why this fired' breakdown." },
      { title: "Learns each host's normal", body: "Kapkan learns what normal traffic looks like for every host and tightens the limits on its own. No hand-tuning." },
      { title: "Hard to misfire", body: "Starts in watch-only mode. Every block has an expiry and lifts itself, a cap limits how many hosts can be blocked at once, and your protected list is never blocked, not by Kapkan and not by you." },
      { title: "Catches carpet-bombing", body: "Spots low-and-slow floods spread across a whole IP range that stay under any single host's limit." },
      { title: "Watch it from anywhere", body: "REST API, Prometheus /metrics, and alerts over Telegram, Slack, email, webhook or a script you run." },
      { title: "Multi-tenant & audited", body: "Scope access per tenant, hand out viewer/operator API tokens, and get an audit log that names who did what." },
      {
        title: "In-kernel mitigation with XDP",
        body: "Instead of asking a router to drop the attack, Kapkan can do it itself. The same rules it would announce as FlowSpec load straight into the Linux kernel and run there (XDP), including a separate rate limit for each attacking source, which BGP FlowSpec can't do. Needs Linux 5.15+, compiles nothing on the box, and every rule expires inside the kernel, so a crashed Kapkan can't leave your traffic dropped. Still watch-only by default.",
      },
    ],
  },
  showcase: {
    heading: "The operator console",
    sub: "Kapkan ships with a live web console for your on-call: attacks, hosts and blocks in one place. No digging through raw logs.",
  },
  compare: {
    heading: "Compared with commercial tools",
    sub: "One static binary instead of a licensed appliance and a set of daemons.",
    colFeature: "Feature",
    colKapkan: "Kapkan",
    colThem: "Commercial tools",
    rows: [
      { feature: "License", kapkan: "Free & open source (Apache 2.0)", them: "Paid license / volume-based" },
      { feature: "Operator console", kapkan: "Included free", them: "Paid add-on" },
      { feature: "IPv6 support", kapkan: "Full, same as IPv4", them: "Missing or planned" },
      { feature: "Threshold tuning", kapkan: "Learns automatically", them: "Offline calculator, copy-paste" },
      { feature: "Automation", kapkan: "Escalation rules in config", them: "Custom bash scripts" },
      { feature: "Architecture", kapkan: "One static binary, no extras", them: "Several daemons to run" },
      { feature: "In-kernel drop", kapkan: "Built in, drops in Linux itself (XDP)", them: "Separate scrubbing appliance" },
    ],
  },
  quickstart: {
    heading: "Running in minutes, watch-only first",
    bodyBefore:
      "Kapkan is safe to run out of the box. It logs every block it would make and shows it in the API and console, but never announces anything to your routers until you explicitly set ",
    bodyAfter: ".",
    cta: "View full documentation",
  },
  cta: { heading: "Set the trap", sub: "Free, Apache 2.0, running in an afternoon. Start in watch-only mode and see what it would have blocked." },
  footer: {
    tagline: "Free, open-source DDoS detection and mitigation. Announce it, or drop it yourself.",
    product: "Product",
    docsCol: "Docs",
    project: "Project",
    features: "Features",
    compare: "Compare",
    configBuilder: "Config builder",
    quickstart: "Quickstart",
    configuration: "Configuration",
    api: "API",
    safety: "Safety model",
    github: "GitHub",
    releases: "Releases",
    license: "License (Apache 2.0)",
  },
};

const ru: LandingDict = {
  meta: {
    title: "Kapkan — бесплатное open-source обнаружение и подавление DDoS",
    description:
      "Kapkan — один Go-бинарник. Он читает статистику трафика, которую ваши маршрутизаторы и так экспортируют (NetFlow, IPFIX, sFlow), за секунды замечает DDoS-флуд на защищаемые вами адреса и останавливает его — командой маршрутизатору сбросить трафик (BGP RTBH/FlowSpec) или сбрасывая его сам в ядре Linux (XDP). Бесплатно и с открытым кодом.",
  },
  nav: {
    features: "Возможности",
    how: "Как работает",
    compare: "Сравнение",
    docs: "Документация",
    star: "Звезда на GitHub",
    readDocs: "Документация",
    buildConfig: "Собрать конфиг",
    viewGithub: "Открыть на GitHub",
    menu: "Меню",
    docFull: "Вся документация",
    underAttack: "Идёт атака?",
  },
  hero: {
    eyebrow: "Open Source · Apache 2.0",
    h1a: "Останавливайте DDoS-флуд за секунды",
    h1b: "одним бинарником.",
    sub: "Kapkan читает статистику трафика, которую ваши маршрутизаторы и так экспортируют (NetFlow, IPFIX, sFlow), за секунды замечает флуд на защищаемые вами адреса и останавливает его — командой маршрутизатору сбросить атаку или сбрасывая её сам, прямо в ядре Linux. Бесплатно, открытый код, и в безопасном режиме «только наблюдение», пока вы не решите иначе.",
    trust: ["Один Go-бинарник", "Больше ничего ставить не нужно", "«Только наблюдение» по умолчанию", "IPv4 + IPv6"],
  },
  stats: ["≥20M потоков/с/ядро", "Обнаружение за секунды", "Blackhole для IPv4 + IPv6", "FlowSpec RFC 8955/8956", "Один статический бинарник"],
  how: {
    heading: "Как это работает",
    sub: "Один бинарник и больше ничего — ни лишних сервисов, ни очереди сообщений, ни базы данных. Направьте на него маршрутизаторы — и всё.",
    steps: [
      {
        title: "ПРИЁМ",
        body: "Направьте маршрутизаторы на Kapkan. Они и так отправляют сводку по каждому потоку трафика — NetFlow, IPFIX или sFlow, — просто нацельте её на порт Kapkan. Всё читает один процесс; ставить больше ничего не нужно.",
      },
      {
        title: "ОБНАРУЖЕНИЕ",
        body: "Kapkan считает пакеты, биты и соединения в секунду для каждого защищаемого адреса. Превышен заданный вами предел — или тот, что Kapkan выучил из обычного трафика хоста, — это атака, и она видна за секунды.",
      },
      {
        title: "ПОДАВЛЕНИЕ",
        body: "Kapkan командует маршрутизатору сбросить атаку по BGP. Можно закрыть весь адрес-жертву целиком (RTBH) или сбросить только атакующий трафик, оставив остальной (FlowSpec). Когда флуд стихает, правило снимается само.",
      },
      {
        title: "ОТБРОС",
        body: "Или без маршрутизатора: если трафик идёт через машину с Kapkan, он может сбросить атаку сам, прямо в ядре Linux (XDP), в тот же миг, как приходят пакеты. У каждого правила есть срок, за которым следит ядро, — упавший Kapkan не сможет и дальше резать ваш трафик.",
      },
    ],
  },
  features: {
    heading: "Что умеет",
    sub: "Обнаружение, подавление, операторская консоль и защита от собственных ошибок в одном бинарнике под Apache 2.0. Коммерческие flow-DDoS продукты продают это отдельными модулями.",
    learnMore: "Как работает отброс в ядре",
    cards: [
      { title: "Читает потоки, которые вы уже экспортируете", body: "sFlow v5, NetFlow v5/v9 и IPFIX по UDP — читает сам Kapkan, без отдельного сервиса." },
      { title: "Замечает флуд меньше чем за секунду", body: "Пределы по пакетам, битам и потокам в секунду на скользящем окне, с поправкой на сэмплинг — ≥20M потоков/с на ядро." },
      { title: "Blackhole или только атаку", body: "Закрыть весь адрес-жертву (RTBH) или сбросить только атакующий трафик, оставив остальной (FlowSpec). Полная поддержка IPv6, наравне с IPv4." },
      { title: "Говорит, что за атака", body: "Усиление (NTP/DNS/memcached), SYN/UDP/ICMP-флуды — и по каждой понятный разбор «почему сработало»." },
      { title: "Учит норму каждого хоста", body: "Kapkan сам изучает, как выглядит обычный трафик каждого хоста, и подтягивает пределы. Руками крутить не нужно." },
      { title: "Трудно выстрелить себе в ногу", body: "Стартует в режиме «только наблюдение». У каждой блокировки есть срок, и она снимается сама; лимит ограничивает, сколько адресов можно заблокировать разом; а защищённый список не блокируется никогда — ни Kapkan, ни вами." },
      { title: "Ловит ковровые атаки", body: "Замечает слабые флуды, размазанные по целому диапазону адресов, которые не дотягивают до предела ни на одном хосте." },
      { title: "Следите откуда угодно", body: "REST API, метрики Prometheus /metrics и оповещения в Telegram, Slack, на почту, вебхук или в ваш скрипт." },
      { title: "Мультиарендность и аудит", body: "Разграничение доступа по арендаторам, API-токены с ролями (наблюдатель/оператор) и журнал аудита, где видно, кто что сделал." },
      {
        title: "Подавление в ядре через XDP",
        body: "Вместо того чтобы просить маршрутизатор сбросить атаку, Kapkan может сделать это сам. Те же правила, что он анонсировал бы как FlowSpec, загружаются прямо в ядро Linux и работают там (XDP) — включая отдельный лимит скорости для каждого атакующего источника, чего BGP FlowSpec не умеет. Нужен Linux 5.15+, на машине ничего компилировать не надо, и каждое правило истекает прямо в ядре — упавший Kapkan не оставит ваш трафик отброшенным. По умолчанию по-прежнему «только наблюдение».",
      },
    ],
  },
  showcase: {
    heading: "Операторская консоль",
    sub: "Kapkan идёт с живой веб-консолью для дежурной смены: атаки, хосты и блокировки в одном месте. Копаться в сырых логах не нужно.",
  },
  compare: {
    heading: "Сравнение с коммерческими продуктами",
    sub: "Один статический бинарник вместо лицензируемого устройства и набора демонов.",
    colFeature: "Возможность",
    colKapkan: "Kapkan",
    colThem: "Коммерческие продукты",
    rows: [
      { feature: "Лицензия", kapkan: "Бесплатно, открытый код (Apache 2.0)", them: "Платная лицензия / по объёму" },
      { feature: "Операторская консоль", kapkan: "Входит бесплатно", them: "Платное дополнение" },
      { feature: "Поддержка IPv6", kapkan: "Полная, как для IPv4", them: "Нет или в планах" },
      { feature: "Настройка порогов", kapkan: "Учится сама", them: "Офлайн-калькулятор, копипаст" },
      { feature: "Автоматизация", kapkan: "Правила эскалации в конфиге", them: "Самописные bash-скрипты" },
      { feature: "Архитектура", kapkan: "Один статический бинарник, без довесков", them: "Несколько демонов" },
      { feature: "Отбрасывание в ядре", kapkan: "Встроено — отбрасывает прямо в ядре Linux (XDP)", them: "Отдельное устройство очистки" },
    ],
  },
  quickstart: {
    heading: "Запуск за минуты, сначала «только наблюдение»",
    bodyBefore:
      "Kapkan безопасен из коробки. Он записывает каждую блокировку, которую сделал бы, и показывает её в API и консоли, но ничего не анонсирует вашим маршрутизаторам, пока вы явно не поставите ",
    bodyAfter: ".",
    cta: "Вся документация",
  },
  cta: { heading: "Поставьте капкан", sub: "Бесплатно, Apache 2.0, разворачивается за вечер. Начните в режиме «только наблюдение» и посмотрите, что он заблокировал бы." },
  footer: {
    tagline: "Бесплатное open-source обнаружение DDoS — анонсировать маршрут или отбросить самому.",
    product: "Продукт",
    docsCol: "Документация",
    project: "Проект",
    features: "Возможности",
    compare: "Сравнение",
    configBuilder: "Сборщик конфига",
    quickstart: "Быстрый старт",
    configuration: "Конфигурация",
    api: "API",
    safety: "Модель безопасности",
    github: "GitHub",
    releases: "Релизы",
    license: "Лицензия (Apache 2.0)",
  },
};

const de: LandingDict = {
  "meta": {
    "title": "Kapkan — kostenlose Open-Source-DDoS-Erkennung und -Abwehr",
    "description": "Kapkan ist eine einzige Go-Binary. Es liest die Verkehrsstatistik, die Ihre Router ohnehin schon exportieren (NetFlow, IPFIX, sFlow), erkennt in Sekunden eine DDoS-Flut gegen die IPs, die Sie schützen, und stoppt sie — indem es Ihren Router anweist, den Angriff zu verwerfen (BGP RTBH/FlowSpec), oder indem es ihn selbst im Linux-Kernel verwirft (XDP). Kostenlos und quelloffen."
  },
  "nav": {
    "features": "Funktionen",
    "how": "So funktioniert's",
    "compare": "Vergleich",
    "docs": "Doku",
    "star": "Star auf GitHub",
    "readDocs": "Doku lesen",
    "buildConfig": "Konfiguration erstellen",
    "viewGithub": "Auf GitHub ansehen",
    "menu": "Menü",
    "docFull": "Vollständige Doku ansehen",
    "underAttack": "Gerade unter Angriff?"
  },
  "hero": {
    "eyebrow": "Open Source · Apache 2.0",
    "h1a": "Stoppen Sie DDoS-Fluten in Sekunden",
    "h1b": "mit einer einzigen Binary.",
    "sub": "Kapkan liest die Verkehrsstatistik, die Ihre Router ohnehin schon exportieren (NetFlow, IPFIX, sFlow), erkennt binnen Sekunden eine Flut gegen die IPs, die Sie schützen, und stoppt sie — indem es Ihren Router anweist, den Angriff zu verwerfen, oder indem es ihn selbst im Linux-Kernel verwirft. Kostenlos, quelloffen und im sicheren Modus „nur beobachten“, bis Sie es anders entscheiden.",
    "trust": [
      "Eine Go-Binary",
      "Sonst nichts zu installieren",
      "Standardmäßig „nur beobachten“",
      "IPv4 + IPv6"
    ]
  },
  "stats": [
    "≥20M Flows/s/Kern",
    "Erkennung in Sekunden",
    "Blackhole für IPv4 + IPv6",
    "FlowSpec RFC 8955/8956",
    "Eine statische Binary"
  ],
  "how": {
    "heading": "So funktioniert es",
    "sub": "Eine Binary, sonst nichts — keine zusätzlichen Dienste, keine Message-Queue, keine Datenbank. Richten Sie Ihre Router darauf und legen Sie los.",
    "steps": [
      {
        "title": "ERFASSEN",
        "body": "Richten Sie Ihre Router auf Kapkan. Eine Zusammenfassung jedes Verkehrsflusses schicken sie ohnehin schon — NetFlow, IPFIX oder sFlow —, lassen Sie sie also einfach auf den Port von Kapkan zeigen. Ein einziger Prozess liest alles; sonst ist nichts zu installieren."
      },
      {
        "title": "ERKENNEN",
        "body": "Kapkan zählt Pakete, Bits und Verbindungen pro Sekunde für jede IP, die Sie schützen. Wird ein Grenzwert überschritten, den Sie gesetzt haben — oder einer, den Kapkan aus dem normalen Verkehr dieses Hosts gelernt hat —, ist das ein Angriff, binnen Sekunden gemeldet."
      },
      {
        "title": "ABWEHREN",
        "body": "Kapkan weist Ihren Router per BGP an, den Angriff zu verwerfen. Es kann die komplette Ziel-IP ins Leere routen (RTBH) oder nur den Angriffsverkehr verwerfen und den Rest weiterlaufen lassen (FlowSpec). Sobald die Flut abklingt, entfernt es die Regel von selbst."
      },
      {
        "title": "VERWERFEN",
        "body": "Oder ganz ohne Router: Läuft der Verkehr über die Maschine, auf der Kapkan sitzt, kann es den Angriff selbst im Linux-Kernel verwerfen (XDP), sobald die Pakete ankommen. Jede Regel hat ein Ablaufdatum, das der Kernel durchsetzt — ein abgestürztes Kapkan kann Ihren Verkehr also nicht endlos weiter verwerfen."
      }
    ]
  },
  "features": {
    "heading": "Was es kann",
    "sub": "Erkennung, Abwehr, eine Operator-Konsole und die Sicherheitsleitplanken für den Produktivbetrieb, in einer Binary unter Apache 2.0. Kommerzielle Flow-DDoS-Produkte verkaufen das als separate Module.",
    "learnMore": "So funktioniert das Verwerfen im Kernel",
    "cards": [
      {
        "title": "Liest die Flows, die Sie ohnehin exportieren",
        "body": "sFlow v5, NetFlow v5/v9 und IPFIX über UDP, von Kapkan selbst gelesen — kein zusätzlicher Dienst nötig."
      },
      {
        "title": "Erkennt Fluten in unter einer Sekunde",
        "body": "Sampling-korrigierte Grenzwerte für Pakete, Bits und Flows pro Sekunde über ein gleitendes Fenster — ≥20M Flows/s pro Kern."
      },
      {
        "title": "Blackhole — oder nur den Angriff verwerfen",
        "body": "Die komplette Ziel-IP ins Leere routen (RTBH) oder nur den Angriffsverkehr verwerfen und den Rest behalten (FlowSpec). Volle IPv6-Unterstützung, gleichauf mit IPv4."
      },
      {
        "title": "Sagt Ihnen die Angriffsart",
        "body": "Amplification (NTP/DNS/memcached), SYN-/UDP-/ICMP-Fluten — jeweils mit einer klaren Aufschlüsselung „warum das ausgelöst hat“."
      },
      {
        "title": "Lernt, was für jeden Host normal ist",
        "body": "Kapkan lernt, wie normaler Verkehr für jeden Host aussieht, und zieht die Grenzwerte von selbst nach. Kein Tuning von Hand."
      },
      {
        "title": "Schwer, falsch auszulösen",
        "body": "Startet im Modus „nur beobachten“. Jede Sperre hat ein Ablaufdatum und hebt sich von selbst auf, eine Obergrenze deckelt die Zahl gleichzeitig gesperrter Hosts, und Ihre geschützte Liste wird nie gesperrt — weder von Kapkan noch von Ihnen."
      },
      {
        "title": "Erkennt Carpet-Bombing",
        "body": "Erkennt schwache, langsame Fluten, die über einen ganzen IP-Bereich verteilt sind und unter dem Grenzwert jedes einzelnen Hosts bleiben."
      },
      {
        "title": "Überwachen Sie es von überall",
        "body": "REST API, Prometheus /metrics und Benachrichtigungen über Telegram, Slack, E-Mail, Webhook oder ein Skript, das Sie ausführen."
      },
      {
        "title": "Mandantenfähig & auditiert",
        "body": "Zugriff pro Mandant abgrenzen, API-Tokens mit Rollen (viewer/operator) vergeben und ein Audit-Log erhalten, das benennt, wer was getan hat."
      },
      {
        "title": "Abwehr im Kernel mit XDP",
        "body": "Statt einen Router zu bitten, den Angriff zu verwerfen, kann Kapkan es selbst tun. Dieselben Regeln, die es als FlowSpec ankündigen würde, werden direkt in den Linux-Kernel geladen und laufen dort (XDP) — samt einem eigenen Rate-Limit für jede angreifende Quelle, was BGP FlowSpec nicht kann. Braucht Linux 5.15+, kompiliert nichts auf der Maschine, und jede Regel läuft im Kernel selbst ab — ein abgestürztes Kapkan kann Ihren Verkehr also nicht verworfen zurücklassen. Weiterhin standardmäßig „nur beobachten“."
      }
    ]
  },
  "showcase": {
    "heading": "Die Operator-Konsole",
    "sub": "Kapkan bringt eine Live-Web-Konsole für Ihre Rufbereitschaft mit: Angriffe, Hosts und Sperren an einem Ort. Kein Wühlen in rohen Logs."
  },
  "compare": {
    "heading": "Im Vergleich zu kommerziellen Tools",
    "sub": "Eine statische Binary statt einer lizenzierten Appliance und einer Handvoll Daemons.",
    "colFeature": "Funktion",
    "colKapkan": "Kapkan",
    "colThem": "Kommerzielle Tools",
    "rows": [
      {
        "feature": "Lizenz",
        "kapkan": "Kostenlos & quelloffen (Apache 2.0)",
        "them": "Kostenpflichtige Lizenz / volumenbasiert"
      },
      {
        "feature": "Operator-Konsole",
        "kapkan": "Kostenlos enthalten",
        "them": "Kostenpflichtiges Add-on"
      },
      {
        "feature": "IPv6-Unterstützung",
        "kapkan": "Voll, wie bei IPv4",
        "them": "Fehlt oder geplant"
      },
      {
        "feature": "Schwellenwerte einstellen",
        "kapkan": "Lernt automatisch",
        "them": "Offline-Rechner, Copy-Paste"
      },
      {
        "feature": "Automatisierung",
        "kapkan": "Eskalationsregeln in der Config",
        "them": "Eigene Bash-Skripte"
      },
      {
        "feature": "Architektur",
        "kapkan": "Eine statische Binary, kein Drumherum",
        "them": "Mehrere Daemons zu betreiben"
      },
      {
        "feature": "Verwerfen im Kernel",
        "kapkan": "Eingebaut — verwirft direkt im Linux-Kernel (XDP)",
        "them": "Separate Scrubbing-Appliance"
      }
    ]
  },
  "quickstart": {
    "heading": "In Minuten startklar, erst „nur beobachten“",
    "bodyBefore": "Kapkan ist von Haus aus sicher im Betrieb. Es protokolliert jede Sperre, die es verhängen würde, und zeigt sie in der API und der Konsole an, kündigt Ihren Routern aber nichts an, bis Sie ausdrücklich ",
    "bodyAfter": " setzen.",
    "cta": "Vollständige Doku ansehen"
  },
  "cta": {
    "heading": "Stellen Sie die Falle",
    "sub": "Kostenlos, Apache 2.0, an einem Nachmittag startklar. Starten Sie im Modus „nur beobachten“ und sehen Sie, was es gesperrt hätte."
  },
  "footer": {
    "tagline": "Kostenlose Open-Source-DDoS-Erkennung und -Abwehr — ankündigen oder selbst verwerfen.",
    "product": "Produkt",
    "docsCol": "Doku",
    "project": "Projekt",
    "features": "Funktionen",
    "compare": "Vergleich",
    "configBuilder": "Config-Builder",
    "quickstart": "Schnellstart",
    "configuration": "Konfiguration",
    "api": "API",
    "safety": "Sicherheitsmodell",
    "github": "GitHub",
    "releases": "Releases",
    "license": "Lizenz (Apache 2.0)"
  }
};

const fr: LandingDict = {
  "meta": {
    "title": "Kapkan — détection et mitigation DDoS gratuites et open source",
    "description": "Kapkan tient dans un seul binaire Go. Il lit les statistiques de trafic que vos routeurs exportent déjà (NetFlow, IPFIX, sFlow), repère en quelques secondes un flood DDoS visant les IP que vous protégez, et l'arrête — en demandant à votre routeur de le rejeter (BGP RTBH/FlowSpec) ou en le rejetant lui-même dans le noyau Linux (XDP). Gratuit et open source."
  },
  "nav": {
    "features": "Fonctionnalités",
    "how": "Fonctionnement",
    "compare": "Comparer",
    "docs": "Docs",
    "star": "Star sur GitHub",
    "readDocs": "Lire la doc",
    "buildConfig": "Créer une config",
    "viewGithub": "Voir sur GitHub",
    "menu": "Menu",
    "docFull": "Voir toute la documentation",
    "underAttack": "Attaque en cours ?"
  },
  "hero": {
    "eyebrow": "Open Source · Apache 2.0",
    "h1a": "Stoppez les floods DDoS en quelques secondes",
    "h1b": "avec un seul binaire.",
    "sub": "Kapkan lit les statistiques de trafic que vos routeurs exportent déjà (NetFlow, IPFIX, sFlow), repère en quelques secondes un flood visant les IP que vous protégez, et l'arrête — en demandant à votre routeur de rejeter l'attaque, ou en la rejetant lui-même dans le noyau Linux. Gratuit, open source, et en mode « observation seule », sans risque, jusqu'à ce que vous en décidiez autrement.",
    "trust": [
      "Un seul binaire Go",
      "Rien d'autre à installer",
      "« Observation seule » par défaut",
      "IPv4 + IPv6"
    ]
  },
  "stats": [
    "≥20M flux/s/cœur",
    "Détection en quelques secondes",
    "Blackhole IPv4 + IPv6",
    "FlowSpec RFC 8955/8956",
    "Un seul binaire statique"
  ],
  "how": {
    "heading": "Comment ça marche",
    "sub": "Un seul binaire, rien d'autre à faire tourner — pas de services en plus, pas de file de messages, pas de base de données. Pointez vos routeurs dessus, c'est parti.",
    "steps": [
      {
        "title": "INGÉRER",
        "body": "Pointez vos routeurs vers Kapkan. Ils envoient déjà un résumé de chaque flux de trafic — NetFlow, IPFIX ou sFlow — alors dirigez-le simplement vers le port de Kapkan. Un seul processus lit tout ; il n'y a rien d'autre à installer."
      },
      {
        "title": "DÉTECTER",
        "body": "Kapkan compte les paquets, les bits et les connexions par seconde pour chaque IP que vous protégez. Franchissez une limite que vous avez fixée — ou une limite qu'il a apprise du trafic normal de l'hôte — et c'est une attaque, signalée en quelques secondes."
      },
      {
        "title": "ATTÉNUER",
        "body": "Kapkan demande à votre routeur de rejeter l'attaque via BGP. Il peut envoyer toute l'IP visée dans un trou noir (RTBH), ou ne rejeter que le trafic d'attaque en laissant passer le reste (FlowSpec). Une fois le flood retombé, il retire la règle lui-même."
      },
      {
        "title": "REJETER",
        "body": "Ou passez-vous du routeur : si le trafic traverse la machine où tourne Kapkan, il peut rejeter l'attaque lui-même dans le noyau Linux (XDP), dès l'arrivée des paquets. Chaque règle a une échéance que le noyau fait respecter : un Kapkan qui a planté ne peut donc pas continuer à rejeter votre trafic."
      }
    ]
  },
  "features": {
    "heading": "Ce qu'il fait",
    "sub": "Détection, mitigation, une console opérateur et les garde-fous pour l'exploiter en production, dans un seul binaire Apache 2.0. Les produits flow-DDoS commerciaux vendent tout cela en modules séparés.",
    "learnMore": "Voir comment fonctionne le rejet dans le noyau",
    "cards": [
      {
        "title": "Lit les flux que vous exportez déjà",
        "body": "sFlow v5, NetFlow v5/v9 et IPFIX sur UDP, lus par Kapkan lui-même — aucun service supplémentaire à faire tourner."
      },
      {
        "title": "Repère les floods en moins d'une seconde",
        "body": "Limites de paquets, de bits et de flux par seconde sur une fenêtre glissante, corrigées de l'échantillonnage — ≥20M flux/s par cœur."
      },
      {
        "title": "Trou noir, ou rejeter juste l'attaque",
        "body": "Envoyez toute l'IP visée dans un trou noir (RTBH), ou ne rejetez que le trafic d'attaque en gardant le reste (FlowSpec). Prise en charge complète d'IPv6, à parité avec IPv4."
      },
      {
        "title": "Vous dit quel type d'attaque",
        "body": "Amplification (NTP/DNS/memcached), floods SYN/UDP/ICMP — chacun avec une explication claire du « pourquoi ça s'est déclenché »."
      },
      {
        "title": "Apprend la normale de chaque hôte",
        "body": "Kapkan apprend à quoi ressemble le trafic normal de chaque hôte et resserre les limites tout seul. Aucun réglage à la main."
      },
      {
        "title": "Difficile de se tromper de cible",
        "body": "Démarre en mode « observation seule ». Chaque blocage a une échéance et se lève tout seul, un plafond limite le nombre d'hôtes pouvant être bloqués à la fois, et votre liste protégée n'est jamais bloquée — ni par Kapkan, ni par vous."
      },
      {
        "title": "Attrape le carpet-bombing",
        "body": "Repère les floods lents et diffus, étalés sur toute une plage d'IP, qui restent sous la limite de chaque hôte pris isolément."
      },
      {
        "title": "Surveillez-le d'où vous voulez",
        "body": "REST API, Prometheus /metrics, et des alertes par Telegram, Slack, e-mail, webhook ou un script que vous lancez."
      },
      {
        "title": "Multi-locataire et audité",
        "body": "Cloisonnez l'accès par locataire, distribuez des jetons d'API viewer/operator, et obtenez un journal d'audit qui nomme qui a fait quoi."
      },
      {
        "title": "Mitigation dans le noyau avec XDP",
        "body": "Au lieu de demander à un routeur de rejeter l'attaque, Kapkan peut le faire lui-même. Les mêmes règles qu'il annoncerait en FlowSpec se chargent directement dans le noyau Linux et s'exécutent là (XDP) — y compris une limite de débit distincte pour chaque source attaquante, ce que BGP FlowSpec ne sait pas faire. Nécessite Linux 5.15+, ne compile rien sur la machine, et chaque règle expire dans le noyau : un Kapkan qui a planté ne peut pas laisser votre trafic rejeté. Toujours en « observation seule » par défaut."
      }
    ]
  },
  "showcase": {
    "heading": "La console opérateur",
    "sub": "Kapkan est livré avec une console web en direct pour votre astreinte : attaques, hôtes et blocages au même endroit. Fini de fouiller dans les logs bruts."
  },
  "compare": {
    "heading": "Face aux outils commerciaux",
    "sub": "Un seul binaire statique au lieu d'une appliance sous licence et d'une poignée de daemons.",
    "colFeature": "Fonctionnalité",
    "colKapkan": "Kapkan",
    "colThem": "Outils commerciaux",
    "rows": [
      {
        "feature": "Licence",
        "kapkan": "Gratuit et open source (Apache 2.0)",
        "them": "Licence payante / au volume"
      },
      {
        "feature": "Console opérateur",
        "kapkan": "Incluse gratuitement",
        "them": "Option payante"
      },
      {
        "feature": "Prise en charge d'IPv6",
        "kapkan": "Complète, comme IPv4",
        "them": "Absente ou prévue"
      },
      {
        "feature": "Réglage des seuils",
        "kapkan": "Apprend tout seul",
        "them": "Calculateur hors ligne, copier-coller"
      },
      {
        "feature": "Automatisation",
        "kapkan": "Règles d'escalade dans la config",
        "them": "Scripts bash maison"
      },
      {
        "feature": "Architecture",
        "kapkan": "Un binaire statique, sans extras",
        "them": "Plusieurs daemons à faire tourner"
      },
      {
        "feature": "Rejet dans le noyau",
        "kapkan": "Intégré — rejette directement dans le noyau Linux (XDP)",
        "them": "Appliance de scrubbing séparée"
      }
    ]
  },
  "quickstart": {
    "heading": "Opérationnel en quelques minutes, « observation seule » d'abord",
    "bodyBefore": "Kapkan est sûr dès l'installation. Il journalise chaque blocage qu'il ferait et l'affiche dans l'API et la console, mais n'annonce jamais rien à vos routeurs tant que vous ne définissez pas explicitement ",
    "bodyAfter": ".",
    "cta": "Voir toute la documentation"
  },
  "cta": {
    "heading": "Tendez le piège",
    "sub": "Gratuit, Apache 2.0, opérationnel en un après-midi. Démarrez en « observation seule » et voyez ce qu'il aurait bloqué."
  },
  "footer": {
    "tagline": "Détection et mitigation DDoS gratuites et open source — annoncez-la, ou rejetez-la vous-même.",
    "product": "Produit",
    "docsCol": "Docs",
    "project": "Projet",
    "features": "Fonctionnalités",
    "compare": "Comparer",
    "configBuilder": "Générateur de config",
    "quickstart": "Démarrage rapide",
    "configuration": "Configuration",
    "api": "API",
    "safety": "Modèle de sûreté",
    "github": "GitHub",
    "releases": "Versions",
    "license": "Licence (Apache 2.0)"
  }
};

const es: LandingDict = {
  "meta": {
    "title": "Kapkan — detección y mitigación de DDoS gratis y de código abierto",
    "description": "Kapkan es un único binario Go. Lee las estadísticas de tráfico que tus routers ya exportan (NetFlow, IPFIX, sFlow), detecta en segundos un ataque DDoS contra las IPs que proteges y lo detiene — diciéndole a tu router que lo descarte (BGP RTBH/FlowSpec) o descartándolo él mismo en el kernel de Linux (XDP). Gratis y de código abierto."
  },
  "nav": {
    "features": "Funciones",
    "how": "Cómo funciona",
    "compare": "Comparar",
    "docs": "Docs",
    "star": "Estrella en GitHub",
    "readDocs": "Leer la documentación",
    "buildConfig": "Crear una configuración",
    "viewGithub": "Ver en GitHub",
    "menu": "Menú",
    "docFull": "Ver toda la documentación",
    "underAttack": "¿Bajo ataque ahora?"
  },
  "hero": {
    "eyebrow": "Open Source · Apache 2.0",
    "h1a": "Detén los ataques DDoS en segundos",
    "h1b": "con un solo binario.",
    "sub": "Kapkan lee las estadísticas de tráfico que tus routers ya exportan (NetFlow, IPFIX, sFlow), detecta en segundos una avalancha contra las IPs que proteges y la detiene — diciéndole a tu router que descarte el ataque, o descartándolo él mismo en el kernel de Linux. Gratis, de código abierto y en modo seguro «solo observación» hasta que decidas otra cosa.",
    "trust": [
      "Un solo binario Go",
      "Nada más que instalar",
      "«Solo observación» por defecto",
      "IPv4 + IPv6"
    ]
  },
  "stats": [
    "≥20M flujos/s/núcleo",
    "Detecta en segundos",
    "Blackhole IPv4 + IPv6",
    "FlowSpec RFC 8955/8956",
    "Un binario estático"
  ],
  "how": {
    "heading": "Cómo funciona",
    "sub": "Un solo binario, nada más que ejecutar — sin servicios extra, sin cola de mensajes, sin base de datos. Apunta tus routers hacia él y listo.",
    "steps": [
      {
        "title": "RECIBIR",
        "body": "Apunta tus routers a Kapkan. Ya envían un resumen de cada flujo de tráfico — NetFlow, IPFIX o sFlow —, así que solo tienes que dirigirlo al puerto de Kapkan. Un único proceso lo lee todo; no hay nada más que instalar."
      },
      {
        "title": "DETECTAR",
        "body": "Kapkan cuenta los paquetes, bits y conexiones por segundo de cada IP que proteges. Si se cruza un límite que fijaste — o uno que aprendió del tráfico normal de ese host —, es un ataque, y lo marca en segundos."
      },
      {
        "title": "MITIGAR",
        "body": "Kapkan le dice a tu router que descarte el ataque por BGP. Puede descartar todo el tráfico de la IP atacada (RTBH), o descartar solo el tráfico del ataque y dejar pasar el resto (FlowSpec). Cuando la avalancha cesa, retira la regla él mismo."
      },
      {
        "title": "DESCARTAR",
        "body": "O sáltate el router: si el tráfico pasa por la máquina donde se ejecuta Kapkan, puede descartar el ataque él mismo dentro del kernel de Linux (XDP), en cuanto llegan los paquetes. Cada regla tiene una caducidad que el kernel hace cumplir, así que un Kapkan caído no puede seguir descartando tu tráfico."
      }
    ]
  },
  "features": {
    "heading": "Qué hace",
    "sub": "Detección, mitigación, una consola de operador y las salvaguardas para operarlo en producción, en un único binario Apache 2.0. Los productos comerciales de flow-DDoS lo venden como módulos aparte.",
    "learnMore": "Mira cómo funciona el descarte en el kernel",
    "cards": [
      {
        "title": "Lee los flujos que ya exportas",
        "body": "sFlow v5, NetFlow v5/v9 e IPFIX sobre UDP, leídos por el propio Kapkan — sin ningún servicio extra que ejecutar."
      },
      {
        "title": "Detecta avalanchas en menos de un segundo",
        "body": "Límites de paquetes, bits y flujos por segundo sobre una ventana deslizante, corregidos por muestreo — ≥20M flujos/s por núcleo."
      },
      {
        "title": "Blackhole, o descartar solo el ataque",
        "body": "Descarta todo el tráfico de la IP atacada (RTBH), o descarta solo el tráfico del ataque y deja pasar el resto (FlowSpec). Soporte completo de IPv6, a la par de IPv4."
      },
      {
        "title": "Te dice de qué tipo es el ataque",
        "body": "Amplificación (NTP/DNS/memcached), avalanchas SYN/UDP/ICMP — cada una con un desglose claro de «por qué saltó»."
      },
      {
        "title": "Aprende lo normal de cada host",
        "body": "Kapkan aprende cómo es el tráfico normal de cada host y ajusta los límites por su cuenta. Sin calibrado manual."
      },
      {
        "title": "Difícil que se dispare por error",
        "body": "Arranca en modo «solo observación». Cada bloqueo tiene una caducidad y se levanta solo, un tope limita cuántos hosts pueden bloquearse a la vez, y tu lista protegida no se bloquea nunca — ni por Kapkan, ni por ti."
      },
      {
        "title": "Detecta el carpet-bombing",
        "body": "Detecta avalanchas de baja intensidad repartidas por todo un rango de IPs que se quedan por debajo del límite de cada host."
      },
      {
        "title": "Vigílalo desde cualquier sitio",
        "body": "REST API, Prometheus /metrics y alertas por Telegram, Slack, correo, webhook o un script que tú ejecutes."
      },
      {
        "title": "Multiinquilino y auditado",
        "body": "Acota el acceso por inquilino, reparte tokens de API de viewer/operator y consigue un registro de auditoría que deja constancia de quién hizo qué."
      },
      {
        "title": "Mitigación en el kernel con XDP",
        "body": "En lugar de pedirle a un router que descarte el ataque, Kapkan puede hacerlo él mismo. Las mismas reglas que anunciaría como FlowSpec se cargan directamente en el kernel de Linux y se ejecutan allí (XDP) — incluido un límite de tasa aparte para cada origen atacante, algo que BGP FlowSpec no puede hacer. Necesita Linux 5.15+, no compila nada en la máquina, y cada regla expira dentro del kernel, así que un Kapkan caído no puede dejar tu tráfico descartado. Sigue en «solo observación» por defecto."
      }
    ]
  },
  "showcase": {
    "heading": "La consola de operador",
    "sub": "Kapkan viene con una consola web en vivo para tu equipo de guardia: ataques, hosts y bloqueos en un solo lugar. Sin escarbar en logs en bruto."
  },
  "compare": {
    "heading": "Frente a las herramientas comerciales",
    "sub": "Un único binario estático en lugar de un appliance con licencia y un puñado de daemons.",
    "colFeature": "Función",
    "colKapkan": "Kapkan",
    "colThem": "Herramientas comerciales",
    "rows": [
      {
        "feature": "Licencia",
        "kapkan": "Gratis y de código abierto (Apache 2.0)",
        "them": "Licencia de pago / por volumen"
      },
      {
        "feature": "Consola de operador",
        "kapkan": "Incluida gratis",
        "them": "Complemento de pago"
      },
      {
        "feature": "Soporte de IPv6",
        "kapkan": "Completo, igual que IPv4",
        "them": "Ausente o previsto"
      },
      {
        "feature": "Ajuste de umbrales",
        "kapkan": "Aprende automáticamente",
        "them": "Calculadora offline, copiar y pegar"
      },
      {
        "feature": "Automatización",
        "kapkan": "Reglas de escalado en la configuración",
        "them": "Scripts bash propios"
      },
      {
        "feature": "Arquitectura",
        "kapkan": "Un binario estático, sin extras",
        "them": "Varios daemons que ejecutar"
      },
      {
        "feature": "Descarte en el kernel",
        "kapkan": "Integrado — descarta en el propio kernel de Linux (XDP)",
        "them": "Appliance de scrubbing aparte"
      }
    ]
  },
  "quickstart": {
    "heading": "En marcha en minutos, primero «solo observación»",
    "bodyBefore": "Kapkan es seguro desde el primer momento. Registra cada bloqueo que haría y lo muestra en la API y la consola, pero nunca anuncia nada a tus routers hasta que establezcas explícitamente ",
    "bodyAfter": ".",
    "cta": "Ver toda la documentación"
  },
  "cta": {
    "heading": "Tiende la trampa",
    "sub": "Gratis, Apache 2.0, funcionando en una tarde. Arranca en «solo observación» y mira qué habría bloqueado."
  },
  "footer": {
    "tagline": "Detección y mitigación de DDoS gratis y de código abierto — anúncialo, o descártalo tú mismo.",
    "product": "Producto",
    "docsCol": "Docs",
    "project": "Proyecto",
    "features": "Funciones",
    "compare": "Comparar",
    "configBuilder": "Generador de configuración",
    "quickstart": "Inicio rápido",
    "configuration": "Configuración",
    "api": "API",
    "safety": "Modelo de seguridad",
    "github": "GitHub",
    "releases": "Versiones",
    "license": "Licencia (Apache 2.0)"
  }
};

export const landing: Record<Locale, LandingDict> = { en, ru, de, fr, es };
