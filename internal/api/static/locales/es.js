/* locales/es.js — Spanish catalog. Mirrors en.js key-for-key. Technical tokens
   (FlowSpec, RTBH, BGP, NTP/DNS/SYN…, pps, Mb/s, IPs, routes) stay verbatim. */
(function (w) {
  w.KAPKAN_LOCALES = w.KAPKAN_LOCALES || {};
  w.KAPKAN_LOCALES.es = {
    units: { d: "d", h: "h", m: "min", s: "s" },

    plurals: {
      activeAttacks: { one: "# ataque activo", other: "# ataques activos" },
      activeBans:    { one: "# bloqueo activo", other: "# bloqueos activos" },
      hostsTracked:  { one: "# host monitorizado", other: "# hosts monitorizados" },
      sources:       { one: "# origen", other: "# orígenes" },
      recentAttacks: { one: "# ataque reciente", other: "# ataques recientes" }
    },

    strings: {
      /* nav */
      "nav.section.monitor": "Monitorización",
      "nav.section.config": "Configuración",
      "nav.overview": "Resumen",
      "nav.attacks": "Ataques",
      "nav.bans": "Bloqueos / Mitigación",
      "nav.hosts": "Hosts",
      "nav.hostgroups": "Grupos de hosts",
      "nav.traffic": "Tráfico / Informes",
      "nav.settings": "Ajustes",

      /* role */
      "role.viewer": "Observador",
      "role.operator": "Operador",

      /* posture + mode */
      "posture.calm": "En calma",
      "posture.attack": "Bajo ataque",
      "posture.mitigating": "Mitigando",
      "mode.dryrun": "Simulación",
      "mode.live": "Real",
      "mode.dryrun.full": "Simulación — la mitigación está simulada",
      "dryrun.banner": "Modo simulación — las rutas y bloqueos de abajo están simulados. No se envían anuncios BGP.",

      /* counters / topbar */
      "counter.attacks": "Ataques",
      "counter.bans": "Bloqueos",
      "counter.hosts": "Hosts",
      "counter.networks": "Redes",
      "live.label": "En vivo",
      "live.updated": "Actualizado",
      "btn.reload": "Recargar config",
      "reload.ok": "Configuración recargada",
      "reload.confirm.title": "¿Recargar configuración?",
      "reload.confirm.text": "Vuelve a leer el archivo de configuración y reaplica los umbrales y la política de grupos de hosts. Los bloqueos activos se conservan.",
      "locale.title": "Idioma",
      "locale.soon": "pronto",
      "locale.soon.title": "Idioma previsto — recurre al inglés",
      "sidebar.collapse": "Contraer barra lateral",

      /* common */
      "common.yes": "Sí", "common.no": "No",
      "common.enabled": "Activado", "common.disabled": "Desactivado",
      "common.none": "Ninguno", "common.na": "—",
      "op.only": "Solo operador",
      "viewer.note": "Estás en modo Observador — las acciones de mitigación son de solo lectura.",
      "confirm.cancel": "Cancelar", "confirm.confirm": "Confirmar",
      "state.loading": "Cargando…",
      "error.title": "No se puede contactar con el motor",
      "error.sub": "La consola perdió contacto con la API de Kapkan. Reintentando cada 3 segundos.",
      "error.retry": "Reintentar",

      /* table columns */
      "col.target": "Objetivo", "col.scope": "Ámbito", "col.dir": "Sentido",
      "col.type": "Tipo", "col.metric": "Métrica", "col.rate": "Tasa",
      "col.threshold": "Umbral", "col.topsources": "Fuentes principales", "col.ban": "Bloqueo",
      "col.peak": "Tasa máx.", "col.started": "Inicio", "col.ended": "Fin",
      "col.duration": "Duración", "col.route": "Ruta", "col.method": "Método",
      "col.state": "Estado", "col.mode": "Modo", "col.expires": "Expira",
      "col.type2": "Origen", "col.reason": "Motivo", "col.host": "Host",
      "col.group": "Grupo", "col.baseline": "Referencia", "col.calc": "Cálculo",
      "col.value": "Valor",

      /* overview */
      "ov.allclear.title": "Todo en calma",
      "ov.allclear.sub": "Sin ataques activos. El motor vigila cada host monitorizado frente a sus umbrales y referencias aprendidas.",
      "ov.firstrun.title": "Escuchando el tráfico",
      "ov.firstrun.sub": "Kapkan está en línea e ingiriendo datos de flujo. Los principales emisores y las referencias se llenan a medida que llegan las muestras — es lo esperado en una instalación nueva.",
      "ov.attack.sub": "Mitigación activa en curso. La escalera de escalado avanza automáticamente; revisa e interviene abajo.",
      "ov.mitigating.sub": "Mitigación aplicada. Manteniéndose en el nivel actual mientras el tráfico se estabiliza.",
      "ov.traffic": "Tráfico agregado",
      "ov.ingress": "Entrante", "ov.egress": "Saliente",
      "ov.now": "ahora", "ov.attackwindow": "Ventana de ataque",
      "ov.heroline": "{n} requiere atención",
      "stat.activeAttacks": "Ataques activos",
      "stat.activeBans": "Bloqueos activos",
      "stat.hostsTracked": "Hosts monitorizados",
      "stat.networks": "Redes protegidas",
      "stat.peak60": "Pico 60 s",
      "stat.allzero": "Sin novedad",

      /* attacks */
      "at.active": "Ataques activos",
      "at.recent": "Ataques recientes",
      "at.empty.title": "Sin ataques activos",
      "at.empty.sub": "Cuando un host o grupo supera su umbral, el ataque y la respuesta del motor aparecen aquí.",
      "at.recent.empty": "Aún no se han registrado ataques.",
      "filter.scope": "Ámbito", "filter.dir": "Sentido", "filter.type": "Tipo",
      "filter.group": "Grupo", "filter.all": "Todos", "filter.search": "Buscar objetivo…",
      "at.viewdetail": "Detalle",

      /* attack card / detail */
      "ac.classification": "Clasificación",
      "ac.confidence": "confianza",
      "ac.metricvsthreshold": "Métrica vs umbral",
      "ac.over": "× por encima",
      "ac.overthreshold": "por encima del umbral",
      "ac.escalation": "Escalera de escalado",
      "ac.mitigation": "Mitigación aplicada",
      "ac.sample": "Muestra capturada",
      "ac.topsources": "Fuentes principales",
      "ac.topsrcports": "Puertos de origen principales",
      "ac.topdstports": "Puertos de destino principales",
      "ac.protocols": "Protocolos",
      "ac.rawflows": "Flujos en bruto",
      "ac.lifecycle": "Ciclo de vida del bloqueo",
      "ac.escalate": "Escalar",
      "ac.withdraw": "Retirar",
      "ac.escalate.confirm": "¿Avanzar la mitigación al siguiente nivel de inmediato, antes del temporizador?",
      "ac.withdraw.confirm": "¿Retirar la mitigación de {t}? Se elimina el anuncio BGP y se restablece el tráfico.",
      "ac.withdraw.ok": "Mitigación retirada",
      "ac.escalate.ok": "Escalado a {s}",
      "ac.totalpackets": "paquetes muestreados en total",
      "ac.current": "Actual", "ac.threshold": "Umbral", "ac.peak": "Pico",
      "ac.nexthop": "Próximo salto", "ac.community": "Comunidad",
      "ac.localpref": "Local-pref", "ac.prefix": "Prefijo", "ac.route": "Ruta",
      "ac.flowspec": "Regla FlowSpec", "ac.alertonly": "Solo alerta — sin ruta anunciada",
      "ac.groupnote": "La detección a nivel de grupo es solo alerta; no hay un objetivo único para bloquear automáticamente.",
      "ac.detected": "Detectado",
      "ac.proto": "proto", "ac.flags": "flags", "ac.frag": "frag", "ac.packets": "paquetes",
      "ac.simulated": "Simulado (modo simulación)",

      /* escalation ladder */
      "lad.timeinstage": "en este nivel",
      "lad.nextin": "siguiente en",
      "lad.atmax": "Último nivel — blackhole completo activo",
      "lad.holding": "manteniendo",
      "lad.alertonly": "solo alerta",
      "lad.config": "Escalera configurada",
      "lad.rampnote": "La severidad sube de alerta a blackhole",

      /* bans */
      "bn.active": "Bloqueos activos",
      "bn.history": "Historial retirados / rechazados",
      "bn.manual": "Mitigación manual",
      "bn.manual.sub": "Bloquear o desbloquear una sola IP de inmediato. El motor valida el objetivo antes de anunciar.",
      "bn.ip": "IP objetivo",
      "bn.ban": "Bloquear", "bn.unban": "Desbloquear",
      "bn.ban.confirm": "¿Anunciar una ruta blackhole para {t}? Se descarta todo el tráfico hacia el objetivo.",
      "bn.unban.confirm": "¿Retirar el bloqueo de {t}?",
      "bn.ban.ok": "Bloqueo anunciado para {t}",
      "bn.unban.ok": "Bloqueo retirado para {t}",
      "bn.manualtag": "Manual", "bn.autotag": "Auto",
      "bn.expiresin": "en {t}",
      "bn.noexpire": "sin caducidad",
      "bn.empty.title": "Sin bloqueos activos",
      "bn.empty.sub": "Las mitigaciones automáticas y manuales aparecen aquí con su ruta, modo y cuenta atrás.",
      "bn.history.empty": "Sin bloqueos retirados ni rechazados.",
      "reject.whitelisted": "El objetivo está en la lista blanca",
      "reject.outside": "Objetivo fuera de las redes protegidas",
      "reject.cap": "Límite max_active_bans alcanzado",
      "reject.label": "Rechazado",

      /* hosts */
      "ho.inout": "Sentido",
      "ho.overbaseline": "× por encima de la referencia",
      "ho.baseline": "referencia",
      "ho.current": "actual",
      "ho.nobaseline": "aprendiendo la referencia…",
      "ho.protocols": "Desglose por protocolo",
      "ho.inattack": "Bajo ataque",
      "ho.empty.title": "Aún no hay hosts monitorizados",
      "ho.empty.sub": "Los principales emisores se llenan a partir de las muestras de flujo. En una instalación nueva, esto se llena en unos pocos ciclos de sondeo.",
      "ho.headline": "Ordenados por tasa respecto a la referencia aprendida",

      /* hostgroups */
      "hg.policy": "Política",
      "hg.calc": "Modo de cálculo",
      "calc.per_host": "Por host", "calc.total": "Total del grupo",
      "hg.thresholds": "Umbrales",
      "hg.mitigation": "Método de mitigación",
      "hg.escalation": "Escalera de escalado",
      "hg.banenabled": "Bloqueo auto",
      "hg.baseline": "Aprendizaje de referencia",
      "hg.bgp": "Atributos BGP",
      "hg.nexthop": "Próximo salto", "hg.community": "Comunidades",
      "hg.localpref": "Local-pref", "hg.scrub": "Próximo salto scrubbing",
      "hg.readonly": "La política de grupos de hosts se define en el archivo de configuración del motor y es de solo lectura aquí.",

      /* traffic */
      "tr.live": "En vivo (búfer de sondeo)",
      "tr.aggregate": "Entrante / saliente agregado",
      "tr.perhost": "Principales hosts — tasa en vivo",
      "tr.window": "Últimas {n} muestras · cadencia 3 s",
      "tr.history.title": "Informes históricos",
      "tr.history.note": "El ancho de banda de largo plazo, los pps y la cronología de ataques provienen de ClickHouse. Activa el almacenamiento en la configuración del motor para llenar esta vista.",
      "tr.history.endpoint": "Requiere almacenamiento ClickHouse",
      "tr.history.detail": "Estos gráficos leen las tablas de ClickHouse {t1} y {t2}; se llenan una vez que el almacenamiento está activado en la configuración del motor.",

      /* settings */
      "se.status": "Estado del motor",
      "se.mode": "Modo de mitigación",
      "se.uptime": "Tiempo activo",
      "se.version": "Versión",
      "se.networks": "Redes protegidas",
      "se.thresholds": "Umbrales globales",
      "se.bgp": "BGP / mitigación",
      "se.routerid": "Router ID",
      "se.localasn": "ASN local",
      "se.neighbors": "Vecinos BGP",
      "se.notify": "Notificaciones",
      "se.reload.title": "Recargar configuración",
      "se.reload.desc": "Vuelve a leer el archivo de configuración sin reiniciar el motor.",
      "se.adminonly": "Campos solo para administradores",
      "se.readonly": "La configuración se gestiona en el archivo de configuración del motor; esta consola la muestra en solo lectura."
    },

    enums: {
      direction: { incoming: "Entrante", outgoing: "Saliente" },
      scope: { host: "Host", group: "Grupo" },
      method: { blackhole: "Blackhole (RTBH)", flowspec: "FlowSpec", divert: "Desvío al scrubber" },
      banState: { active: "Activo", withdrawn: "Retirado", rejected: "Rechazado" },
      action: { none: "Solo alerta", flowspec: "FlowSpec: descarte / límite", divert: "Desvío a depuración", blackhole: "Blackhole (RTBH)" },
      calc: { per_host: "Por host", total: "Total del grupo" },
      attackType: {
        ntp_amplification: "Amplificación NTP",
        dns_amplification: "Amplificación DNS",
        cldap_amplification: "Amplificación CLDAP",
        memcached_amplification: "Amplificación Memcached",
        ssdp_amplification: "Amplificación SSDP",
        chargen_amplification: "Amplificación CHARGEN",
        syn_flood: "Inundación SYN",
        fragment_flood: "Inundación de fragmentos",
        icmp_flood: "Inundación ICMP",
        udp_flood: "Inundación UDP",
        tcp_flood: "Inundación TCP",
        mixed: "Vector mixto"
      },
      metric: {
        pps: "Paquetes / s", mbps: "Ancho de banda", flows_per_sec: "Flujos / s",
        tcp_pps: "TCP pps", tcp_mbps: "TCP Mb/s", udp_pps: "UDP pps", udp_mbps: "UDP Mb/s",
        icmp_pps: "ICMP pps", icmp_mbps: "ICMP Mb/s", tcp_syn_pps: "TCP SYN pps",
        tcp_syn_mbps: "TCP SYN Mb/s", frag_pps: "Fragmentos pps", frag_mbps: "Fragmentos Mb/s"
      }
    },

    enumsShort: {
      action: { none: "Alerta", flowspec: "FlowSpec", divert: "Desvío", blackhole: "Blackhole" }
    }
  };
})(window);
