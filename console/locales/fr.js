/* locales/fr.js — French catalog. Mirrors en.js key-for-key. Technical tokens
   (FlowSpec, RTBH, BGP, NTP/DNS/SYN…, pps, Mb/s, IPs, routes) stay verbatim. */
(function (w) {
  w.KAPKAN_LOCALES = w.KAPKAN_LOCALES || {};
  w.KAPKAN_LOCALES.fr = {
    units: { d: "j", h: "h", m: "min", s: "s" },

    plurals: {
      activeAttacks: { one: "# attaque active", other: "# attaques actives" },
      activeBans:    { one: "# blocage actif", other: "# blocages actifs" },
      hostsTracked:  { one: "# hôte suivi", other: "# hôtes suivis" },
      sources:       { one: "# source", other: "# sources" },
      recentAttacks: { one: "# attaque récente", other: "# attaques récentes" }
    },

    strings: {
      /* nav */
      "nav.section.monitor": "Surveillance",
      "nav.section.config": "Configuration",
      "nav.overview": "Vue d'ensemble",
      "nav.attacks": "Attaques",
      "nav.bans": "Blocages / Atténuation",
      "nav.hosts": "Hôtes",
      "nav.hostgroups": "Groupes d'hôtes",
      "nav.traffic": "Trafic / Rapports",
      "nav.settings": "Paramètres",

      /* role */
      "role.viewer": "Observateur",
      "role.operator": "Opérateur",

      /* posture + mode */
      "posture.calm": "Calme",
      "posture.attack": "Sous attaque",
      "posture.mitigating": "Atténuation en cours",
      "mode.dryrun": "Simulation",
      "mode.live": "Réel",
      "mode.dryrun.full": "Simulation — l'atténuation est simulée",
      "dryrun.banner": "Mode simulation — les routes et blocages ci-dessous sont simulés. Aucune annonce BGP n'est envoyée.",

      /* counters / topbar */
      "counter.attacks": "Attaques",
      "counter.bans": "Blocages",
      "counter.hosts": "Hôtes",
      "counter.networks": "Réseaux",
      "live.label": "En direct",
      "live.updated": "Mis à jour",
      "btn.reload": "Recharger la config",
      "reload.ok": "Configuration rechargée",
      "reload.confirm.title": "Recharger la configuration ?",
      "reload.confirm.text": "Relit le fichier de configuration et réapplique les seuils et la politique des groupes d'hôtes. Les blocages actifs sont conservés.",
      "locale.title": "Langue",
      "locale.soon": "bientôt",
      "locale.soon.title": "Langue prévue — repli sur l'anglais",
      "sidebar.collapse": "Réduire la barre latérale",

      /* common */
      "common.yes": "Oui", "common.no": "Non",
      "common.enabled": "Activé", "common.disabled": "Désactivé",
      "common.none": "Aucun", "common.na": "—",
      "op.only": "Opérateur uniquement",
      "viewer.note": "Vous êtes en mode Observateur — les actions d'atténuation sont en lecture seule.",
      "confirm.cancel": "Annuler", "confirm.confirm": "Confirmer",
      "state.loading": "Chargement…",
      "error.title": "Moteur injoignable",
      "error.sub": "La console a perdu le contact avec l'API Kapkan. Nouvelle tentative toutes les 3 secondes.",
      "error.retry": "Réessayer",

      /* table columns */
      "col.target": "Cible", "col.scope": "Portée", "col.dir": "Sens",
      "col.type": "Type", "col.metric": "Métrique", "col.rate": "Débit",
      "col.threshold": "Seuil", "col.topsources": "Sources principales", "col.ban": "Blocage",
      "col.peak": "Débit max", "col.started": "Début", "col.ended": "Fin",
      "col.duration": "Durée", "col.route": "Route", "col.method": "Méthode",
      "col.state": "État", "col.mode": "Mode", "col.expires": "Expire",
      "col.type2": "Origine", "col.reason": "Raison", "col.host": "Hôte",
      "col.group": "Groupe", "col.baseline": "Référence", "col.calc": "Calcul",
      "col.value": "Valeur",

      /* overview */
      "ov.allclear.title": "Tout est calme",
      "ov.allclear.sub": "Aucune attaque active. Le moteur surveille chaque hôte suivi par rapport à ses seuils et à ses références apprises.",
      "ov.firstrun.title": "Écoute du trafic",
      "ov.firstrun.sub": "Kapkan est en ligne et ingère les données de flux. Les principaux émetteurs et les références se remplissent à mesure que les échantillons arrivent — c'est normal sur une nouvelle installation.",
      "ov.attack.sub": "Atténuation active en cours. L'échelle d'escalade progresse automatiquement ; vérifiez et intervenez ci-dessous.",
      "ov.mitigating.sub": "Atténuation appliquée. Maintien au niveau actuel le temps que le trafic se stabilise.",
      "ov.traffic": "Trafic agrégé",
      "ov.ingress": "Entrant", "ov.egress": "Sortant",
      "ov.now": "actuel", "ov.attackwindow": "Fenêtre d'attaque",
      "ov.heroline": "{n} requiert une attention",
      "stat.activeAttacks": "Attaques actives",
      "stat.activeBans": "Blocages actifs",
      "stat.hostsTracked": "Hôtes suivis",
      "stat.networks": "Réseaux protégés",
      "stat.peak60": "Pic 60 s",
      "stat.allzero": "RAS",

      /* attacks */
      "at.active": "Attaques actives",
      "at.recent": "Attaques récentes",
      "at.empty.title": "Aucune attaque active",
      "at.empty.sub": "Lorsqu'un hôte ou un groupe dépasse son seuil, l'attaque et la réponse du moteur apparaissent ici.",
      "at.recent.empty": "Aucune attaque enregistrée pour l'instant.",
      "filter.scope": "Portée", "filter.dir": "Sens", "filter.type": "Type",
      "filter.group": "Groupe", "filter.all": "Tous", "filter.search": "Rechercher une cible…",
      "at.viewdetail": "Détail",

      /* attack card / detail */
      "ac.classification": "Classification",
      "ac.confidence": "confiance",
      "ac.metricvsthreshold": "Métrique vs seuil",
      "ac.over": "× au-dessus",
      "ac.overthreshold": "au-dessus du seuil",
      "ac.escalation": "Échelle d'escalade",
      "ac.mitigation": "Atténuation appliquée",
      "ac.sample": "Échantillon capturé",
      "ac.topsources": "Sources principales",
      "ac.topdest": "Destinations principales",
      "ac.topasns": "Top ASN",
      "ac.topdestasns": "Top ASN destination",
      "ac.topsrcports": "Ports source principaux",
      "ac.topdstports": "Ports destination principaux",
      "ac.protocols": "Protocoles",
      "ac.rawflows": "Flux bruts",
      "ac.lifecycle": "Cycle de vie du blocage",
      "ac.escalate": "Escalader",
      "ac.withdraw": "Retirer",
      "ac.escalate.confirm": "Passer immédiatement l'atténuation au niveau suivant, avant le minuteur ?",
      "ac.withdraw.confirm": "Retirer l'atténuation pour {t} ? L'annonce BGP est supprimée et le trafic est rétabli.",
      "ac.withdraw.ok": "Atténuation retirée",
      "ac.escalate.ok": "Escaladé vers {s}",
      "ac.totalpackets": "paquets échantillonnés au total",
      "ac.current": "Actuel", "ac.threshold": "Seuil", "ac.peak": "Pic",
      "ac.nexthop": "Saut suivant", "ac.community": "Communauté",
      "ac.localpref": "Local-pref", "ac.prefix": "Préfixe", "ac.route": "Route",
      "ac.flowspec": "Règle FlowSpec", "ac.alertonly": "Alerte seule — aucune route annoncée",
      "ac.groupnote": "La détection au niveau du groupe est en alerte seule ; pas de cible unique à bloquer automatiquement.",
      "ac.detected": "Détecté",
      "ac.proto": "proto", "ac.flags": "drapeaux", "ac.frag": "frag", "ac.packets": "paquets",
      "ac.simulated": "Simulé (mode simulation)",

      /* why this fired (detection reason) */
      "ac.why": "Pourquoi cela s'est déclenché",
      "ac.why.static": "Seuil statique",
      "ac.why.baseline": "Référence apprise",
      "ac.why.staticnote": "Le seuil statique configuré a été dépassé.",
      "ac.why.baselinenote": "Une référence apprise a défini le seuil qui a été dépassé.",
      "ac.why.warmupnote": "Référence encore en apprentissage ({t} restant) — le seuil statique s'est appliqué.",
      "ac.why.normal": "Normale apprise",
      "ac.why.factor": "Facteur",
      "ac.why.floor": "Plancher",
      "ac.why.ceiling": "Plafond (limite statique)",
      "ac.why.effective": "Seuil effectif",
      "ac.why.shares": "Mix de protocoles",
      "ac.why.dominant": "dominant",
      "ac.why.gate": "Seuil de part dominante : {p}",
      "ac.why.mixed": "Aucun protocole n'a atteint le seuil de {p} — classé comme mixte.",

      /* escalation ladder */
      "lad.timeinstage": "à ce niveau",
      "lad.nextin": "suivant dans",
      "lad.atmax": "Dernier niveau — blackhole complet actif",
      "lad.holding": "maintien",
      "lad.alertonly": "alerte seule",
      "lad.config": "Échelle configurée",
      "lad.rampnote": "La sévérité monte de l'alerte au blackhole",

      /* bans */
      "bn.active": "Blocages actifs",
      "bn.history": "Historique retirés / rejetés",
      "bn.manual": "Atténuation manuelle",
      "bn.manual.sub": "Bloquer ou débloquer une seule IP immédiatement. Le moteur valide la cible avant l'annonce.",
      "bn.ip": "IP cible",
      "bn.ban": "Bloquer", "bn.unban": "Débloquer",
      "bn.ban.confirm": "Annoncer une route blackhole pour {t} ? Tout le trafic vers la cible est rejeté.",
      "bn.unban.confirm": "Retirer le blocage pour {t} ?",
      "bn.ban.ok": "Blocage annoncé pour {t}",
      "bn.unban.ok": "Blocage retiré pour {t}",
      "bn.manualtag": "Manuel", "bn.autotag": "Auto",
      "bn.expiresin": "dans {t}",
      "bn.noexpire": "sans expiration",
      "bn.empty.title": "Aucun blocage actif",
      "bn.empty.sub": "Les atténuations automatiques et manuelles apparaissent ici avec leur route, leur mode et leur compte à rebours.",
      "bn.history.empty": "Aucun blocage retiré ou rejeté.",
      "reject.whitelisted": "La cible est sur liste blanche",
      "reject.outside": "Cible hors des réseaux protégés",
      "reject.cap": "Plafond max_active_bans atteint",
      "reject.label": "Rejeté",

      /* hosts */
      "ho.inout": "Sens",
      "ho.overbaseline": "× au-dessus de la référence",
      "ho.baseline": "référence",
      "ho.current": "actuel",
      "ho.nobaseline": "apprentissage de la référence…",
      "ho.protocols": "Détail par protocole",
      "ho.inattack": "Sous attaque",
      "ho.empty.title": "Aucun hôte suivi pour l'instant",
      "ho.empty.sub": "Les principaux émetteurs se remplissent à partir des échantillons de flux. Sur une nouvelle installation, cela se remplit en quelques cycles d'interrogation.",
      "ho.headline": "Classés par débit par rapport à la référence apprise",

      /* hostgroups */
      "hg.policy": "Politique",
      "hg.calc": "Mode de calcul",
      "calc.per_host": "Par hôte", "calc.total": "Total du groupe",
      "hg.thresholds": "Seuils",
      "hg.mitigation": "Méthode d'atténuation",
      "hg.escalation": "Échelle d'escalade",
      "hg.banenabled": "Blocage auto",
      "hg.baseline": "Apprentissage de la référence",
      "hg.bgp": "Attributs BGP",
      "hg.nexthop": "Saut suivant", "hg.community": "Communautés",
      "hg.localpref": "Local-pref", "hg.scrub": "Saut suivant scrubbing",
      "hg.readonly": "La politique des groupes d'hôtes est définie dans le fichier de configuration du moteur et est en lecture seule ici.",

      /* traffic */
      "tr.live": "En direct (tampon d'interrogation)",
      "tr.aggregate": "Entrant / sortant agrégé",
      "tr.perhost": "Principaux hôtes — débit en direct",
      "tr.window": "{n} derniers échantillons · cadence 3 s",
      "tr.history.title": "Rapports historiques",
      "tr.history.note": "Le débit longue durée, les pps et la chronologie des attaques proviennent de ClickHouse. Activez le stockage dans la configuration du moteur pour remplir cette vue.",
      "tr.history.endpoint": "Nécessite le stockage ClickHouse",
      "tr.history.detail": "Ces graphiques lisent les tables ClickHouse {t1} et {t2} ; ils se remplissent une fois le stockage activé dans la configuration du moteur.",

      /* settings */
      "se.status": "État du moteur",
      "se.mode": "Mode d'atténuation",
      "se.uptime": "Disponibilité",
      "se.version": "Version",

      /* update-available banner */
      "update.banner": "Une nouvelle version est disponible : {version}",
      "update.banner.security": "Une mise à jour de sécurité est disponible : {version}",
      "update.view": "Voir la version",
      "update.dismiss": "Fermer",

      "se.networks": "Réseaux protégés",
      "se.thresholds": "Seuils globaux",
      "se.bgp": "BGP / atténuation",
      "se.routerid": "Router ID",
      "se.localasn": "ASN locale",
      "se.neighbors": "Voisins BGP",
      "se.notify": "Notifications",
      "se.reload.title": "Recharger la configuration",
      "se.reload.desc": "Relit le fichier de configuration sans redémarrer le moteur.",
      "se.adminonly": "Champs réservés aux administrateurs",
      "se.readonly": "La configuration est gérée dans le fichier de configuration du moteur ; cette console l'affiche en lecture seule."
    },

    enums: {
      direction: { incoming: "Entrant", outgoing: "Sortant" },
      scope: { host: "Hôte", group: "Groupe" },
      method: { blackhole: "Blackhole (RTBH)", flowspec: "FlowSpec", divert: "Redirection vers scrubber" },
      banState: { active: "Actif", withdrawn: "Retiré", rejected: "Rejeté" },
      action: { none: "Alerte seule", flowspec: "FlowSpec : rejet / limite", divert: "Redirection vers nettoyage", blackhole: "Blackhole (RTBH)" },
      calc: { per_host: "Par hôte", total: "Total du groupe" },
      attackType: {
        ntp_amplification: "Amplification NTP",
        dns_amplification: "Amplification DNS",
        cldap_amplification: "Amplification CLDAP",
        memcached_amplification: "Amplification Memcached",
        ssdp_amplification: "Amplification SSDP",
        chargen_amplification: "Amplification CHARGEN",
        syn_flood: "Inondation SYN",
        fragment_flood: "Inondation de fragments",
        icmp_flood: "Inondation ICMP",
        udp_flood: "Inondation UDP",
        tcp_flood: "Inondation TCP",
        mixed: "Vecteur mixte"
      },
      metric: {
        pps: "Paquets / s", mbps: "Débit", flows_per_sec: "Flux / s",
        tcp_pps: "TCP pps", tcp_mbps: "TCP Mb/s", udp_pps: "UDP pps", udp_mbps: "UDP Mb/s",
        icmp_pps: "ICMP pps", icmp_mbps: "ICMP Mb/s", tcp_syn_pps: "TCP SYN pps",
        tcp_syn_mbps: "TCP SYN Mb/s", frag_pps: "Fragments pps", frag_mbps: "Fragments Mb/s"
      }
    },

    enumsShort: {
      action: { none: "Alerte", flowspec: "FlowSpec", divert: "Redirection", blackhole: "Blackhole" }
    }
  };
})(window);
