/* locales/en.js — SOURCE catalog. All UI strings + enum label maps live here.
   Verbatim/never-translated values (IPs, routes, metric keys, communities,
   FlowSpec rules, group names) are NOT in this file — they render as data. */
(function (w) {
  w.KAPKAN_LOCALES = w.KAPKAN_LOCALES || {};
  w.KAPKAN_LOCALES.en = {
    units: { d: "d", h: "h", m: "m", s: "s" },

    plurals: {
      activeAttacks: { one: "# active attack", other: "# active attacks" },
      activeBans:    { one: "# active ban", other: "# active bans" },
      hostsTracked:  { one: "# host tracked", other: "# hosts tracked" },
      sources:       { one: "# source", other: "# sources" },
      recentAttacks: { one: "# recent attack", other: "# recent attacks" }
    },

    strings: {
      /* nav */
      "nav.section.monitor": "Monitor",
      "nav.section.config": "Configure",
      "nav.overview": "Overview",
      "nav.attacks": "Attacks",
      "nav.bans": "Bans / Mitigation",
      "nav.hosts": "Hosts",
      "nav.hostgroups": "Hostgroups",
      "nav.traffic": "Traffic / Reports",
      "nav.settings": "Settings",

      /* role */
      "role.viewer": "Viewer",
      "role.operator": "Operator",

      /* posture + mode */
      "posture.calm": "Calm",
      "posture.attack": "Under attack",
      "posture.mitigating": "Mitigating",
      "mode.dryrun": "Dry-run",
      "mode.live": "Live",
      "mode.dryrun.full": "Dry-run — mitigation is simulated",
      "dryrun.banner": "Dry-run mode — routes and bans below are simulated. No BGP announcements are sent.",

      /* counters / topbar */
      "counter.attacks": "Attacks",
      "counter.bans": "Bans",
      "counter.hosts": "Hosts",
      "counter.networks": "Networks",
      "live.label": "Live",
      "live.updated": "Updated",
      "btn.reload": "Reload config",
      "reload.ok": "Configuration reloaded",
      "reload.confirm.title": "Reload configuration?",
      "reload.confirm.text": "Re-reads the config file and re-applies thresholds and hostgroup policy. Active bans are preserved.",
      "locale.title": "Language",
      "locale.soon": "soon",
      "locale.soon.title": "Planned locale — falls back to English strings",
      "sidebar.collapse": "Collapse sidebar",

      /* common */
      "common.yes": "Yes", "common.no": "No",
      "common.enabled": "Enabled", "common.disabled": "Disabled",
      "common.none": "None", "common.na": "—",
      "op.only": "Operator only",
      "viewer.note": "You are in Viewer mode — mitigation actions are read-only.",
      "confirm.cancel": "Cancel", "confirm.confirm": "Confirm",
      "state.loading": "Loading…",
      "error.title": "Can't reach the engine",
      "error.sub": "The console lost contact with the Kapkan API. Retrying every 3 seconds.",
      "error.retry": "Retry now",

      /* table columns */
      "col.target": "Target", "col.scope": "Scope", "col.dir": "Dir",
      "col.type": "Type", "col.metric": "Metric", "col.rate": "Rate",
      "col.threshold": "Threshold", "col.topsources": "Top sources", "col.ban": "Ban",
      "col.peak": "Peak rate", "col.started": "Started", "col.ended": "Ended",
      "col.duration": "Duration", "col.route": "Route", "col.method": "Method",
      "col.state": "State", "col.mode": "Mode", "col.expires": "Expires",
      "col.type2": "Origin", "col.reason": "Reason", "col.host": "Host",
      "col.group": "Group", "col.baseline": "Baseline", "col.calc": "Calc",
      "col.value": "Value",

      /* overview */
      "ov.allclear.title": "All clear",
      "ov.allclear.sub": "No active attacks. The engine is watching every tracked host against its thresholds and learned baselines.",
      "ov.firstrun.title": "Listening for traffic",
      "ov.firstrun.sub": "Kapkan is online and ingesting flow data. Top talkers and baselines populate as samples arrive — this is expected on a fresh install.",
      "ov.attack.sub": "Active mitigation in progress. The escalation ladder advances automatically; review and intervene below.",
      "ov.mitigating.sub": "Mitigation applied. Holding at the current rung while traffic settles.",
      "ov.traffic": "Aggregate traffic",
      "ov.ingress": "Ingress", "ov.egress": "Egress",
      "ov.now": "now", "ov.attackwindow": "Attack window",
      "ov.heroline": "{n} requires attention",
      "stat.activeAttacks": "Active attacks",
      "stat.activeBans": "Active bans",
      "stat.hostsTracked": "Hosts tracked",
      "stat.networks": "Networks protected",
      "stat.peak60": "60s peak",
      "stat.allzero": "Clear",

      /* attacks */
      "at.active": "Active attacks",
      "at.recent": "Recent attacks",
      "at.empty.title": "No active attacks",
      "at.empty.sub": "When a host or group crosses its threshold, the attack and the engine's response appear here.",
      "at.recent.empty": "No attacks recorded yet.",
      "filter.scope": "Scope", "filter.dir": "Direction", "filter.type": "Type",
      "filter.group": "Group", "filter.all": "All", "filter.search": "Search target…",
      "at.viewdetail": "Detail",

      /* attack card / detail */
      "ac.classification": "Classification",
      "ac.confidence": "confidence",
      "ac.metricvsthreshold": "Metric vs threshold",
      "ac.over": "× over",
      "ac.overthreshold": "over threshold",
      "ac.escalation": "Escalation ladder",
      "ac.mitigation": "Applied mitigation",
      "ac.sample": "Captured sample",
      "ac.topsources": "Top sources",
      "ac.topdest": "Top destinations",
      "ac.topasns": "Top ASNs",
      "ac.topdestasns": "Top dest ASNs",
      "ac.topsrcports": "Top source ports",
      "ac.topdstports": "Top dest ports",
      "ac.protocols": "Protocols",
      "ac.rawflows": "Raw flows",
      "ac.lifecycle": "Ban lifecycle",
      "ac.escalate": "Escalate now",
      "ac.withdraw": "Withdraw",
      "ac.escalate.confirm": "Advance mitigation to the next rung immediately, ahead of the timer?",
      "ac.withdraw.confirm": "Withdraw mitigation for {t}? The BGP announcement is removed and traffic is restored.",
      "ac.withdraw.ok": "Mitigation withdrawn",
      "ac.escalate.ok": "Escalated to {s}",
      "ac.totalpackets": "total packets sampled",
      "ac.current": "Current", "ac.threshold": "Threshold", "ac.peak": "Peak",
      "ac.nexthop": "Next-hop", "ac.community": "Community",
      "ac.localpref": "Local-pref", "ac.prefix": "Prefix", "ac.route": "Route",
      "ac.flowspec": "FlowSpec rule", "ac.alertonly": "Alert only — no route announced",
      "ac.groupnote": "Group-scoped detection is alert-only; no single target to auto-ban.",
      "ac.detected": "Detected",
      "ac.proto": "proto", "ac.flags": "flags", "ac.frag": "frag", "ac.packets": "packets",
      "ac.simulated": "Simulated (dry-run)",

      /* why this fired (detection reason) */
      "ac.why": "Why this fired",
      "ac.why.static": "Static threshold",
      "ac.why.baseline": "Learned baseline",
      "ac.why.staticnote": "The configured static threshold was crossed.",
      "ac.why.baselinenote": "A learned baseline set the threshold that was crossed.",
      "ac.why.warmupnote": "Baseline still warming up ({t} left) — the static threshold applied.",
      "ac.why.normal": "Learned normal",
      "ac.why.factor": "Factor",
      "ac.why.floor": "Floor",
      "ac.why.ceiling": "Ceiling (static cap)",
      "ac.why.effective": "Effective threshold",
      "ac.why.shares": "Protocol mix",
      "ac.why.dominant": "dominant",
      "ac.why.gate": "Dominant-share gate: {p}",
      "ac.why.mixed": "No protocol reached the {p} gate — classified as mixed.",

      /* escalation ladder */
      "lad.timeinstage": "in stage",
      "lad.nextin": "next in",
      "lad.atmax": "Top rung — full blackhole active",
      "lad.holding": "holding",
      "lad.alertonly": "alert only",
      "lad.config": "Configured ladder",
      "lad.rampnote": "Severity ramps from alert → blackhole",

      /* bans */
      "bn.active": "Active bans",
      "bn.history": "Withdrawn / rejected history",
      "bn.manual": "Manual mitigation",
      "bn.manual.sub": "Ban or unban a single IP immediately. The engine validates the target before announcing.",
      "bn.ip": "Target IP",
      "bn.ban": "Ban", "bn.unban": "Unban",
      "bn.ban.confirm": "Announce a blackhole route for {t}? This drops all traffic to the target.",
      "bn.unban.confirm": "Withdraw the ban for {t}?",
      "bn.ban.ok": "Ban announced for {t}",
      "bn.unban.ok": "Ban withdrawn for {t}",
      "bn.manualtag": "Manual", "bn.autotag": "Auto",
      "bn.expiresin": "in {t}",
      "bn.noexpire": "no expiry",
      "bn.empty.title": "No active bans",
      "bn.empty.sub": "Automatic and manual mitigations appear here with their route, mode and countdown.",
      "bn.history.empty": "No withdrawn or rejected bans.",
      "reject.whitelisted": "Target is whitelisted",
      "reject.outside": "Target outside protected networks",
      "reject.cap": "max_active_bans cap reached",
      "reject.label": "Rejected",

      /* hosts */
      "ho.inout": "Direction",
      "ho.overbaseline": "× over baseline",
      "ho.baseline": "baseline",
      "ho.current": "current",
      "ho.nobaseline": "learning baseline…",
      "ho.protocols": "Per-protocol breakdown",
      "ho.inattack": "In attack",
      "ho.empty.title": "No tracked hosts yet",
      "ho.empty.sub": "Top talkers populate from flow samples. On a fresh install this fills within a few polling cycles.",
      "ho.headline": "Ranked by throughput (Mbit/s)",

      /* hostgroups */
      "hg.policy": "Policy",
      "hg.calc": "Calc mode",
      "calc.per_host": "Per host", "calc.total": "Group total",
      "hg.thresholds": "Thresholds",
      "hg.mitigation": "Mitigation method",
      "hg.escalation": "Escalation ladder",
      "hg.banenabled": "Auto-ban",
      "hg.baseline": "Baseline learning",
      "hg.bgp": "BGP attributes",
      "hg.nexthop": "Next-hop", "hg.community": "Communities",
      "hg.localpref": "Local-pref", "hg.scrub": "Scrub next-hop",
      "hg.readonly": "Hostgroup policy is configured in the engine config file and is read-only here.",

      /* traffic */
      "tr.live": "Live (polling buffer)",
      "tr.aggregate": "Aggregate ingress / egress",
      "tr.perhost": "Top hosts — live rate",
      "tr.window": "Last {n} samples · 3s cadence",
      "tr.history.title": "Historical reports",
      "tr.history.note": "Long-range bandwidth, pps and the attack timeline come from ClickHouse. Enable storage in the engine config to populate this view.",
      "tr.history.endpoint": "Requires ClickHouse storage",
      "tr.history.detail": "These charts read the ClickHouse tables {t1} and {t2}; they fill in once storage is enabled in the engine config.",

      /* settings */
      "se.status": "Engine status",
      "se.mode": "Mitigation mode",
      "se.uptime": "Uptime",
      "se.version": "Version",

      /* update-available banner */
      "update.banner": "A new version is available: {version}",
      "update.banner.security": "A security update is available: {version}",
      "update.view": "View release",
      "update.dismiss": "Dismiss",

      "se.networks": "Protected networks",
      "se.thresholds": "Global thresholds",
      "se.bgp": "BGP / mitigation",
      "se.routerid": "Router ID",
      "se.localasn": "Local ASN",
      "se.neighbors": "BGP neighbors",
      "se.notify": "Notifications",
      "se.reload.title": "Reload configuration",
      "se.reload.desc": "Re-read the config file without restarting the engine.",
      "se.adminonly": "Admin-only fields",
      "se.readonly": "Configuration is managed in the engine config file; this console shows it read-only."
    },

    enums: {
      direction: { incoming: "Incoming", outgoing: "Outgoing" },
      scope: { host: "Host", group: "Group" },
      method: { blackhole: "Blackhole (RTBH)", flowspec: "FlowSpec", divert: "Divert to scrubber" },
      banState: { active: "Active", withdrawn: "Withdrawn", rejected: "Rejected" },
      action: { none: "Alert only", flowspec: "FlowSpec drop / rate-limit", divert: "Divert to scrubbing", blackhole: "Blackhole (RTBH)" },
      calc: { per_host: "Per host", total: "Group total" },
      attackType: {
        ntp_amplification: "NTP amplification",
        dns_amplification: "DNS amplification",
        cldap_amplification: "CLDAP amplification",
        memcached_amplification: "Memcached amplification",
        ssdp_amplification: "SSDP amplification",
        chargen_amplification: "CHARGEN amplification",
        syn_flood: "SYN flood",
        fragment_flood: "Fragment flood",
        icmp_flood: "ICMP flood",
        udp_flood: "UDP flood",
        tcp_flood: "TCP flood",
        mixed: "Mixed vector"
      },
      metric: {
        pps: "Packets / s", mbps: "Bandwidth", flows_per_sec: "Flows / s",
        tcp_pps: "TCP pps", tcp_mbps: "TCP Mb/s", udp_pps: "UDP pps", udp_mbps: "UDP Mb/s",
        icmp_pps: "ICMP pps", icmp_mbps: "ICMP Mb/s", tcp_syn_pps: "TCP SYN pps",
        tcp_syn_mbps: "TCP SYN Mb/s", frag_pps: "Fragment pps", frag_mbps: "Fragment Mb/s"
      }
    },

    /* short label variants for tight widths (escalation ladder rungs) */
    enumsShort: {
      action: { none: "Alert", flowspec: "FlowSpec", divert: "Divert", blackhole: "Blackhole" }
    }
  };
})(window);
