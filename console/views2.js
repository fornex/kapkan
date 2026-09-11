/* views2.js — lighter views (Hostgroups, Traffic/Reports, Settings) +
   the attack-detail drawer content. Extends window.Views. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h, V = w.Views;

  /* ===== ATTACK DETAIL DRAWER ===== */
  function attackDetail(a, ctx) {
    var isLive = a.active;
    var actions = [];
    if (ctx.role === "operator" && isLive) {
      actions.push(h("button", { class: "btn btn--danger btn--sm", onclick: function (e) { ctx.actions.withdraw(e.currentTarget, a.target); } }, [w.icon("x"), h("span", { text: I.t("ac.withdraw") })]));
    }

    var head = h("div", { class: "drawer__head" }, [
      h("div", { class: "drawer__title" }, [
        h("div", { class: "attack-card__target" }, [
          h("span", { class: "mono", text: a.scope === "group" ? a.group : a.target }),
          K.dirBadge(a.direction)
        ]),
        h("div", { class: "attack-card__sub" }, [
          K.badge("badge--active", I.label("attackType", a.classification.type), "flame"),
          K.badge(isLive ? "badge--active" : "badge--muted", isLive ? I.t("posture.mitigating") : I.label("banState", a.ban_state || "withdrawn")),
          a.dry_run ? K.badge("badge--dry", I.t("mode.dryrun"), "shield-alert") : null
        ])
      ]),
      h("button", { class: "icon-btn", attrs: { "aria-label": "Close" }, onclick: function () { ctx.actions.closeDrawer(); } }, w.icon("x"))
    ]);

    var sample = a.sample;
    // For outgoing attacks the host itself is the single source, so the engine
    // ranks the remote *destinations* (the victims) under top_sources/top_asns.
    // Relabel accordingly so the panel doesn't call destinations "sources".
    var isOut = a.direction === "outgoing";
    var body = h("div", { class: "drawer__body" }, [
      actions.length ? h("div", { class: "row", style: { justifyContent: "flex-end" } }, actions) : null,

      section("ac.classification", "info", h("div", { class: "row wrap", style: { gap: "var(--s-4)" } }, [
        K.badge("badge--active", I.label("attackType", a.classification.type), "flame"),
        K.confidence(a.classification.confidence),
        a.classification.src_port != null ? h("span", { class: "td-muted" }, ["src port ", h("span", { class: "mono", text: String(a.classification.src_port) })]) : null
      ])),

      section("ac.metricvsthreshold", "activity", K.gauge(a.metric, a.rate || a.peak_rate || 0, a.threshold)),

      a.reason ? section("ac.why", "zap", reasonBody(a.reason)) : null,

      section("ac.escalation", "layers", h("div", {}, [
        K.ladder(a.escalation, a.escalation_step, { live: isLive, startedMs: new Date(a.started_at).getTime() }),
        h("div", { class: "ladder__legend" }, [w.icon("info"), h("span", { text: I.t("lad.rampnote") })])
      ])),

      a.method || a.route
        ? section("ac.mitigation", "shield", K.routeDisplay(a, a.dry_run))
        : section("ac.mitigation", "bell", h("div", { class: "route" }, h("div", { class: "route__line" }, h("span", { class: "route__v", text: a.scope === "group" ? I.t("ac.groupnote") : I.t("ac.alertonly") })))),

      // "Installed in kernel": each announced rule beside what the datapath
      // measured for it. Only for a data-plane mitigation — for a flowspec ban
      // the rules were handed to an upstream peer and this box counts nothing,
      // so a panel of dashes would imply a measurement that does not exist.
      a.method === "dataplane" ? section("ac.inkernel", "chip", K.kernelRules(a)) : null,

      sample ? section("ac.sample", "target", h("div", {}, [
        h("div", { class: "shares" }, [
          K.shareGroup(I.t(isOut ? "ac.topdest" : "ac.topsources"), sample.top_sources, { src: true }),
          (sample.top_asns && sample.top_asns.length) ? K.shareGroup(I.t(isOut ? "ac.topdestasns" : "ac.topasns"), sample.top_asns, { src: true }) : null,
          K.shareGroup(I.t("ac.protocols"), sample.protocols, {}),
          K.shareGroup(I.t("ac.topsrcports"), sample.top_src_ports, {}),
          K.shareGroup(I.t("ac.topdstports"), sample.top_dst_ports, {})
        ]),
        h("div", { class: "td-muted", style: { marginTop: "var(--s-3)", fontSize: "var(--t-xs)" }, text: I.num(sample.total_packets) + " " + I.t("ac.totalpackets") })
      ])) : null,

      sample && sample.flows ? section("ac.rawflows", "database", rawFlows(sample.flows)) : null,

      section("ac.lifecycle", "clock", K.timeline(a))
    ]);

    return [head, body];
  }
  function section(titleKey, icon, body) {
    return h("div", {}, [h("div", { class: "section-label" }, [w.icon(icon), h("span", { text: I.t(titleKey) })]), body]);
  }
  /* "Why this fired" — renders the detection Reason: threshold provenance
     (static vs learned baseline, with the baseline math), warm-up state, and
     the protocol-share breakdown that drove classification. r is a.reason;
     absent on attacks captured before explainability shipped (caller guards). */
  function reasonBody(r) {
    var blocks = [];
    var isBaseline = r.threshold_source === "baseline" && r.baseline;

    blocks.push(h("div", { class: "reason__src" }, [
      isBaseline ? K.badge("badge--active", I.t("ac.why.baseline"), "activity")
                 : K.badge("badge--muted", I.t("ac.why.static"), "shield"),
      h("span", { class: "td-muted", text: isBaseline ? I.t("ac.why.baselinenote") : I.t("ac.why.staticnote") })
    ]));

    if (r.warming_up) {
      var left = r.warmup_remaining_seconds ? I.countdown(r.warmup_remaining_seconds) : "—";
      blocks.push(h("div", { class: "reason__warmup" }, [
        w.icon("clock"), h("span", { text: I.t("ac.why.warmupnote", { t: left }) })
      ]));
    }

    if (isBaseline) {
      var b = r.baseline;
      var eff = Math.min(b.ceiling, Math.max(b.floor, b.normal * b.factor));
      var kv = [
        ["ac.why.normal", I.abbr(b.normal), false],
        ["ac.why.factor", "×" + I.abbr(b.factor, ""), false],
        ["ac.why.floor", I.abbr(b.floor), false],
        ["ac.why.ceiling", I.abbr(b.ceiling), false],
        ["ac.why.effective", I.abbr(eff), true]
      ];
      blocks.push(h("div", { class: "reason__math" }, kv.map(function (row) {
        return h("div", { class: "reason__kv" + (row[2] ? " is-eff" : "") }, [
          h("span", { class: "reason__kv-k", text: I.t(row[0]) }),
          h("span", { class: "reason__kv-v mono", text: row[1] })
        ]);
      })));
      blocks.push(h("div", { class: "reason__formula mono td-muted", text: "min(ceiling, max(floor, normal × factor))" }));
    }

    var shares = r.shares || {};
    var gate = r.dominant_share_gate || 0.5;
    var list = [["udp", "UDP"], ["syn", "SYN"], ["tcp", "TCP"], ["icmp", "ICMP"], ["frag", "Frag"]]
      .map(function (p) { return { key: p[1], v: shares[p[0]] || 0 }; })
      .filter(function (x) { return x.v > 0; })
      .sort(function (x, y) { return y.v - x.v; });
    if (list.length) {
      var anyDom = false;
      var bars = list.map(function (x) {
        var dom = x.v >= gate; if (dom) anyDom = true;
        var bar = h("i"); bar.style.width = Math.max(2, x.v * 100) + "%";
        return h("div", { class: "share" }, [
          h("span", { class: "share__key" }, [
            h("span", { text: x.key }),
            dom ? h("span", { class: "reason__dom", text: I.t("ac.why.dominant") }) : null
          ]),
          h("span", { class: "share__pct", text: I.pct(x.v) }),
          h("span", { class: "share__bar" + (dom ? " is-dom" : "") }, bar)
        ]);
      });
      blocks.push(h("div", { class: "reason__shares" }, [
        h("div", { class: "share-group__title", text: I.t("ac.why.shares") }),
        bars,
        h("div", { class: "reason__gate td-muted", text: I.t(anyDom ? "ac.why.gate" : "ac.why.mixed", { p: I.pct(gate) }) })
      ]));
    }

    return h("div", { class: "reason" }, blocks);
  }
  function rawFlows(flows) {
    var head = h("tr", {}, ["src", "ac.proto", "dst", "dport", "ac.flags", "ac.frag", "ac.packets"].map(function (k, i) {
      var label = i === 0 ? "src → " : (k.indexOf(".") > 0 ? I.t(k) : k);
      return h("th", { text: label });
    }));
    var rows = flows.map(function (f) {
      var srcCell = [h("span", { text: f.src }), h("span", { class: "td-muted", text: ":" + f.src_port })];
      if (f.src_country) srcCell.push(h("span", { class: "geo-tag", title: f.src_org || "", text: f.src_country }));
      return h("tr", {}, [
        h("td", {}, srcCell),
        h("td", { text: f.proto }),
        h("td", {}, [h("span", { text: f.dst }), h("span", { class: "td-muted", text: ":" + f.dst_port })]),
        h("td", { text: String(f.dst_port) }),
        h("td", {}, f.flags ? h("span", { class: "flag", text: f.flags }) : h("span", { class: "td-muted", text: "—" })),
        h("td", {}, f.fragment ? h("span", { class: "flag", text: "Y" }) : h("span", { class: "td-muted", text: "—" })),
        h("td", { class: "num", text: I.num(f.packets) })
      ]);
    });
    return h("div", { class: "tablewrap" }, h("table", { class: "tbl flows" }, [h("thead", {}, head), h("tbody", {}, rows)]));
  }

  /* ===== HOSTGROUPS ===== */
  /* full policy detail for one group — shown in the expanded table row */
  function groupBody(g) {
    var thr = g.thresholds || {};
    var thrRows = Object.keys(thr).map(function (k) {
      return [h("dt", { class: "mono", text: k }), h("dd", { class: "mono", text: I.abbr(thr[k]) })];
    });
    var bgpRows = [
      [h("dt", { text: I.t("hg.nexthop") }), h("dd", { class: "mono", text: g.next_hop || I.t("common.na") })],
      [h("dt", { text: I.t("hg.community") }), h("dd", { class: "mono", text: g.community || I.t("common.na") })],
      [h("dt", { text: I.t("hg.localpref") }), h("dd", { class: "mono", text: g.local_pref != null ? String(g.local_pref) : I.t("common.na") })],
      [h("dt", { text: I.t("hg.scrub") }), h("dd", { class: "mono", text: g.scrub_next_hop || I.t("common.na") })]
    ];
    var bl = g.baseline, blRows = [[h("dt", { text: I.t("hg.baseline") }), h("dd", { text: bl ? I.t("common.enabled") : I.t("common.disabled") })]];
    if (bl) {
      blRows.push([h("dt", { text: "factor" }), h("dd", { class: "mono", text: "×" + bl.factor })]);
      if (bl.warmup_seconds != null) blRows.push([h("dt", { text: "warmup" }), h("dd", { class: "mono", text: bl.warmup_seconds + "s" })]);
    }
    return h("div", { class: "stack" }, [
      h("div", { class: "cols-2" }, [
        h("div", {}, [h("div", { class: "section-label", text: I.t("hg.thresholds") }), h("dl", { class: "kv" }, [].concat.apply([], thrRows))]),
        h("div", {}, [h("div", { class: "section-label", text: I.t("hg.baseline") }), h("dl", { class: "kv" }, [].concat.apply([], blRows))])
      ]),
      h("div", {}, [
        h("div", { class: "section-label" }, [w.icon("layers"), h("span", { text: I.t("hg.escalation") }), h("span", { class: "td-muted", style: { fontSize: "var(--t-xs)" }, text: "· " + I.t("lad.config") })]),
        K.ladder(g.escalation, -1, { config: true })
      ]),
      h("div", {}, [h("div", { class: "section-label", text: I.t("hg.bgp") }), h("dl", { class: "kv" }, [].concat.apply([], bgpRows))])
    ]);
  }

  function hgKey(e, fn) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fn(); } }

  function hostgroups(root, ctx) {
    var rows = [];
    ctx.groups.forEach(function (g) {
      var key = "hg:" + g.name, expanded = ctx.state.expanded.has(key);
      var toggle = function () { ctx.actions.toggleHost(key); };
      rows.push(h("tr", { class: "is-clickable" + (expanded ? " is-open" : ""), tabindex: "0", role: "button", "data-akey": key,
        onclick: toggle, onkeydown: function (e) { hgKey(e, toggle); } }, [
        h("td", { class: "target-cell" }, h("span", { class: "row", style: { gap: "8px" } }, [w.icon(expanded ? "chevron-down" : "chevron-right"), h("span", { class: "mono", text: g.name })])),
        h("td", {}, K.badge("badge--muted", I.label("calc", g.calc))),
        h("td", {}, K.methodPill(g.mitigation)),
        h("td", {}, K.badge(g.ban_enabled ? "badge--calm" : "badge--muted", g.ban_enabled ? I.t("common.enabled") : I.t("common.disabled"))),
        h("td", { class: "mono", text: g.baseline ? "×" + g.baseline.factor : "—" })
      ]));
      if (expanded) rows.push(h("tr", { class: "attack-detail-row" }, h("td", { attrs: { colspan: "5" } }, h("div", { class: "attack-card__body" }, groupBody(g)))));
    });
    function hgth(k) { return h("th", { text: I.t(k) }); }
    K.mount(root, [
      V.viewHead(I.t("nav.hostgroups"), null),
      h("div", { class: "banner banner--info" }, [w.icon("lock"), h("span", { class: "banner__txt", text: I.t("hg.readonly") })]),
      h("div", { class: "card" }, h("div", { class: "tablewrap" }, h("table", { class: "tbl attacks-tbl" }, [
        h("thead", {}, h("tr", {}, [hgth("col.group"), hgth("hg.calc"), hgth("col.method"), hgth("hg.banenabled"), hgth("hg.baseline")])),
        h("tbody", {}, rows)
      ])))
    ]);
  }

  /* ===== TRAFFIC / REPORTS ===== */
  function traffic(root, ctx) {
    var b = ctx.buf;
    var bigIn = h("div", { class: "tcard" }, [
      h("div", { class: "tcard__head" }, [
        h("div", { class: "tcard__label" }, [(function () { var d = h("span", { class: "tcard__dir" }); d.style.background = "var(--chart-in)"; return d; })(), h("span", { text: I.t("ov.ingress") })]),
        h("div", { class: "tcard__now" }, [I.mbps(ctx.agg.in_mbps)])
      ]),
      h("div", { class: "tcard__chart", style: { height: "130px" } }, K.areaChart(b.aggIn.length ? b.aggIn : [0, 0], { color: "var(--chart-in)", height: 130 }))
    ]);
    var bigOut = h("div", { class: "tcard" }, [
      h("div", { class: "tcard__head" }, [
        h("div", { class: "tcard__label" }, [(function () { var d = h("span", { class: "tcard__dir" }); d.style.background = "var(--chart-out)"; return d; })(), h("span", { text: I.t("ov.egress") })]),
        h("div", { class: "tcard__now" }, [I.mbps(ctx.agg.out_mbps)])
      ]),
      h("div", { class: "tcard__chart", style: { height: "130px" } }, K.areaChart(b.aggOut.length ? b.aggOut : [0, 0], { color: "var(--chart-out)", height: 130 }))
    ]);

    /* aggregate packet-rate twin of the bandwidth cards above */
    var bigInPps = h("div", { class: "tcard" }, [
      h("div", { class: "tcard__head" }, [
        h("div", { class: "tcard__label" }, [(function () { var d = h("span", { class: "tcard__dir" }); d.style.background = "var(--chart-in)"; return d; })(), h("span", { text: I.t("ov.ingress") })]),
        h("div", { class: "tcard__now" }, [I.pps(ctx.agg.in_pps)])
      ]),
      h("div", { class: "tcard__chart", style: { height: "130px" } }, K.areaChart(b.aggInPps.length ? b.aggInPps : [0, 0], { color: "var(--chart-in)", height: 130 }))
    ]);
    var bigOutPps = h("div", { class: "tcard" }, [
      h("div", { class: "tcard__head" }, [
        h("div", { class: "tcard__label" }, [(function () { var d = h("span", { class: "tcard__dir" }); d.style.background = "var(--chart-out)"; return d; })(), h("span", { text: I.t("ov.egress") })]),
        h("div", { class: "tcard__now" }, [I.pps(ctx.agg.out_pps)])
      ]),
      h("div", { class: "tcard__chart", style: { height: "130px" } }, K.areaChart(b.aggOutPps.length ? b.aggOutPps : [0, 0], { color: "var(--chart-out)", height: 130 }))
    ]);

    /* top host sparklines from per-host buffer — ranked by bandwidth */
    var hostCardsMbps = ctx.hosts.slice().sort(function (x, y) { return y.rates.mbps - x.rates.mbps; }).slice(0, 6).map(function (host) {
      var series = (b.hostMbps[host.target] || [host.rates.mbps]);
      return h("div", { class: "tcard" }, [
        h("div", { class: "tcard__head" }, [
          h("div", { class: "tcard__label mono", text: host.target }),
          h("div", { class: "tcard__now", style: { fontSize: "var(--t-md)" }, text: I.mbps(host.rates.mbps) })
        ]),
        h("div", { class: "tcard__chart", style: { height: "44px" } }, K.sparkline(series, { color: host.in_attack ? "var(--active)" : "var(--chart-in)", height: 44 }))
      ]);
    });

    /* top host sparklines from per-host buffer — ranked by packet rate */
    var hostCards = ctx.hosts.slice().sort(function (x, y) { return y.rates.pps - x.rates.pps; }).slice(0, 6).map(function (host) {
      var series = (b.hostPps[host.target] || [host.rates.pps]);
      return h("div", { class: "tcard" }, [
        h("div", { class: "tcard__head" }, [
          h("div", { class: "tcard__label mono", text: host.target }),
          h("div", { class: "tcard__now", style: { fontSize: "var(--t-md)" }, text: I.pps(host.rates.pps) })
        ]),
        h("div", { class: "tcard__chart", style: { height: "44px" } }, K.sparkline(series, { color: host.in_attack ? "var(--active)" : "var(--accent)", height: 44 }))
      ]);
    });

    var ext = h("div", { class: "ext-point" }, [
      h("span", { class: "ext-point__badge" }, K.badge("badge--elev", I.t("tr.history.endpoint"), "history")),
      h("div", { class: "section-label", style: { fontSize: "var(--t-md)", color: "var(--text)" } }, [w.icon("chart"), h("span", { text: I.t("tr.history.title") })]),
      h("p", { class: "td-muted", style: { maxWidth: "72ch", marginBottom: "var(--s-4)" }, text: I.t("tr.history.note") }),
      h("div", { class: "ext-ghost" }, ghostChart()),
      h("div", { class: "ext-note" }, [w.icon("database"), h("div", {}, [
        I.t("tr.history.detail", { ep: "", t1: "traffic", t2: "attack_events" }).split("{ep}").join(""),
        h("div", { style: { marginTop: "8px" } }, [
          h("code", { text: "GET /api/v1/traffic?key=&from=&to=&step=" })
        ])
      ])])
    ]);

    /* probe persisted history once; render a real chart if available, else the stub */
    var st = ctx.state.traffic;
    var topHost = ctx.hosts.slice().sort(function (x, y) { return y.rates.pps - x.rates.pps; })[0];
    if (topHost) ctx.actions.loadTraffic(topHost.target);
    var historyBlock;
    if (st.available && st.points.length) {
      var hvals = st.points.map(function (p) { return p.mbps; });
      historyBlock = h("div", { class: "card mt-6" }, [
        h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("history"), h("span", { text: I.t("tr.history.title") })]), K.badge("badge--accent", st.key)]),
        h("div", { class: "card__body" }, h("div", { class: "tcard__chart", style: { height: "200px" } }, K.areaChart(hvals, { color: "var(--chart-in)", height: 200 })))
      ]);
    } else {
      historyBlock = h("div", { class: "mt-6" }, ext);
    }

    K.mount(root, [
      V.viewHead(I.t("nav.traffic"), I.t("tr.window", { n: b.aggIn.length })),
      h("div", { class: "card" }, [
        h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("activity"), h("span", { text: I.t("tr.aggregate.mbps") })]), K.badge("badge--calm", I.t("tr.live"), "dot")]),
        h("div", { class: "card__body" }, h("div", { class: "cols-2" }, [bigIn, bigOut]))
      ]),
      h("div", { class: "card mt-4" }, [
        h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("activity"), h("span", { text: I.t("tr.aggregate.pps") })]), K.badge("badge--calm", I.t("tr.live"), "dot")]),
        h("div", { class: "card__body" }, h("div", { class: "cols-2" }, [bigInPps, bigOutPps]))
      ]),
      h("div", { class: "card mt-4" }, [
        h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("server"), h("span", { text: I.t("tr.perhost.mbps") })])),
        h("div", { class: "card__body" }, h("div", { class: "cols-3" }, hostCardsMbps))
      ]),
      h("div", { class: "card mt-4" }, [
        h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("server"), h("span", { text: I.t("tr.perhost.pps") })])),
        h("div", { class: "card__body" }, h("div", { class: "cols-3" }, hostCards))
      ]),
      historyBlock
    ]);
  }
  /* The placeholder's shape is drawn ONCE, not per render: every view here is
     re-rendered on the 3s poll, and re-rolling the noise each time made the
     ghost twitch as if it were live data. */
  var GHOST_PTS = (function () {
    var pts = []; for (var i = 0; i < 40; i++) pts.push(40 + Math.sin(i / 3) * 18 + Math.random() * 14);
    return pts;
  })();
  function ghostChart() {
    var c = K.areaChart(GHOST_PTS, { color: "var(--muted)", height: 200 });
    c.style.width = "100%"; c.style.height = "100%";
    return c;
  }

  /* ===== SETTINGS ===== */
  function settings(root, ctx) {
    var s = ctx.status;
    var statusCard = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("activity"), h("span", { text: I.t("se.status") })])),
      h("div", { class: "card__body" }, h("dl", { class: "kv" }, [
        h("dt", { text: I.t("se.mode") }), h("dd", {}, K.modeBadge(s.dry_run)),
        h("dt", { text: I.t("se.uptime") }), h("dd", { class: "mono", text: I.duration(s.uptime_seconds) }),
        h("dt", { text: I.t("se.version") }), h("dd", { class: "mono", text: s.version || I.t("common.na") })
      ]))
    ]);

    var netCard = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("globe"), h("span", { text: I.t("se.networks") })]), K.badge("badge--muted", I.t("se.adminonly"), "lock")]),
      h("div", { class: "card__body" }, h("div", { class: "row wrap" }, ctx.networks.map(function (n) { return K.badge("badge--accent", n); })))
    ]);

    var thr = s.thresholds || {};
    var thrCard = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("sliders"), h("span", { text: I.t("se.thresholds") })]), K.badge("badge--muted", I.t("se.adminonly"), "lock")]),
      h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
        h("thead", {}, h("tr", {}, [V.th("col.metric"), V.thNum("col.value")])),
        h("tbody", {}, Object.keys(thr).map(function (k) {
          return h("tr", {}, [h("td", {}, [h("span", { text: I.label("metric", k) }), h("span", { class: "mono td-muted", text: "  " + k })]), h("td", { class: "num", text: I.abbr(thr[k]) })]);
        }))
      ]))
    ]);

    var bgp = s.bgp, scrub = s.scrubbing || {}, notif = s.notify || {};
    var bgpBody;
    if (bgp) {
      var notifOn = Object.keys(notif).filter(function (k) { return notif[k]; });
      var rows = [
        [h("dt", { text: I.t("se.routerid") }), h("dd", { class: "mono", text: bgp.router_id || I.t("common.na") })],
        [h("dt", { text: I.t("se.localasn") }), h("dd", { class: "mono", text: bgp.local_asn != null ? String(bgp.local_asn) : I.t("common.na") })],
        [h("dt", { text: I.t("hg.nexthop") }), h("dd", { class: "mono", text: bgp.next_hop || I.t("common.na") })],
        [h("dt", { text: I.t("hg.community") }), h("dd", { class: "mono", text: bgp.community || I.t("common.na") })],
        [h("dt", { text: I.t("hg.localpref") }), h("dd", { class: "mono", text: bgp.local_pref ? String(bgp.local_pref) : I.t("common.na") })],
        [h("dt", { text: I.t("hg.scrub") }), h("dd", { class: "mono", text: scrub.next_hop || I.t("common.na") })],
        [h("dt", { text: I.t("se.neighbors") }), h("dd", { class: "mono", text: (bgp.neighbors && bgp.neighbors.length) ? bgp.neighbors.join(", ") : I.t("common.none") })],
        [h("dt", { text: I.t("se.notify") }), h("dd", { class: "row wrap", style: { gap: "6px" } }, notifOn.length ? notifOn.map(function (k) { return K.badge("badge--muted", k.charAt(0).toUpperCase() + k.slice(1)); }) : h("span", { class: "td-muted", text: I.t("common.none") }))]
      ];
      bgpBody = h("div", { class: "card__body" }, h("dl", { class: "kv" }, [].concat.apply([], rows)));
    } else {
      bgpBody = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("se.adminonly") }));
    }
    var bgpCard = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("shield"), h("span", { text: I.t("se.bgp") })]), K.badge("badge--muted", I.t("se.adminonly"), "lock")]),
      bgpBody
    ]);

    var dpCard = dataplaneCard(s);

    var reloadCard = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("refresh"), h("span", { text: I.t("se.reload.title") })]), ctx.role === "operator" ? K.badge("badge--accent", I.t("op.only"), "lock") : null]),
      h("div", { class: "card__body row between wrap" }, [
        h("p", { class: "td-muted", style: { maxWidth: "60ch" }, text: I.t("se.reload.desc") }),
        ctx.role === "operator"
          ? h("button", { class: "btn btn--primary", onclick: function (e) { ctx.actions.reload(e.currentTarget); } }, [w.icon("refresh"), h("span", { text: I.t("btn.reload") })])
          : K.badge("badge--muted", I.t("op.only"), "lock")
      ])
    ]);

    K.mount(root, [
      V.viewHead(I.t("nav.settings"), null),
      h("div", { class: "banner banner--info" }, [w.icon("lock"), h("span", { class: "banner__txt", text: I.t("se.readonly") })]),
      h("div", { class: "cols-2" }, [statusCard, netCard]),
      h("div", { class: "cols-2 mt-4" }, [thrCard, bgpCard]),
      h("div", { class: "mt-4" }, dpCard),
      h("div", { class: "mt-4" }, reloadCard)
    ]);
  }

  /* The XDP data plane card.
     THREE STATES, and conflating any two of them would mislead:
       - the block is admin-only (it names interfaces, which is topology), so a
         scoped token gets `dataplane: null` and is told that, not that the data
         plane is off;
       - `enabled: false` means this box does no in-kernel filtering at all;
       - enabled but DEGRADED means the program is loaded and at least one
         configured NIC is not filtering — traffic on it is not being inspected,
         which looks identical to "protected" unless it is said out loud.
     The dry_run row reads back what the DATAPATH is doing (kapkan_cfg), not what
     the config asked for: the two can disagree across an adoption, and that
     disagreement is the reason the field is reported separately. */
  function dataplaneCard(s) {
    var dp = s.dataplane;
    var head = h("div", { class: "card__head" }, [
      h("div", { class: "card__title" }, [w.icon("chip"), h("span", { text: I.t("se.dp") })]),
      K.badge("badge--muted", I.t("se.adminonly"), "lock")
    ]);
    if (!dp) {
      return h("div", { class: "card" }, [head,
        h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("se.adminonly") }))]);
    }
    if (!dp.enabled) {
      return h("div", { class: "card" }, [head,
        h("div", { class: "card__body" }, K.empty("chip", I.t("se.dp.off"), I.t("se.dp.off.sub")))]);
    }

    var state = dp.degraded
      ? K.badge("badge--active", I.t("se.dp.degraded"), "shield-alert")
      : K.badge("badge--calm", I.t("se.dp.ok"), "shield-check");
    var rows = [
      [h("dt", { text: I.t("se.dp.state") }), h("dd", { class: "row wrap", style: { gap: "6px" } }, [
        state,
        K.badge(dp.dry_run ? "badge--dry" : "badge--calm",
          dp.dry_run ? I.t("mode.dryrun") : I.t("mode.live"),
          dp.dry_run ? "shield-alert" : "shield-check"),
        dp.adopted ? K.badge("badge--muted", I.t("se.dp.adopted"), "history") : null
      ])],
      [h("dt", { text: I.t("se.dp.attached") }),
        h("dd", { class: "mono", text: I.num(dp.attached || 0) + " / " + I.num(dp.configured || 0) +
          (dp.mode ? "  " + dp.mode : "") })],
      [h("dt", { text: I.t("se.dp.interfaces") }), h("dd", { class: "row wrap", style: { gap: "6px" } },
        (dp.interfaces || []).length
          ? dp.interfaces.map(function (i) {
              return K.badge(i.attached ? "badge--calm" : "badge--elev",
                i.interface + (i.mode ? " · " + i.mode : ""),
                i.attached ? "shield-check" : "shield-alert",
                i.attached ? "" : (i.last_error || ""));
            })
          : h("span", { class: "td-muted", text: I.t("common.none") }))],
      [h("dt", { text: I.t("se.dp.rules") }),
        h("dd", { class: "mono", text: I.num(dp.static_rules || 0) + " + " + I.num(dp.dynamic_rules || 0) })],
      [h("dt", { text: I.t("se.dp.generation") }), h("dd", { class: "mono", text: String(dp.generation || 0) })],
      [h("dt", { text: I.t("se.dp.maps") }), h("dd", { class: "mono", text: K.bytesFmt(dp.map_bytes) })]
    ];
    var body = [h("dl", { class: "kv" }, [].concat.apply([], rows))];

    /* The filter-bypass alarm, ABOVE the counters it is derived from. The
       overview already carries a page-level banner for this; repeating it here
       is deliberate rather than redundant, because this card is where an
       operator lands when they go looking at the data plane, and the counter it
       comes from is three lines below. Seeing the raw pass_exthdr_cap number
       without the sentence that says "no rule was evaluated" is exactly the
       misreading this whole treatment exists to prevent. */
    var bypassPkts = (dp.verdicts && dp.verdicts["pass_exthdr_cap"] &&
      dp.verdicts["pass_exthdr_cap"].packets) || 0;
    if (bypassPkts) {
      body.push(h("div", { class: "banner banner--dry-loud mt-4", attrs: { role: "alert" } }, [
        w.icon("shield-alert"),
        h("span", { class: "banner__txt", text: I.t("dp.bypass.card", { n: I.abbr(bypassPkts) }) })
      ]));
    }

    // Verdict counters, biggest first, zeros dropped: a table of twenty-one
    // names of which two are non-zero buries the two.
    var vs = dp.verdicts || {};
    var names = Object.keys(vs).filter(function (k) { return (vs[k].packets || 0) > 0; })
      .sort(function (a, b) { return (vs[b].packets || 0) - (vs[a].packets || 0); });
    if (names.length) {
      body.push(h("div", { class: "section-label mt-4" }, [w.icon("activity"), h("span", { text: I.t("se.dp.verdicts") })]));
      body.push(h("div", { class: "row wrap", style: { gap: "6px" } }, names.map(function (k) {
        /* pass_exthdr_cap is not a parser statistic like its neighbours: it
           counts packets that skipped the rule scan entirely. Colouring it like
           the other twenty would be the console agreeing that it is one of
           them. */
        var bypass = k === "pass_exthdr_cap";
        return K.badge(bypass ? "badge--active" : "badge--muted",
          k + " · " + I.abbr(vs[k].packets || 0),
          bypass ? "shield-alert" : "",
          bypass ? I.t("dp.bypass.tip") : "");
      })));
    }
    if (dp.error) {
      body.push(h("p", { class: "td-muted mt-4", text: I.t("se.dp.readerr", { t: dp.error }) }));
    }
    (dp.conditions || []).forEach(function (c) {
      body.push(h("p", { class: "td-muted", text: c.message }));
    });
    return h("div", { class: "card" }, [head, h("div", { class: "card__body" }, body)]);
  }

  /* ===== SCRUBBING NODES =====
     One row per managed node. Two provenances on one row, deliberately kept
     visually apart: liveness, ban count and config come from the BRAIN (the
     rules poll is the only liveness signal); load, drops, version and the
     node-side dry-run flag are the node's own CLAIMS from its advisory report
     — trustworthy for display, never for decisions, and labeled as reported. */
  function nodeStatusBadge(n) {
    if (n.alive) return K.badge("badge--calm", I.t(n.holding ? "nd.polling" : "nd.up"), "shield-check");
    if (n.last_seen) return K.badge("badge--active", I.t("nd.lost"), "shield-alert");
    return K.badge("badge--muted", I.t("nd.never"), "clock");
  }
  /* load bar: reported Mbps against configured capacity. CSSOM width only —
     this console runs under style-src 'self', so setAttribute("style") would
     be silently discarded and every bar would render full. */
  function nodeLoadCell(n) {
    var rep = n.report;
    if (!rep) return h("span", { class: "td-muted", text: I.t("nd.noreport") });
    /* absent-but-reported is a ZERO claim, not an unknown: load_mbps rides the
       report with omitempty, so a standby node's honest 0 arrives keyless —
       same convention as the drops column's `|| 0` */
    var load = rep.load_mbps || 0;
    var txt = I.mbps(load);
    if (!n.capacity_mbps) return h("span", { class: "mono", text: txt });
    var frac = Math.max(0, Math.min(1, load / n.capacity_mbps));
    var bar = h("i");
    bar.style.width = Math.max(2, frac * 100) + "%";
    return h("div", { class: "share", title: I.t("nd.load.title", { c: I.mbps(n.capacity_mbps) }) }, [
      h("span", { class: "share__pct mono", text: txt }),
      h("span", { class: "share__bar" + (frac >= 0.8 ? " is-dom" : "") }, bar)
    ]);
  }
  function nodes(root, ctx) {
    ctx.actions.loadNodes();
    var st = ctx.state.nodes;
    var children = [V.viewHead(I.t("nav.nodes"), I.t("nd.sub"))];

    if (!ctx.status.nodes_total) {
      children.push(h("div", { class: "card" }, K.empty("divert", I.t("nd.empty.title"), I.t("nd.empty.sub"), "muted")));
    } else if (st.forbidden) {
      children.push(h("div", { class: "banner banner--info" }, [w.icon("lock"), h("span", { class: "banner__txt", text: I.t("nd.adminonly") })]));
    } else if (!st.fetchedAt) {
      children.push(h("div", { class: "card" }, h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("nd.loading") }))));
    } else if (!st.ok) {
      /* a FAILED fetch is an error state, never an empty fleet: /status says
         nodes exist, so a bare table claiming zero would be a false count at
         exactly the moment (an incident) someone opens this view */
      children.push(h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
        w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("nd.error") })]));
    } else {
      var rows = st.list.map(function (n) {
        var rep = n.report;
        return h("tr", {}, [
          h("td", { class: "target-cell" }, [
            h("div", { class: "mono", text: n.name }),
            h("div", { class: "td-muted", text: n.next_hop + (n.next_hop6 ? " · " + n.next_hop6 : "") })
          ]),
          h("td", {}, nodeStatusBadge(n)),
          h("td", {}, nodeLoadCell(n)),
          h("td", { class: "num" }, rep
            ? h("span", { class: "mono", text: I.abbr(rep.dropped_packets || 0) })
            : h("span", { class: "td-muted", text: "—" })),
          h("td", { class: "num mono", text: I.num(n.active_bans || 0) }),
          /* dry_run rides the report with omitempty: absent-but-reported IS the
             "not watch-only" claim, so a report without the key renders Live —
             only a node with no report at all gets the unknown dash */
          h("td", {}, rep
            ? K.badge(rep.dry_run ? "badge--dry" : "badge--calm", rep.dry_run ? I.t("mode.dryrun") : I.t("mode.live"))
            : h("span", { class: "td-muted", text: "—" })),
          h("td", { class: "td-muted" }, rep ? [
            h("div", { class: "mono", text: (rep.version || "—") + (rep.xdp_mode ? " · " + rep.xdp_mode : "") }),
            n.reported_at ? h("div", { text: I.rel(new Date(n.reported_at)) }) : null
          ] : h("span", { text: "—" })),
          h("td", { class: "td-muted", text: n.last_seen ? I.rel(new Date(n.last_seen)) : I.t("nd.never") }),
          h("td", {}, (n.hostgroups || []).length
            ? h("span", { class: "row wrap", style: { gap: "4px" } }, n.hostgroups.map(function (g) { return K.badge("badge--muted", g); }))
            : h("span", { class: "td-muted", text: I.t("nd.anygroup") }))
        ]);
      });
      children.push(h("div", { class: "card" }, [
        h("div", { class: "card__head" }, [
          h("div", { class: "card__title" }, [w.icon("divert"), h("span", { text: I.t("nd.list") }), K.badge("badge--muted", String(st.total))]),
          h("span", { class: "td-muted", text: I.t("nd.note", { t: st.staleAfter }) })
        ]),
        h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
          h("thead", {}, h("tr", {}, [V.th("col.node"), V.th("col.state"), V.th("nd.load"), V.thNum("nd.dropped"),
            V.thNum("counter.bans"), V.th("nd.mode"), V.th("nd.agent"), V.th("nd.lastseen"), V.th("nav.hostgroups")])),
          h("tbody", {}, rows)
        ]))
      ]));
      children.push(h("div", { class: "banner banner--info mt-4" }, [w.icon("info"), h("span", { class: "banner__txt", text: I.t("nd.reportnote") })]));
    }
    K.mount(root, children);
  }

  /* ===== EDGE (E4.5): the edge nodes' zones, merged, and who would be
     challenged. Read-only; the lever (E4.6) comes later. ===== */
  /* The challenge column reads the zone's MODE first, then where it bites —
     from STATE, never from a window's counters: off — nothing challenges;
     manual — everyone without a clearance is challenged; auto — the ladder is
     armed. Either is a preview on the nodes rung_watch_only names (the node's
     dry_run, the zone's, or the rung's own challenge_options.dry_run) and
     bites on the rest; a zone-wide flip shows as active on the nodes where it
     bites, as a preview where it only counts. */
  function edgeChallengeCell(z) {
    var active = z.challenge_active || [];
    var nodes = z.nodes || 0, rungWatch = (z.rung_watch_only || []).length, biting = Math.max(0, nodes - rungWatch);
    var previewWhy = "";
    if (active.length) {
      var reasons = {}, bite = 0;
      active.forEach(function (c) { reasons[c.reason || "manual"] = true; if (!c.dry_run) bite++; });
      var why = " · " + Object.keys(reasons).sort().join(", ");
      if (bite > 0) return K.badge("badge--active", I.plural(bite, "edgeActiveOnNodes") + why, "shield-alert");
      /* every flip previews: said beside the mode, never INSTEAD of a rung
         that bites on other nodes — fall through with the reasons */
      previewWhy = why;
    }
    if (z.challenge === "manual" || z.challenge === "auto") {
      if (biting === 0) return K.badge("badge--dry", I.t("ed.challenge.preview") + previewWhy);
      var label = I.t(z.challenge === "manual" ? "ed.challenge.manual" : "ed.challenge.auto");
      if (rungWatch > 0) label += " · " + I.plural(biting, "edgeBitingNodes");
      if (previewWhy) label += " · " + I.t("ed.challenge.preview") + previewWhy;
      return K.badge(z.challenge === "manual" ? "badge--active" : "badge--muted", label);
    }
    if (previewWhy) return K.badge("badge--dry", I.t("ed.challenge.preview") + previewWhy);
    return h("span", { class: "td-muted", text: I.t("ed.challenge.off") });
  }
  /* The HTTP/3 column reads the zone's h3 STATE, never a window's counters.
     No h3 object at all — nobody asks and nobody speaks it (an older brain
     sends no such field either): off. Asked for and served by every node that
     reports the zone: on, with the share of the last window that arrived over
     HTTP/3. Asked for where a node cannot serve it: the preview look, because
     the zone is only partly on — the tooltip names each such node, why (its
     terminator.h3 state) and any advisory its probe raised, all from the
     node's OWN report in the inventory. Switched off in the file while a node
     still holds a QUIC listener: off, saying so — the file and the fleet
     disagree, and hiding that would read as a finished switch-off. */
  var h3States = { ready: 1, no_module: 1, node_off: 1, unknown: 1 };
  function edgeH3Report(inv, name) {
    for (var i = 0; i < inv.length; i++) {
      if (inv[i].name === name) {
        var rep = inv[i].report;
        return (rep && rep.terminator && rep.terminator.h3) || null;
      }
    }
    return null;
  }
  /* one tooltip line per node: its name, and — when the inventory carries its
     report — the state that explains it plus any advisory. A node the
     inventory does not cover is named alone rather than guessed about. */
  function edgeH3Why(inv, names) {
    return names.map(function (name) {
      var h3 = edgeH3Report(inv, name);
      if (!h3 || !h3.state) return name;
      var line = name + " — " + (h3States[h3.state] ? I.t("ed.h3.state." + h3.state) : h3.state);
      return h3.advisory ? line + " · " + h3.advisory : line;
    }).join("\n");
  }
  function edgeH3Cell(z, inv) {
    var h3 = z.h3;
    if (!h3) return h("span", { class: "td-muted", text: I.t("ed.h3.off") });
    var serving = (h3.serving || []).length, unsup = (h3.unsupported || []).length;
    /* the nodes reporting the zone is the denominator; never below the nodes
       h3 itself names, so the fraction cannot read as more than the whole */
    var nodes = Math.max(z.nodes || 0, serving + unsup);
    if (!h3.enabled) {
      if (serving === 0) return h("span", { class: "td-muted", text: I.t("ed.h3.off") });
      return K.badge("badge--elev", I.t("ed.h3.off") + " · " + I.plural(serving, "edgeH3StillServing"), null,
        I.t("ed.h3.tip.offserving") + "\n" + edgeH3Why(inv, h3.serving));
    }
    if (unsup === 0 && serving >= nodes) {
      var label = I.t("ed.h3.on"), tip = nodes > 0 ? I.t("ed.h3.tip.on") : null;
      if (z.requests > 0) {
        var share = I.pct((h3.requests || 0) / z.requests);
        label += " · " + share;
        tip = I.t("ed.h3.tip.share", { p: share });
      }
      if (nodes > 0) label += " · " + I.num(serving) + "/" + I.num(nodes);
      return K.badge("badge--calm", label, null, tip);
    }
    /* the header names a list, so it is said only when there IS one; a node
       reporting the zone that named neither list said nothing about HTTP/3 at
       all — it predates the report that carries it */
    var why = [];
    if (unsup > 0) why.push(I.t("ed.h3.tip.partial"), edgeH3Why(inv, h3.unsupported));
    if (serving + unsup < nodes) why.push(I.t("ed.h3.tip.silent"));
    return K.badge("badge--dry", I.t("ed.h3.on") + " · " + I.plural(serving, "edgeH3ReadyNodes", { n: I.num(nodes) }), null, why.join("\n"));
  }
  /* ===== EDGE: one zone's STORED history (E6.7) =====
     The live table above is one ten-second window; this is the same zone over
     an hour, a day or a week, read from ClickHouse. */

  /* The state badge for a source, shared by the live would-be table and the
     history's sources table so one source cannot read differently in the two.
     A lookup with a muted fallback, not a ternary: the four states below are
     the ones the brain stores, and a newer kapkan that stores a fifth must
     render it as an unknown badge rather than as one of these. */
  var SOURCE_STATE_BADGE = {
    "denied": "badge--active",
    "challenged": "badge--elev",
    "would-deny": "badge--dry",
    "would-challenge": "badge--muted"
  };
  function edgeStateBadge(state) {
    return K.badge(SOURCE_STATE_BADGE[state] || "badge--muted", I.t("ed.state." + state));
  }

  /* ClickHouse hands back "2026-09-10 15:04:05" — UTC, with no zone marker.
     `new Date()` reads that shape as LOCAL time, which would shift every
     timestamp in this card by the operator's offset, so the marker is added
     before parsing. A value that already carries one (an ISO string from a
     newer engine) is parsed as it stands. */
  function edgeTime(s) {
    if (!s) return null;
    var str = String(s);
    if (!/([Zz]|[+-]\d\d:?\d\d)$/.test(str)) str = str.replace(" ", "T") + "Z";
    var d = new Date(str);
    return isNaN(d.getTime()) ? null : d;
  }
  function edgeTimeCell(s) {
    var d = edgeTime(s);
    return h("td", { class: "td-muted", text: d ? I.datetime(d) : "—" });
  }

  /* The three ids of the range switch. app.js owns what each means in seconds
     and in bucket width; an id it does not know falls back to the hour. */
  var HIST_RANGES = ["1h", "24h", "7d"];

  /* The storage-off ghost, the Traffic view's own treatment: `available:
     false` is not an empty period and not an error — the engine never looked,
     so the honest answer is the panel that says how to make it look. */
  function edgeGhost(titleKey, subKey) {
    return h("div", { class: "ext-point" }, [
      h("span", { class: "ext-point__badge" }, K.badge("badge--elev", I.t("tr.history.endpoint"), "history")),
      h("div", { class: "section-label", style: { fontSize: "var(--t-md)", color: "var(--text)" } },
        [w.icon("chart"), h("span", { text: I.t(titleKey) })]),
      h("p", { class: "td-muted", style: { maxWidth: "72ch", marginBottom: "var(--s-4)" }, text: I.t(subKey) }),
      h("div", { class: "ext-ghost" }, ghostChart())
    ]);
  }

  /* `head` is the one number in the chart's own unit. It is deliberately NOT
     the period's total: the totals are in the stats row below, and repeating
     one of them beside a per-second axis read as "the rate is 46.4k". */
  function histChart(labelKey, values, head, color, tag) {
    return h("div", { class: "tcard" }, [
      h("div", { class: "tcard__head" }, [
        h("div", { class: "tcard__label" }, [
          (function () { var d = h("span", { class: "tcard__dir" }); d.style.background = color; return d; })(),
          h("span", { text: I.t(labelKey) }),
          tag || null
        ]),
        h("div", { class: "tcard__now", text: head })
      ]),
      h("div", { class: "tcard__chart", style: { height: "150px" } },
        K.areaChart(values.length ? values : [0, 0], { color: color, height: 150 }))
    ]);
  }

  /* The row the card was opened from, so focus can be put back on it when the
     card that took it goes away. CSS.escape because a zone name is whatever
     the zones file says it is. */
  function edgeZoneRow(root, zone) {
    return root.querySelector('tr[data-edge-zone="' + CSS.escape(zone) + '"]');
  }

  /* The card under the zones table. `z` is the zone's live row when it still
     has one — it is what knows whether the rung bites anywhere — and may be
     absent if a reload dropped the zone while the card was open, in which case
     the counters are labelled without that claim rather than with a guess. */
  function edgeHistoryCard(root, ctx, zone, z) {
    var st = ctx.state.edgeHist;
    var body;
    var nodes = (z && z.nodes) || 0, rungWatch = (z && (z.rung_watch_only || []).length) || 0;
    /* The rung previewing on every node NOW says nothing about the hour, day
       or week behind it: a rung switched to watch-only an hour ago leaves real
       denials in the period it was still biting for. So the live state only
       gets to title the series "would be refused" when the period ALSO holds
       no real refusal — the buckets carry their own denied/challenged and are
       asked below. With a zone nobody reports (nodes: 0) there is no live
       claim to make at all. */
    var liveWatchOnly = nodes > 0 && rungWatch >= nodes;

    if (st.forbidden) return null;              /* another tenant's zone: nothing to say */
    if (st.notFound) {
      body = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.hist.gone") }));
    } else if (!st.fetchedAt) {
      body = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.hist.loading") }));
    } else if (!st.ok) {
      body = h("div", { class: "card__body" }, h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
        w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.hist.error") })]));
    } else if (!st.available) {
      body = h("div", { class: "card__body" }, edgeGhost("ed.hist.off.title", "ed.hist.off.sub"));
    } else if (!st.points.length) {
      body = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.hist.empty") }));
    } else {
      var rps = [], refused = [], h3 = [];
      var sumReq = 0, sumRefused = 0, sumReal = 0, sumH3 = 0, sumErr = 0, maxNodes = 0, anyH3 = false;
      st.points.forEach(function (p) {
        var req = p.requests || 0;
        /* the API's own formula: requests over the real length of the windows
           that fell in the bucket (they are not aligned across nodes, so this
           is a rate to the nearest window, never an exact one) */
        rps.push(p.window_seconds > 0 ? req / p.window_seconds : 0);
        var real = (p.denied || 0) + (p.challenged || 0);
        var ref = real + (p.would_deny || 0) + (p.would_challenge || 0);
        refused.push(ref);
        if (p.h3_requests) anyH3 = true;
        h3.push(req > 0 ? (p.h3_requests || 0) / req * 100 : 0);
        sumReq += req; sumRefused += ref; sumReal += real; sumH3 += p.h3_requests || 0;
        sumErr += (p.status_4xx || 0) + (p.status_5xx || 0);
        maxNodes = Math.max(maxNodes, p.nodes || 0);
      });
      /* "Would be refused" is a claim about the whole series, so it is made
         only when the period bears it out; the preview tag is a claim about
         NOW and rides on the live state either way. */
      var watchOnly = liveWatchOnly && sumReal === 0;
      var refusedKey = watchOnly ? "ed.hist.wouldbe" : "ed.hist.refused";
      var peak = function (vals) { return I.t("ac.peak") + " " + I.abbr(Math.max.apply(null, vals)); };
      var charts = [
        histChart("ed.hist.rps", rps, peak(rps), "var(--chart-in)", null),
        histChart(refusedKey, refused, peak(refused), watchOnly ? "var(--elev)" : "var(--active)",
          liveWatchOnly ? K.badge("badge--dry", I.t("ed.challenge.preview")) : null)
      ];
      /* the HTTP/3 line is drawn only where there is HTTP/3 to draw: a flat
         zero line under a zone nobody reaches over QUIC would read as a
         measurement of nothing */
      if (anyH3) {
        charts.push(histChart("ed.hist.h3", h3, I.pct(sumReq > 0 ? sumH3 / sumReq : 0), "var(--chart-out)", null));
      }
      var stats = [
        [I.t("ed.hist.nodes"), I.num(maxNodes)],
        [I.t("ed.requests"), I.num(sumReq)],
        [I.t(refusedKey), I.num(sumRefused)],
        [I.t("ed.hist.errors"), I.num(sumErr)],
        [I.t("ed.hist.bucket"), I.duration(st.stepSeconds)]
      ];
      body = h("div", { class: "card__body" }, [
        h("div", { class: "hist-charts" }, charts),
        h("div", { class: "hist-stats" }, stats.map(function (s) {
          return h("div", { class: "hist-stat" }, [
            h("div", { class: "hist-stat__lbl", text: s[0] }),
            h("div", { class: "hist-stat__val mono", text: s[1] })
          ]);
        }))
      ]);
    }

    var seg = h("div", { class: "seg" }, HIST_RANGES.map(function (r) {
      return h("button", { class: "seg__btn" + (st.range === r ? " is-on" : ""), text: I.t("ed.hist.range." + r),
        onclick: function () { ctx.actions.setEdgeHistRange(r); } });
    }));
    return h("div", { class: "card mt-4" }, [
      h("div", { class: "card__head" }, [
        h("div", { class: "card__title" }, [w.icon("history"), h("span", { text: I.t("ed.hist.title") }), K.badge("badge--accent", zone)]),
        h("div", { class: "row", style: { gap: "var(--s-2)" } }, [
          seg,
          /* closing removes this button with the card, so the keyboard would
             land on <body>; focus goes back to the row the card belongs to,
             the drawer's own return-focus treatment */
          h("button", { class: "btn btn--ghost btn--sm", onclick: function () {
            ctx.actions.toggleEdgeZone(zone);
            var row = edgeZoneRow(root, zone);
            if (row) row.focus();
          } }, [w.icon("x"), h("span", { text: I.t("ed.hist.close") })])
        ])
      ]),
      body
    ]);
  }

  /* "Who would have been challenged — over {period}": the same question the
     live table asks of one window, asked of the whole period. */
  function edgeHistorySourcesCard(ctx, zone) {
    var st = ctx.state.edgeHist;
    if (st.forbidden || st.notFound) return null;
    /* the charts' own card carries the loading state, the storage-off ghost
       and the failure of the HISTORY read for the pair, so none of those is
       repeated here. The SOURCES read is this card's alone: the charts have
       nothing to say about it, and a card that simply vanished would read as
       "no source was telling in this period" rather than as a query that
       never answered. */
    if (!st.fetchedAt || !st.ok || !st.available) return null;
    var period = I.t("ed.hist.range." + st.range);
    var head = function (count) {
      return h("div", { class: "card__head" }, [
        h("div", { class: "card__title" }, [w.icon("shield-alert"), h("span", { text: I.t("ed.srcs.title", { t: period }) }),
          count === null ? null : K.badge("badge--muted", String(count))]),
        h("span", { class: "td-muted", text: I.t("ed.srcs.sub") })
      ]);
    };
    if (!st.srcOk) {
      return h("div", { class: "card mt-4" }, [
        head(null),
        h("div", { class: "card__body" }, h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
          w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.srcs.error") })]))
      ]);
    }
    if (!st.srcAvailable) return null;
    var rows = st.sources.map(function (s) {
      return h("tr", {}, [
        h("td", { class: "mono", text: s.source }),
        h("td", {}, edgeStateBadge(s.state)),
        h("td", { class: "num mono", text: I.abbr(s.requests || 0) }),
        h("td", { class: "num mono", text: I.num(s.windows || 0) }),
        h("td", { class: "num mono", text: I.num(s.nodes || 0) }),
        edgeTimeCell(s.first_seen),
        edgeTimeCell(s.last_seen)
      ]);
    });
    return h("div", { class: "card mt-4" }, [
      head(st.sources.length),
      st.sources.length
        ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [V.th("ed.source"), V.th("col.state"), V.thNum("ed.requests"),
              V.thNum("ed.srcs.windows"), V.thNum("ed.nodes"), V.th("ed.srcs.firstseen"), V.th("ed.srcs.lastseen")])),
            h("tbody", {}, rows)
          ]))
        : h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.srcs.empty") }))
    ]);
  }

  /* The fleet's events, last 24 hours. The kinds are an enum so a kapkan
     newer than this console renders its seventeenth kind as its raw name
     (I.label falls back to the key) instead of dropping it. */
  var EVENT_KIND_BADGE = {
    node_alive: "badge--calm", terminator_alive: "badge--calm", generation_installed: "badge--calm",
    cert_issued: "badge--calm", cert_renewed: "badge--calm", challenge_ended: "badge--calm",
    node_lost: "badge--active", generation_refused: "badge--active", cert_gone: "badge--active",
    clock_skew: "badge--active", report_truncated: "badge--elev", challenge_started: "badge--elev",
    dry_run: "badge--dry"
  };
  function edgeEventsCard(ctx) {
    var st = ctx.state.edgeEvents;
    if (st.forbidden) return null;              /* a tenant-scoped token: the events name nodes */
    if (st.absent) return null;                 /* a kapkan without the endpoint: no card, not a fault */
    var body;
    if (!st.fetchedAt) {
      body = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.hist.loading") }));
    } else if (!st.ok) {
      body = h("div", { class: "card__body" }, h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
        w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.ev.error") })]));
    } else if (!st.available) {
      body = h("div", { class: "card__body" }, edgeGhost("ed.hist.off.title", "ed.ev.off.sub"));
    } else if (!st.events.length) {
      body = h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.ev.empty") }));
    } else {
      var rows = st.events.map(function (e) {
        return h("tr", {}, [
          edgeTimeCell(e.event_time),
          h("td", {}, K.badge(EVENT_KIND_BADGE[e.kind] || "badge--muted", I.label("edgeEventKind", e.kind))),
          h("td", { class: "mono", text: e.node || "—" }),
          h("td", { class: "mono td-muted", text: e.zone || "—" }),
          h("td", { class: "td-muted", text: e.detail || "" })
        ]);
      });
      body = h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
        h("thead", {}, h("tr", {}, [V.th("ed.ev.when"), V.th("ed.ev.kind"), V.th("col.node"), V.th("ed.zone"), V.th("ed.ev.detail")])),
        h("tbody", {}, rows)
      ]));
    }
    return h("div", { class: "card mt-6" }, [
      h("div", { class: "card__head" }, [
        h("div", { class: "card__title" }, [w.icon("clock"), h("span", { text: I.t("ed.ev.title") }),
          st.available && st.events.length ? K.badge("badge--muted", String(st.events.length)) : null]),
        h("span", { class: "td-muted", text: I.t("ed.ev.sub") })
      ]),
      body
    ]);
  }

  function edge(root, ctx) {
    ctx.actions.loadEdge();
    var st = ctx.state.edge;
    var children = [V.viewHead(I.t("nav.edge"), I.t("ed.sub"))];

    if (!ctx.status.edge_nodes_total) {
      children.push(h("div", { class: "card" }, K.empty("shield-check", I.t("ed.empty.title"), I.t("ed.empty.sub"), "muted")));
    } else if (st.forbidden) {
      children.push(h("div", { class: "banner banner--info" }, [w.icon("lock"), h("span", { class: "banner__txt", text: I.t("ed.adminonly") })]));
    } else if (!st.fetchedAt) {
      children.push(h("div", { class: "card" }, h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("ed.loading") }))));
    } else if (!st.ok) {
      /* a failed fetch is an error, never "no zones": the status says edge
         nodes exist, so an empty table would be a false claim */
      children.push(h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
        w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.error") })]));
    } else if (!st.zones.length) {
      children.push(h("div", { class: "card" }, K.empty("shield-check", I.t("ed.nozones.title"), I.plural(st.nodesAlive, "edgeNodesUp") + " " + I.t("ed.nozones.sub"), "muted")));
    } else {
      var inv = st.inv || [];
      var openZone = ctx.state.edgeHist.zone;
      var rows = st.zones.map(function (z) {
        var watch = z.watch_only || [];
        var open = openZone === z.zone;
        var toggle = function () { ctx.actions.toggleEdgeZone(z.zone); };
        return h("tr", { class: "is-clickable" + (open ? " is-open" : ""), tabindex: "0", role: "button",
          /* the open row's own click closes the card, so it must not offer to
             open it; aria-expanded is the same fact for a screen reader */
          attrs: { title: I.t(open ? "ed.hist.close" : "ed.hist.open"), "aria-expanded": open ? "true" : "false" },
          dataset: { edgeZone: z.zone },
          onclick: toggle, onkeydown: function (e) { hgKey(e, toggle); } }, [
          h("td", { class: "target-cell" }, [
            h("div", { class: "row", style: { gap: "8px" } },
              [w.icon(open ? "chevron-down" : "chevron-right"), h("span", { class: "mono", text: z.zone })]),
            watch.length ? h("div", { class: "td-muted", text: I.plural(watch.length, "edgeWatchOnlyNodes") }) : null
          ]),
          h("td", { class: "num mono", text: I.num(z.nodes || 0) }),
          h("td", { class: "num mono", text: I.num(Math.round(z.rps || 0)) }),
          h("td", { class: "num mono", text: I.abbr(z.challenged || 0) }),
          h("td", { class: "num mono", text: I.abbr(z.cleared || 0) }),
          h("td", { class: "num mono", text: I.abbr(z.would_challenge || 0) }),
          h("td", { class: "num mono", text: I.abbr(z.would_deny || 0) }),
          h("td", {}, edgeChallengeCell(z)),
          h("td", {}, edgeH3Cell(z, inv))
        ]);
      });
      children.push(h("div", { class: "card" }, [
        h("div", { class: "card__head" }, [
          h("div", { class: "card__title" }, [w.icon("shield-check"), h("span", { text: I.t("ed.zones") }), K.badge("badge--muted", String(st.zones.length))]),
          h("span", { class: "td-muted", text: I.plural(st.nodesReporting, "edgeReportingNodes") })
        ]),
        h("div", { class: "tablewrap" }, h("table", { class: "tbl edge-tbl" }, [
          h("thead", {}, h("tr", {}, [V.th("ed.zone"), V.thNum("ed.nodes"), V.thNum("ed.rps"), V.thNum("ed.challenged"), V.thNum("ed.cleared"),
            V.thNum("ed.wouldchallenge"), V.thNum("ed.woulddeny"), V.th("ed.challenge"), V.th("ed.h3")])),
          h("tbody", {}, rows)
        ]))
      ]));

      /* the stored history of the zone whose row is open, under the table it
         was opened from. The reads are on demand — asked for here, once the
         operator has actually opened a zone, never by the 3s poll. */
      if (openZone) {
        ctx.actions.loadEdgeHistory();
        var openRow = null;
        st.zones.forEach(function (z) { if (z.zone === openZone) openRow = z; });
        children.push(edgeHistoryCard(root, ctx, openZone, openRow));
        children.push(edgeHistorySourcesCard(ctx, openZone));
      }

      /* zone entries the nodes cut from their reports to fit: those zones are
         missing or undercounted above, and the table must not read as whole */
      if (st.zonesTruncated) {
        children.push(h("div", { class: "banner banner--info mt-4" }, [w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.zonestruncated", { n: st.zonesTruncated }) })]));
      }

      /* who would be challenged: the union across nodes, busiest first across
         zones (the caption says so); partial when a node cut part of its
         per-source detail — the aggregator's bound or the report's size */
      var would = [], partial = false;
      st.zones.forEach(function (z) { if (z.partial) partial = true; (z.would_be || []).forEach(function (s) { would.push({ zone: z.zone, s: s }); }); });
      would.sort(function (a, b) { return (b.s.requests || 0) - (a.s.requests || 0) || (a.s.source < b.s.source ? -1 : a.s.source > b.s.source ? 1 : 0); });
      var wouldRows = would.map(function (e) {
        return h("tr", {}, [
          h("td", { class: "mono", text: e.s.source }),
          h("td", { class: "mono td-muted", text: e.zone }),
          h("td", {}, edgeStateBadge(e.s.state)),
          h("td", { class: "num mono", text: I.abbr(e.s.requests || 0) }),
          h("td", {}, h("span", { class: "row wrap", style: { gap: "4px" } }, (e.s.nodes || []).map(function (n) { return K.badge("badge--muted", n); })))
        ]);
      });
      children.push(h("div", { class: "card mt-4" }, [
        h("div", { class: "card__head" }, [
          h("div", { class: "card__title" }, [w.icon("shield-alert"), h("span", { text: I.t("ed.wouldbe.title") }), K.badge("badge--muted", String(would.length)), partial ? K.badge("badge--dry", I.t("ed.wouldbe.partial")) : null]),
          h("span", { class: "td-muted", text: I.t("ed.wouldbe.sub") })
        ]),
        would.length
          ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [V.th("ed.source"), V.th("ed.zone"), V.th("col.state"), V.thNum("ed.requests"), V.th("col.node")])),
            h("tbody", {}, wouldRows)
          ]))
          : h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t(partial ? "ed.wouldbe.shed" : "ed.wouldbe.empty") }))
      ]));
    }

    /* The fleet's events belong to the fleet, not to a zone, so they are shown
       whatever the zone table came back with — as long as there are edge nodes
       at all and the token can see node names. `unscoped` rides on /status for
       every role and long predates the events endpoint, so it says nothing
       about a kapkan older than E6.6; that one answers 404, which the api
       layer reports as absent and this card drops in silence. */
    if (ctx.status.edge_nodes_total && ctx.status.unscoped) {
      ctx.actions.loadEdgeEvents();
      children.push(edgeEventsCard(ctx));
    }
    /* keyboard focus lives on a zone row, and this view re-mounts on every
       poll: keep it where the operator put it, the attacks table's treatment */
    var af = document.activeElement;
    var keepZone = (af && af.getAttribute) ? af.getAttribute("data-edge-zone") : null;
    K.mount(root, children);
    if (keepZone) { var kr = edgeZoneRow(root, keepZone); if (kr) kr.focus(); }
  }

  V.hostgroups = hostgroups;
  V.traffic = traffic;
  V.settings = settings;
  V.attackDetail = attackDetail;
  V.nodes = nodes;
  V.edge = edge;
})(window);
