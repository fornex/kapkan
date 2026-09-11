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
  function ghostChart() {
    var pts = []; for (var i = 0; i < 40; i++) pts.push(40 + Math.sin(i / 3) * 18 + Math.random() * 14);
    var c = K.areaChart(pts, { color: "var(--muted)", height: 200 });
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
  /* The state is a NODE's word and reaches us unfiltered, so the "do we have a
     string for it?" test has to be an own-property one: a report claiming
     `"state": "constructor"` passes a bare `h3States[state]` lookup through
     the prototype chain and the badge then renders the raw catalogue key. Both
     the tooltip and the per-node cell read the state through here, so they can
     never disagree about which readings are known. */
  function edgeH3StateLabel(state) {
    return Object.prototype.hasOwnProperty.call(h3States, state) ? I.t("ed.h3.state." + state) : state;
  }
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
      var line = name + " — " + edgeH3StateLabel(h3.state);
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
  /* ---------- the zones table's E6 cells ----------
     Every field E6 added is OPTIONAL on the wire, and a brain older than it
     sends none of them. Each cell below therefore reads its field defensively
     and falls back to exactly what this table rendered before E6 — the
     regression guard is that an old brain's table is byte-for-byte the one it
     always was. */

  /* The Nodes column answers "how much of this zone's placement is up?", not
     "how many nodes happen to be reporting it". placement (E6.3) is absent
     from an older brain, and the cell then reads as it did: the count of
     alive nodes reporting the zone. A zone whose placement covers NO node
     gets a dash rather than 0/0 — nowhere to serve it is a configuration
     mistake (`-check-config` warns about it), not an outage, and 0/0 in a red
     column would send an operator hunting for a dead box. */
  function edgeNodesCell(z) {
    var pl = z.placement;
    if (!pl || !pl.nodes) return h("td", { class: "num mono", text: I.num(z.nodes || 0) });
    var placed = pl.nodes.length, alive = (pl.alive || []).length;
    /* the operator's topology label, absent for a tenant-scoped token — which
       sees the node names and nothing of how the operator groups them. It is
       shown on the empty placement too, and matters most there: the group
       nobody lists IS the reason the zone is served nowhere. */
    var group = pl.hostgroup ? h("div", { class: "td-muted", text: pl.hostgroup }) : null;
    if (!placed) {
      return h("td", { class: "num" }, [
        h("div", { class: "td-muted", attrs: { title: I.t("ed.nodes.none") }, text: "—" }), group]);
    }
    var kids = [h("div", { class: "mono", attrs: { title: I.t("ed.nodes.title", { t: pl.nodes.join(", ") }) },
      text: I.num(alive) + "/" + I.num(placed) })];
    /* the zone has nodes and none of them is alive: the operator's alarm */
    if (z.unserved) kids.push(K.badge("badge--active", I.t("ed.nodes.unserved"), "shield-alert"));
    kids.push(group);
    return h("td", { class: "num" }, kids);
  }

  /* A row the zones FILE seeded that no alive node reports (E6.2) has no
     window at all: its counters are absent, not zero. A "0" in an rps column
     reads as "measured, and quiet"; a dash reads as "nothing measured", which
     is the only true answer for a zone in mode: none or one whose nodes are
     all down. An older brain rows a zone only when a node reported it, so
     nodes is never 0 there and nothing changes. */
  function edgeNumCell(z, value, fmt) {
    if (!z.nodes) return h("td", { class: "num" }, h("span", { class: "td-muted", text: "—" }));
    return h("td", { class: "num mono", text: fmt(value || 0) });
  }

  /* The challenge column, with the three states a file-seeded row can be in
     BEFORE the rung is worth reading: a proxy-only zone challenges nothing by
     construction, a deciding zone nobody serves applies nothing at all, and a
     deciding zone that IS placed on a live node has simply not been reported
     yet. Saying "off" for any of them would be the console answering a
     question the fleet never got to ask.

     The three are told apart by the PLACEMENT, not by the report count:
     `nodes` counts the alive nodes whose last report mentioned the zone,
     while liveness lives in placement.alive/unserved, so keying "not served
     by any alive node" on `nodes: 0` alone would print it beside a "2/2" in
     the Nodes cell — two cells of one row contradicting each other — for a
     zone whose nodes are up but silent (a fresh start, a report older than
     the window, a zone the node shed under zones_truncated).

     mode and placement are both absent on an older brain: without mode the
     row falls through to the E4.5 cell, and without placement (pre-E6.3) the
     report count is the only liveness the console has and the cell reads as
     it did. */
  function edgeZoneChallenge(z) {
    if (z.mode === "none") return h("span", { class: "td-muted", text: I.t("ed.proxyonly") });
    if (z.mode && !z.nodes) {
      var pl = z.placement;
      if (!pl || !pl.nodes || z.unserved || !pl.nodes.length) {
        return h("span", { class: "td-muted", text: I.t("ed.notserved") });
      }
      return h("span", { class: "td-muted", text: I.t("ed.noreport") });
    }
    return edgeChallengeCell(z);
  }

  /* ---------- tenant filter (E6.2) ----------
     Only an unscoped token is ever told a zone's tenant, so the chips appear
     only when a row carries one: a single-tenant deployment and every scoped
     operator see the view exactly as before. TENANT_NONE stands for the
     unlabelled (house) zones — it holds a '*', which a tenant label may not
     (`[A-Za-z0-9._-]`), so it can never collide with a real one. */
  var TENANT_NONE = "*none*";
  function edgeTenantList(zones) {
    /* a prototype-less set: a tenant is `[A-Za-z0-9._-]`, so "__proto__" is a
       legal label, and on a plain `{}` it would hit the prototype setter,
       record nothing and leave that customer with no chip of their own */
    var seen = Object.create(null), labelled = false, unlabelled = false;
    zones.forEach(function (z) {
      if (z.tenant) { seen[z.tenant] = true; labelled = true; } else unlabelled = true;
    });
    if (!labelled) return null;
    var list = Object.keys(seen).sort();
    if (unlabelled) list.push(TENANT_NONE);
    return list;
  }
  /* The persisted choice is honoured only while it still names something on
     screen. A tenant that has left the file — or one carried over from an
     unscoped session into a scoped token's — would otherwise filter the whole
     table away and read as an empty fleet. It is FORGOTTEN rather than
     masked: a choice merely hidden would re-engage by itself the moment that
     tenant's zones came back, days later, with nothing on screen having said
     so. This decision is made during a render, and clearEdgeTenant
     deliberately does not start another one. */
  function edgeTenantCurrent(ctx, list) {
    var cur = ctx.state.edgeTenant || "";
    if (!cur) return "";
    if (list && list.indexOf(cur) >= 0) return cur;
    ctx.actions.clearEdgeTenant();
    return "";
  }
  function edgeTenantChips(ctx, list, cur) {
    function chip(val, label) {
      return h("button", { class: "seg__btn" + (cur === val ? " is-on" : ""), text: label,
        onclick: function () { ctx.actions.setEdgeTenant(val); } });
    }
    var chips = [chip("", I.t("ed.tenant.all"))];
    list.forEach(function (t) { chips.push(chip(t, t === TENANT_NONE ? I.t("ed.tenant.none") : t)); });
    return h("div", { class: "filters" }, [
      h("span", { class: "row", style: { color: "var(--muted)" } }, [w.icon("layers"), h("span", { class: "td-muted", text: I.t("ed.tenant.filter") })]),
      h("div", { class: "seg seg--wrap" }, chips)
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
      /* the inventory is the Edge NODES view's document, read here for the
         one thing the merged status cannot carry: why a node serves a zone
         over TCP. A 403 or a failed fetch leaves it empty and the HTTP/3
         tooltip falls back to bare node names. */
      var inv = ctx.state.edgeInv.list || [];
      /* the tenant chips narrow the zones table AND the would-be set below,
         so an operator filtering to one customer is not still reading every
         other customer's sources underneath it */
      var tenants = edgeTenantList(st.zones);
      var tenant = edgeTenantCurrent(ctx, tenants);
      var zones = tenant
        ? st.zones.filter(function (z) { return tenant === TENANT_NONE ? !z.tenant : z.tenant === tenant; })
        : st.zones;
      if (tenants) children.push(edgeTenantChips(ctx, tenants, tenant));
      var rows = zones.map(function (z) {
        var watch = z.watch_only || [];
        return h("tr", {}, [
          h("td", { class: "target-cell" }, [
            h("div", { class: "mono", text: z.zone }),
            /* the owner label, for unscoped tokens only — the API omits it
               for a scoped one, whose every row is its own */
            z.tenant ? h("div", { class: "td-muted", text: z.tenant }) : null,
            watch.length ? h("div", { class: "td-muted", text: I.plural(watch.length, "edgeWatchOnlyNodes") }) : null
          ]),
          edgeNodesCell(z),
          edgeNumCell(z, Math.round(z.rps || 0), I.num.bind(I)),
          edgeNumCell(z, z.challenged, I.abbr.bind(I)),
          edgeNumCell(z, z.cleared, I.abbr.bind(I)),
          edgeNumCell(z, z.would_challenge, I.abbr.bind(I)),
          edgeNumCell(z, z.would_deny, I.abbr.bind(I)),
          h("td", {}, edgeZoneChallenge(z)),
          h("td", {}, edgeH3Cell(z, inv))
        ]);
      });
      children.push(h("div", { class: "card" }, [
        h("div", { class: "card__head" }, [
          h("div", { class: "card__title" }, [w.icon("shield-check"), h("span", { text: I.t("ed.zones") }), K.badge("badge--muted", String(zones.length))]),
          h("span", { class: "td-muted", text: I.plural(st.nodesReporting, "edgeReportingNodes") })
        ]),
        h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
          h("thead", {}, h("tr", {}, [V.th("ed.zone"), V.thNum("ed.nodes"), V.thNum("ed.rps"), V.thNum("ed.challenged"), V.thNum("ed.cleared"),
            V.thNum("ed.wouldchallenge"), V.thNum("ed.woulddeny"), V.th("ed.challenge"), V.th("ed.h3")])),
          h("tbody", {}, rows)
        ]))
      ]));

      /* zone entries the nodes cut from their reports to fit: those zones are
         missing or undercounted above, and the table must not read as whole */
      if (st.zonesTruncated) {
        children.push(h("div", { class: "banner banner--info mt-4" }, [w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("ed.zonestruncated", { n: st.zonesTruncated }) })]));
      }

      /* who would be challenged: the union across nodes, busiest first across
         zones (the caption says so); partial when a node cut part of its
         per-source detail — the aggregator's bound or the report's size */
      var would = [], partial = false;
      zones.forEach(function (z) { if (z.partial) partial = true; (z.would_be || []).forEach(function (s) { would.push({ zone: z.zone, s: s }); }); });
      would.sort(function (a, b) { return (b.s.requests || 0) - (a.s.requests || 0) || (a.s.source < b.s.source ? -1 : a.s.source > b.s.source ? 1 : 0); });
      var wouldRows = would.map(function (e) {
        return h("tr", {}, [
          h("td", { class: "mono", text: e.s.source }),
          h("td", { class: "mono td-muted", text: e.zone }),
          h("td", {}, K.badge(e.s.state === "would-deny" ? "badge--dry" : "badge--muted", I.t("ed.state." + e.s.state))),
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
    K.mount(root, children);
  }

  /* ===== EDGE NODES (E6.7): the fleet inventory =====
     One row per CONFIGURED edge node — the scrub Nodes view's shape, and its
     discipline about provenance. Two sources sit on one row and are kept
     apart on purpose:

       the BRAIN's knowledge — liveness (the zones poll is the only liveness
       signal; a self-report never is), the agent tokens bound to the node and
       the placement scope with the count of zones it puts there;

       the NODE's CLAIMS — its kapkan version, the terminator it orchestrates,
       that terminator's HTTP/3 readiness and the certificates it holds. Every
       one of those columns is labelled "(reported)" for the same reason the
       scrub view labels its own: they are trustworthy to display and never to
       decide by.

     Every E6 field is optional on the wire. A brain older than E6.1/E6.3
     sends no tokens, no last_token, no hostgroups and no zones_placed, and
     those cells render a dash rather than an invented answer.

     The whole document is unscoped-only, so a scoped token gets a 403 — which
     is a NOTICE here, not an error: the fleet is not broken, the caller is
     simply not entitled to the topology. */

  /* the docs section the unbound-token banner sends an operator to */
  var DOCS_BINDING = "https://kapkan.io/docs/authentication#binding-an-agent-token-to-its-node";

  function edgeNodeStateBadge(n) {
    if (n.alive) return K.badge("badge--calm", I.t(n.holding ? "nd.polling" : "nd.up"), "shield-check");
    if (n.last_seen) return K.badge("badge--active", I.t("nd.lost"), "shield-alert");
    return K.badge("badge--muted", I.t("nd.never"), "clock");
  }

  /* The tokens cell carries the whole migration story for one node: which
     tokens are bound to it, and which token actually polled last (watch it
     flip as a fleet moves off a shared credential). A node with no token of
     its own WHILE a fleet-wide one exists is the case worth a colour: that
     unbound token may poll and report as this node, and a blank cell would
     read as "nothing to do here". With every token bound the amber never
     appears, so the badge is a migration marker, not permanent decoration. */
  function edgeNodeTokensCell(n, unbound) {
    var toks = n.tokens || [];
    var kids = [];
    if (toks.length) {
      kids.push(h("span", { class: "row wrap", style: { gap: "4px" } },
        toks.map(function (t) { return K.badge("badge--muted", t, "lock"); })));
    } else if (unbound.length) {
      kids.push(K.badge("badge--elev", I.t("en.shared"), "shield-alert", I.t("en.shared.title")));
    } else {
      kids.push(h("span", { class: "td-muted", text: "—" }));
    }
    if (n.last_token) kids.push(h("div", { class: "td-muted", text: I.t("en.lasttoken", { t: n.last_token }) }));
    return h("td", {}, kids);
  }

  /* One certificate as the node reports it: the zone, when it expires, and
     the issuer behind the tooltip. The colour is the expiry alarm edge-spec
     asks for (T−30 d), read off the node's own claim; an unparsable date is
     shown as unknown rather than as an expiry in 1970. */
  var CERTS_SHOWN = 6;
  function edgeCertBadge(c) {
    var when = new Date(c.not_after);
    if (isNaN(when.getTime())) return K.badge("badge--muted", c.zone + " · " + I.t("common.na"));
    var days = (when.getTime() - Date.now()) / 86400000;
    var tone = days <= 7 ? "badge--active" : days <= 30 ? "badge--elev" : "badge--muted";
    var title = c.issuer
      ? I.t("en.cert.title", { i: c.issuer, t: I.datetime(when) })
      : I.t("en.cert.title.noissuer", { t: I.datetime(when) });
    return K.badge(tone, c.zone + " · " + I.rel(when), null, title);
  }
  function edgeNodeCertsCell(rep) {
    if (!rep) return h("td", { class: "td-muted", text: "—" });
    var certs = rep.certs || [];
    if (!certs.length && !rep.certs_truncated) return h("td", {}, h("span", { class: "td-muted", text: I.t("en.nocerts") }));
    var shown = certs.slice(0, CERTS_SHOWN);
    var kids = shown.map(edgeCertBadge);
    if (certs.length > shown.length) {
      kids.push(K.badge("badge--muted", I.t("en.certs.more", { n: I.num(certs.length - shown.length) }), null,
        certs.slice(CERTS_SHOWN).map(function (c) { return c.zone; }).join("\n")));
    }
    /* a list the node CUT to fit the 64 KiB body limit is short, not
       complete: say so, or the row claims the fleet holds fewer certificates
       than it does */
    if (rep.certs_truncated) {
      kids.push(K.badge("badge--dry", I.t("en.certs.cut", { n: I.num(rep.certs_truncated) })));
    }
    return h("td", {}, h("span", { class: "row wrap", style: { gap: "4px" } }, kids));
  }

  /* The node's HTTP/3 readiness, straight from its terminator probe — the
     same four readings the Edge view's zone tooltip explains, said here once
     per node instead of once per zone. Absent from a node that predates the
     probe, and a dash is the honest rendering of that. */
  function edgeNodeH3Cell(rep) {
    var h3 = rep && rep.terminator && rep.terminator.h3;
    if (!h3 || !h3.state) return h("td", { class: "td-muted", text: "—" });
    var label = edgeH3StateLabel(h3.state);
    return h("td", {}, K.badge(h3.state === "ready" ? "badge--calm" : "badge--elev", label, null, h3.advisory || ""));
  }

  function edgeNodeTerminatorCell(rep) {
    var t = rep && rep.terminator;
    if (!t) return h("td", { class: "td-muted", text: "—" });
    return h("td", { class: "td-muted" }, [
      h("div", { class: "mono", text: (t.kind || "—") + (t.version ? " · " + t.version : "") }),
      t.generation ? h("div", { text: I.t("en.generation", { n: I.num(t.generation) }) }) : null
    ]);
  }

  /* An unbound agent token is a fleet-wide credential: it may poll and report
     as ANY node. The brain keeps accepting it (bindings are a migration, not
     a flag day), so nothing else on this page would say so — hence a banner
     that names the tokens and links to the one paragraph that fixes it. */
  function edgeUnboundBanner(unbound) {
    return h("div", { class: "banner banner--dry" }, [
      w.icon("shield-alert"),
      h("span", { class: "banner__txt", text: I.plural(unbound.length, "edgeUnboundTokens", { t: unbound.join(", ") }) }),
      h("a", { class: "btn btn--ghost btn--sm", href: DOCS_BINDING, target: "_blank", rel: "noopener", text: I.t("en.unbound.link") })
    ]);
  }

  function edgeNodes(root, ctx) {
    ctx.actions.loadEdgeInv();
    var st = ctx.state.edgeInv;
    var children = [V.viewHead(I.t("nav.edgenodes"), I.t("en.sub"))];

    if (!ctx.status.edge_nodes_total) {
      children.push(h("div", { class: "card" }, K.empty("globe", I.t("ed.empty.title"), I.t("ed.empty.sub"), "muted")));
    } else if (st.forbidden) {
      /* a scoped token: the notice, never an error — the fleet is fine, the
         inventory is simply topology and stays with unscoped tokens */
      children.push(h("div", { class: "banner banner--info" }, [w.icon("lock"), h("span", { class: "banner__txt", text: I.t("en.adminonly") })]));
    } else if (!st.fetchedAt) {
      children.push(h("div", { class: "card" }, h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("en.loading") }))));
    } else if (!st.ok) {
      /* a FAILED fetch is an error state, never an empty fleet: /status says
         edge nodes exist, so a bare table claiming zero would be a false
         count at exactly the moment someone opens this view */
      children.push(h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
        w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("en.error") })]));
    } else {
      if (st.unbound.length) children.push(edgeUnboundBanner(st.unbound));
      var rows = st.list.map(function (n) {
        var rep = n.report;
        var groups = n.hostgroups || [];
        return h("tr", {}, [
          h("td", { class: "target-cell" }, h("div", { class: "mono", text: n.name })),
          h("td", {}, edgeNodeStateBadge(n)),
          edgeNodeTokensCell(n, st.unbound),
          h("td", {}, groups.length
            ? h("span", { class: "row wrap", style: { gap: "4px" } }, groups.map(function (g) { return K.badge("badge--muted", g); }))
            : h("span", { class: "td-muted", text: "—" })),
          h("td", { class: "num" }, n.zones_placed != null
            ? h("span", { class: "mono", text: I.num(n.zones_placed) })
            : h("span", { class: "td-muted", text: "—" })),
          h("td", { class: "td-muted" }, rep ? [
            h("div", { class: "mono", text: rep.version || "—" }),
            n.reported_at ? h("div", { text: I.rel(new Date(n.reported_at)) }) : null
          ] : h("span", { text: I.t("nd.noreport") })),
          edgeNodeTerminatorCell(rep),
          edgeNodeH3Cell(rep),
          edgeNodeCertsCell(rep),
          h("td", { class: "td-muted", text: n.last_seen ? I.rel(new Date(n.last_seen)) : I.t("nd.never") })
        ]);
      });
      children.push(h("div", { class: "card" }, [
        h("div", { class: "card__head" }, [
          h("div", { class: "card__title" }, [w.icon("globe"), h("span", { text: I.t("en.list") }), K.badge("badge--muted", String(st.total))]),
          h("span", { class: "td-muted", text: I.t("en.note", { t: st.staleAfter }) })
        ]),
        h("div", { class: "tablewrap" }, h("table", { class: "tbl fleet-tbl" }, [
          /* en.h3, not the Edge view's ed.h3: this column is the NODE's claim
             about its own terminator, so it carries the "(reported)" label
             every other claim column on this row carries */
          h("thead", {}, h("tr", {}, [V.th("col.node"), V.th("col.state"), V.th("en.tokens"), V.th("en.scope"),
            V.thNum("en.zones"), V.th("en.version"), V.th("en.terminator"), V.th("en.h3"), V.th("en.certs"), V.th("nd.lastseen")])),
          h("tbody", {}, rows)
        ]))
      ]));
      children.push(h("div", { class: "banner banner--info mt-4" }, [w.icon("info"), h("span", { class: "banner__txt", text: I.t("en.reportnote") })]));
    }
    K.mount(root, children);
  }

  V.hostgroups = hostgroups;
  V.traffic = traffic;
  V.settings = settings;
  V.attackDetail = attackDetail;
  V.nodes = nodes;
  V.edge = edge;
  V.edgenodes = edgeNodes;
})(window);
