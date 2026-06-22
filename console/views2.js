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

      sample ? section("ac.sample", "target", h("div", {}, [
        h("div", { class: "shares" }, [
          K.shareGroup(I.t("ac.topsources"), sample.top_sources, { src: true }),
          (sample.top_asns && sample.top_asns.length) ? K.shareGroup(I.t("ac.topasns"), sample.top_asns, { src: true }) : null,
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
        h("td", {}, K.badge(g.mitigation === "blackhole" ? "badge--active" : g.mitigation === "divert" ? "badge--elev" : "badge--accent", I.label("method", g.mitigation))),
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

    /* top host sparklines from per-host buffer */
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
        h("div", { class: "card__head" }, [h("div", { class: "card__title" }, [w.icon("activity"), h("span", { text: I.t("tr.aggregate") })]), K.badge("badge--calm", I.t("tr.live"), "dot")]),
        h("div", { class: "card__body" }, h("div", { class: "cols-2" }, [bigIn, bigOut]))
      ]),
      h("div", { class: "card mt-4" }, [
        h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("server"), h("span", { text: I.t("tr.perhost") })])),
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
      h("div", { class: "mt-4" }, reloadCard)
    ]);
  }

  V.hostgroups = hostgroups;
  V.traffic = traffic;
  V.settings = settings;
  V.attackDetail = attackDetail;
})(window);
