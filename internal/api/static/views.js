/* views.js — per-screen render functions. Each renders into a view root that
   app.js clears every 3s poll. UI state (filters/sort/expanded/drawer) lives in
   app.js and is passed in via ctx so it survives re-renders. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h;

  /* keyboard activation for click-only rows (Enter / Space) */
  function keyAct(fn) { return function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fn(e); } }; }

  /* ===== shared building blocks ===== */
  function viewHead(title, sub, actions) {
    return h("div", { class: "view-head" }, [
      h("div", {}, [h("h1", { class: "view-head__title", text: title }), sub ? h("div", { class: "view-head__sub", text: sub }) : null]),
      actions ? h("div", { class: "view-head__actions" }, actions) : null
    ]);
  }

  function statCard(opts) {
    var card = h("div", { class: "stat" + (opts.hot ? " is-hot" : "") }, [
      h("div", { class: "stat__top" }, [w.icon(opts.icon), h("span", { text: opts.label })]),
      h("div", { class: "stat__val " + (opts.valClass || ""), text: opts.value }),
      opts.sub ? h("div", { class: "stat__delta" }, [opts.subIcon ? w.icon(opts.subIcon) : null, h("span", { text: opts.sub })]) : null,
      h("div", { class: "stat__spark" }, K.sparkline(opts.spark && opts.spark.length ? opts.spark : [0, 0], { color: opts.sparkColor || "var(--accent)" }))
    ]);
    return card;
  }

  function statsGrid(ctx) {
    var s = ctx.status, b = ctx.buf, attacks = s.active_attacks, bans = s.active_bans;
    return h("div", { class: "stats" }, [
      statCard({ icon: "alert", label: I.t("stat.activeAttacks"), value: I.num(attacks), hot: attacks > 0,
        valClass: attacks > 0 ? "is-hot" : "is-calm", spark: b.attacks, sparkColor: attacks > 0 ? "var(--active)" : "var(--calm)",
        sub: attacks > 0 ? I.plural(attacks, "activeAttacks") : I.t("stat.allzero") }),
      statCard({ icon: "ban", label: I.t("stat.activeBans"), value: I.num(bans), hot: bans > 0,
        valClass: bans > 0 ? "is-hot" : "", spark: b.bans, sparkColor: bans > 0 ? "var(--active)" : "var(--accent)",
        sub: bans > 0 ? I.plural(bans, "activeBans") : I.t("stat.allzero") }),
      statCard({ icon: "server", label: I.t("stat.hostsTracked"), value: I.num(ctx.hosts.length),
        spark: b.hosts, sparkColor: "var(--accent)", sub: I.plural(ctx.hosts.length, "hostsTracked") }),
      statCard({ icon: "shield", label: I.t("stat.networks"), value: I.num(ctx.networks.length),
        spark: b.aggIn, sparkColor: "var(--chart-in)", sub: ctx.networks.join("  ") })
    ]);
  }

  function trafficStrip(ctx) {
    var b = ctx.buf, agg = ctx.agg;
    var markerFrac = null;
    var idx = b.inAttack.indexOf(true);
    if (idx >= 0 && ctx.posture !== "calm") markerFrac = idx / Math.max(1, b.inAttack.length - 1);
    function card(labelKey, dirColor, vals, now, color) {
      return h("div", { class: "tcard" }, [
        h("div", { class: "tcard__head" }, [
          h("div", { class: "tcard__label" }, [(function () { var d = h("span", { class: "tcard__dir" }); d.style.background = dirColor; return d; })(), h("span", { text: I.t(labelKey) })]),
          h("div", { class: "tcard__now" }, [now, " ", h("small", { text: I.t("ov.now") })])
        ]),
        h("div", { class: "tcard__chart" }, K.areaChart(vals.length ? vals : [0, 0], { color: color, markerFrac: markerFrac }))
      ]);
    }
    return h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [
        h("div", { class: "card__title" }, [w.icon("activity"), h("span", { text: I.t("ov.traffic") })]),
        markerFrac != null ? K.badge("badge--active", I.t("ov.attackwindow"), "alert") : null
      ]),
      h("div", { class: "card__body" }, h("div", { class: "traffic-strip" }, [
        card("ov.ingress", "var(--chart-in)", ctx.buf.aggIn, I.mbps(agg.in_mbps), "var(--chart-in)"),
        card("ov.egress", "var(--chart-out)", ctx.buf.aggOut, I.mbps(agg.out_mbps), "var(--chart-out)")
      ]))
    ]);
  }

  /* ===== ATTACK CARD (hero, reused) ===== */
  function attackCard(a, ctx, opts) {
    opts = opts || {};
    var isOut = a.direction === "outgoing";
    var actions = [];
    if (ctx.role === "operator" && a.active) {
      actions.push(h("button", { class: "btn btn--danger btn--sm", onclick: function (e) { ctx.actions.withdraw(e.currentTarget, a.target); } }, [w.icon("x"), h("span", { text: I.t("ac.withdraw") })]));
    }
    var head = h("div", { class: "attack-card__head" }, [
      h("div", { class: "attack-card__id" }, [
        h("div", { class: "attack-card__target" }, [
          h("span", { class: "mono", text: a.scope === "group" ? a.group : a.target }),
          K.dirBadge(a.direction),
          K.badge("badge--active", I.label("attackType", a.classification.type), "flame")
        ]),
        h("div", { class: "attack-card__sub" }, [
          K.badge(a.scope === "group" ? "badge--elev" : "badge--muted", I.label("scope", a.scope)),
          a.scope === "host" ? h("span", { text: I.t("col.group") + ": " + a.group }) : null,
          K.confidence(a.classification.confidence),
          isOut ? K.badge("badge--active", I.label("direction", "outgoing"), "arrow-up") : null
        ])
      ]),
      actions.length ? h("div", { class: "attack-card__actions" }, actions) : null
    ]);

    var ladderBlock = h("div", {}, [
      h("div", { class: "section-label" }, [w.icon("layers"), h("span", { text: I.t("ac.escalation") })]),
      K.ladder(a.escalation, a.escalation_step, { live: a.active, startedMs: new Date(a.started_at).getTime(), compact: opts.compactLadder })
    ]);

    var mitigation = a.method
      ? h("div", {}, [h("div", { class: "section-label" }, [w.icon("shield"), h("span", { text: I.t("ac.mitigation") })]), K.routeDisplay(a, a.dry_run)])
      : h("div", {}, [h("div", { class: "section-label" }, [w.icon("bell"), h("span", { text: I.t("ac.mitigation") })]),
          h("div", { class: "route" }, h("div", { class: "route__line" }, h("span", { class: "route__v", text: I.t("ac.alertonly") })))]);

    var grid = h("div", { class: "attack-card__grid" }, [
      h("div", {}, [h("div", { class: "section-label" }, [w.icon("activity"), h("span", { text: I.t("ac.metricvsthreshold") })]), K.gauge(a.metric, a.rate, a.threshold)]),
      mitigation
    ]);

    var sources = a.sample ? h("div", {}, [
      h("div", { class: "section-label" }, [w.icon("target"), h("span", { text: I.t("ac.topsources") })]),
      h("div", { class: "shares" }, [
        K.shareGroup(I.t("ac.topsources"), a.sample.top_sources, { src: true }),
        K.shareGroup(I.t("ac.topdstports"), a.sample.top_dst_ports, {})
      ])
    ]) : null;

    var detailBtn = h("button", { class: "btn btn--ghost btn--sm", onclick: function () { ctx.actions.openDrawer(a); } }, [w.icon("search"), h("span", { text: I.t("at.viewdetail") })]);

    return h("div", { class: "attack-card" + (isOut ? " is-outgoing" : "") }, [
      head,
      h("div", { class: "attack-card__body" }, [ladderBlock, grid, sources, h("div", { class: "row", style: { justifyContent: "flex-end" } }, detailBtn)])
    ]);
  }

  /* ===== OVERVIEW ===== */
  function overview(root, ctx) {
    var posture = ctx.posture;
    var bannerCls = "posture-banner" + (posture === "attack" ? " is-attack" : posture === "mitigating" ? " is-mitigating" : "");
    var iconName = posture === "calm" ? "shield-check" : "shield-alert";
    var title, sub;
    if (posture === "calm") {
      var firstRun = ctx.hosts.length === 0;
      title = firstRun ? I.t("ov.firstrun.title") : I.t("ov.allclear.title");
      sub = firstRun ? I.t("ov.firstrun.sub") : I.t("ov.allclear.sub");
    } else {
      title = posture === "mitigating" ? I.t("posture.mitigating") : I.t("posture.attack");
      sub = posture === "mitigating" ? I.t("ov.mitigating.sub") : I.t("ov.attack.sub");
    }
    var banner = h("div", { class: bannerCls }, [
      h("div", { class: "posture-banner__icon" }, w.icon(iconName)),
      h("div", {}, [
        h("h2", { class: "posture-banner__title", text: title }),
        h("p", { class: "posture-banner__sub", text: sub })
      ]),
      h("div", { class: "posture-banner__meta" }, [
        K.modeBadge(ctx.status.dry_run),
        h("div", { class: "live__time mono", style: { color: "var(--muted)", fontSize: "var(--t-sm)" }, text: I.t("se.uptime") + " " + I.duration(ctx.status.uptime_seconds) })
      ])
    ]);

    var children = [banner];
    if (ctx.dryRun) children.push(dryRunBanner());

    if (posture !== "calm" && ctx.attacks.active.length) {
      children.push(h("div", { class: "stack" }, ctx.attacks.active.map(function (a) { return attackCard(a, ctx); })));
      children.push(trafficStrip(ctx));
      children.push(statsGrid(ctx));
    } else {
      children.push(statsGrid(ctx));
      children.push(trafficStrip(ctx));
      if (ctx.attacks.recent.length) children.push(recentMini(ctx));
    }
    K.mount(root, children);
  }

  function dryRunBanner() {
    return h("div", { class: "banner banner--dry" }, [w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t("dryrun.banner") })]);
  }

  function recentMini(ctx) {
    var rows = ctx.attacks.recent.slice(0, 4).map(function (r) {
      return h("tr", { class: "is-clickable", tabindex: "0", role: "button", onclick: function () { ctx.actions.openDrawer(r); }, onkeydown: keyAct(function () { ctx.actions.openDrawer(r); }) }, [
        h("td", { class: "target-cell", text: r.scope === "group" ? r.group : r.target }),
        h("td", {}, K.dirBadge(r.direction)),
        h("td", { class: "td-muted", text: I.label("attackType", r.classification.type) }),
        h("td", { class: "num", text: I.abbr(r.peak_rate) }),
        h("td", { class: "td-muted", text: I.rel(new Date(r.ended_at || r.started_at)) })
      ]);
    });
    return h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("clock"), h("span", { text: I.t("at.recent") })])),
      h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
        h("thead", {}, h("tr", {}, [th("col.target"), th("col.dir"), th("col.type"), thNum("col.peak"), th("col.ended")])),
        h("tbody", {}, rows)
      ]))
    ]);
  }
  function th(key) { return h("th", { text: I.t(key) }); }
  function thNum(key) { return h("th", { class: "num", text: I.t(key) }); }

  /* ===== ATTACKS ===== */
  function attacks(root, ctx) {
    var f = ctx.state.filters;
    var groups = ctx.groups.map(function (g) { return g.name; });
    var types = Object.keys(I._en().enums.attackType);

    function sel(key, val, options, labelFn) {
      var s = h("select", { class: "select", id: "f-" + key, onchange: function (e) { ctx.actions.setFilter(key, e.target.value); } },
        [h("option", { value: "", text: I.t("filter." + key) })].concat(options.map(function (o) {
          var opt = h("option", { value: o, text: labelFn ? labelFn(o) : o }); if (val === o) opt.selected = true; return opt;
        })));
      return s;
    }
    var search = h("input", { class: "input mono", id: "f-q", placeholder: I.t("filter.search"), value: f.q || "",
      oninput: function (e) { ctx.actions.setFilter("q", e.target.value); } });

    var filters = h("div", { class: "filters" }, [
      h("span", { class: "row", style: { color: "var(--muted)" } }, [w.icon("sliders")]),
      sel("scope", f.scope, ["host", "group"], function (o) { return I.label("scope", o); }),
      sel("dir", f.dir, ["incoming", "outgoing"], function (o) { return I.label("direction", o); }),
      sel("type", f.type, types, function (o) { return I.label("attackType", o); }),
      sel("group", f.group, groups),
      search
    ]);

    function match(a) {
      if (f.scope && a.scope !== f.scope) return false;
      if (f.dir && a.direction !== f.dir) return false;
      if (f.type && a.classification.type !== f.type) return false;
      if (f.group && a.group !== f.group) return false;
      if (f.q && String(a.target || a.group).indexOf(f.q) < 0) return false;
      return true;
    }

    var active = ctx.attacks.active.filter(match);
    var recent = ctx.attacks.recent.filter(match);

    var activeBlock = active.length
      ? h("div", { class: "stack" }, active.map(function (a) { return attackCard(a, ctx); }))
      : h("div", { class: "card" }, K.empty("shield-check", I.t("at.empty.title"), I.t("at.empty.sub")));

    var recentRows = recent.map(function (r) {
      var dur = r.ended_at ? Math.round((new Date(r.ended_at) - new Date(r.started_at)) / 1000) : 0;
      return h("tr", { class: "is-clickable", tabindex: "0", role: "button", onclick: function () { ctx.actions.openDrawer(r); }, onkeydown: keyAct(function () { ctx.actions.openDrawer(r); }) }, [
        h("td", { class: "target-cell", text: r.scope === "group" ? r.group : r.target }),
        h("td", {}, K.dirBadge(r.direction)),
        h("td", { class: "td-muted", text: I.label("attackType", r.classification.type) }),
        h("td", { class: "mono td-muted", text: r.metric }),
        h("td", { class: "num", text: I.abbr(r.peak_rate) }),
        h("td", { class: "td-muted", text: I.datetime(new Date(r.started_at)) }),
        h("td", { class: "td-muted", text: I.duration(dur) })
      ]);
    });
    var recentBlock = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("clock"), h("span", { text: I.t("at.recent") }), recent.length ? K.badge("badge--muted", String(recent.length)) : null])),
      recent.length
        ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [th("col.target"), th("col.dir"), th("col.type"), th("col.metric"), thNum("col.peak"), th("col.started"), th("col.duration")])),
            h("tbody", {}, recentRows)
          ]))
        : h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("at.recent.empty") }))
    ]);

    K.mount(root, [
      viewHead(I.t("nav.attacks"), null),
      filters,
      h("div", { class: "section-label", style: { marginTop: "var(--s-2)" } }, [w.icon("flame"), h("span", { text: I.t("at.active") }), active.length ? K.badge("badge--active", String(active.length)) : null]),
      activeBlock,
      h("div", { class: "mt-6" }, recentBlock)
    ]);
  }

  /* ===== BANS / MITIGATION ===== */
  function bans(root, ctx) {
    var data = ctx.bans;
    var manualForm = ctx.role === "operator" ? banForm(ctx) : viewerNote();

    var activeRows = data.active.map(function (b) {
      var expires = b.expires_at ? I.t("bn.expiresin", { t: I.duration((new Date(b.expires_at) - Date.now()) / 1000) }) : I.t("bn.noexpire");
      return h("tr", {}, [
        h("td", { class: "target-cell" }, [h("span", { text: b.target }), h("span", { class: "td-muted", text: b.prefix })]),
        h("td", { class: "mono td-muted", text: b.route }),
        h("td", {}, K.badge(b.method === "blackhole" ? "badge--active" : b.method === "divert" ? "badge--elev" : "badge--accent", I.label("method", b.method))),
        h("td", {}, K.badge("badge--calm", I.label("banState", b.state))),
        h("td", {}, b.dry_run ? K.badge("badge--dry", I.t("mode.dryrun"), "shield-alert") : K.badge("badge--calm", I.t("mode.live"))),
        h("td", { class: "mono", dataset: { cdText: b.expires_at || "" }, text: expires }),
        h("td", {}, K.badge(b.manual ? "badge--accent" : "badge--muted", b.manual ? I.t("bn.manualtag") : I.t("bn.autotag"))),
        h("td", {}, ctx.role === "operator" ? h("button", { class: "btn btn--ghost btn--sm", onclick: function (e) { ctx.actions.unban(e.currentTarget, b.target); } }, [w.icon("x"), h("span", { text: I.t("bn.unban") })]) : null)
      ]);
    });

    var activeBlock = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("ban"), h("span", { text: I.t("bn.active") }), data.active.length ? K.badge("badge--active", String(data.active.length)) : null])),
      data.active.length
        ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [th("col.target"), th("col.route"), th("col.method"), th("col.state"), th("col.mode"), th("col.expires"), th("col.type2"), h("th", {})])),
            h("tbody", {}, activeRows)
          ]))
        : h("div", { class: "card__body" }, K.empty("shield-check", I.t("bn.empty.title"), I.t("bn.empty.sub")))
    ]);

    var histRows = data.history.map(function (b) {
      var rejected = b.state === "rejected";
      return h("tr", {}, [
        h("td", { class: "target-cell" }, [h("span", { text: b.target }), h("span", { class: "td-muted", text: b.prefix })]),
        h("td", { class: "mono td-muted", text: b.route }),
        h("td", {}, K.badge(b.method === "blackhole" ? "badge--muted" : "badge--muted", I.label("method", b.method))),
        h("td", {}, K.badge(rejected ? "badge--elev" : "badge--muted", I.label("banState", b.state))),
        h("td", {}, K.badge(b.manual ? "badge--accent" : "badge--muted", b.manual ? I.t("bn.manualtag") : I.t("bn.autotag"))),
        h("td", { class: "td-muted", text: rejected ? rejectReason(b.reason) : (b.withdrawn_at ? I.rel(new Date(b.withdrawn_at)) : "") })
      ]);
    });
    var histBlock = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("history"), h("span", { text: I.t("bn.history") })])),
      data.history.length
        ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [th("col.target"), th("col.route"), th("col.method"), th("col.state"), th("col.type2"), th("col.reason")])),
            h("tbody", {}, histRows)
          ]))
        : h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("bn.history.empty") }))
    ]);

    K.mount(root, [
      viewHead(I.t("nav.bans"), null),
      ctx.dryRun ? dryRunBanner() : null,
      manualForm,
      h("div", { class: "mt-4" }, activeBlock),
      h("div", { class: "mt-6" }, histBlock)
    ]);
  }

  function rejectReason(reason) {
    return { whitelisted: I.t("reject.whitelisted"), outside_networks: I.t("reject.outside"), cap: I.t("reject.cap") }[reason] || reason;
  }

  function banForm(ctx) {
    var input = h("input", { class: "input mono", id: "ban-ip", placeholder: "203.0.113.66", value: "" });
    function doBan(e) { var ip = input.value.trim(); if (!ip) { input.focus(); return; }
      K.confirm(e.currentTarget, { title: I.t("bn.ban"), text: I.t("bn.ban.confirm", { t: ip }), danger: true, confirmLabel: I.t("bn.ban"), onConfirm: function () { ctx.actions.ban(ip); input.value = ""; } }); }
    function doUnban(e) { var ip = input.value.trim(); if (!ip) { input.focus(); return; }
      K.confirm(e.currentTarget, { title: I.t("bn.unban"), text: I.t("bn.unban.confirm", { t: ip }), confirmLabel: I.t("bn.unban"), onConfirm: function () { ctx.actions.unban(null, ip); input.value = ""; } }); }
    return h("div", { class: "card" }, [
      h("div", { class: "card__head" }, [
        h("div", { class: "card__title" }, [w.icon("edit"), h("span", { text: I.t("bn.manual") })]),
        K.badge("badge--accent", I.t("op.only"), "lock")
      ]),
      h("div", { class: "card__body" }, [
        h("p", { class: "td-muted", style: { marginBottom: "var(--s-3)", maxWidth: "70ch" }, text: I.t("bn.manual.sub") }),
        h("div", { class: "row wrap" }, [
          h("label", { class: "row", style: { gap: "8px" } }, [h("span", { class: "td-muted", text: I.t("bn.ip") }), input]),
          h("button", { class: "btn btn--danger", onclick: doBan }, [w.icon("ban"), h("span", { text: I.t("bn.ban") })]),
          h("button", { class: "btn btn--ghost", onclick: doUnban }, [w.icon("check"), h("span", { text: I.t("bn.unban") })])
        ])
      ])
    ]);
  }
  function viewerNote() {
    return h("div", { class: "banner banner--info" }, [w.icon("eye"), h("span", { class: "banner__txt", text: I.t("viewer.note") })]);
  }

  /* ===== HOSTS (top talkers) ===== */
  function hosts(root, ctx) {
    var dir = ctx.state.hostDir || "incoming";
    var list = ctx.hosts.map(function (host) {
      var r = dir === "outgoing" ? host.out_rates : host.rates;
      var bl = dir === "outgoing" ? host.out_baseline : host.baseline;
      var blPps = bl ? bl.pps : null;
      var mult = blPps ? r.pps / blPps : null;
      return { host: host, r: r, blPps: blPps, mult: mult, attacked: host.in_attack && dir === "incoming" };
    });
    list.sort(function (a, b) {
      if (a.attacked !== b.attacked) return a.attacked ? -1 : 1;
      return (b.mult || 0) - (a.mult || 0);
    });

    var dirSeg = h("div", { class: "seg" }, ["incoming", "outgoing"].map(function (d) {
      return h("button", { class: "seg__btn" + (dir === d ? " is-on" : ""), text: I.label("direction", d), onclick: function () { ctx.actions.setHostDir(d); } });
    }));

    var rows = list.map(function (it) {
      var host = it.host, expanded = ctx.state.expanded.has(host.target);
      var blInfo = K.baselineBar(it.r.pps, it.blPps);
      var multNode = it.mult != null
        ? h("div", { class: "host-mult" }, [
            h("div", { class: "host-mult__x", style: { color: it.mult >= 3 ? "var(--active)" : it.mult >= 1.5 ? "var(--elev)" : "var(--calm)" }, text: I.abbr(it.mult) + "×" }),
            h("div", { class: "host-mult__lbl", text: I.t("ho.overbaseline") })
          ])
        : h("div", { class: "host-mult" }, [h("div", { class: "host-mult__x", style: { color: "var(--muted)", fontSize: "var(--t-md)" }, text: "—" }), h("div", { class: "host-mult__lbl", text: I.t("ho.nobaseline") })]);

      var row = h("div", { class: "host-row" + (it.attacked ? " is-attack" : "") + (host.direction === "outgoing" && dir === "outgoing" ? " is-outgoing" : "") + (expanded ? " is-open" : ""),
        tabindex: "0", role: "button", onclick: function () { ctx.actions.toggleHost(host.target); }, onkeydown: keyAct(function () { ctx.actions.toggleHost(host.target); }) }, [
        h("div", { class: "host-id" }, [
          h("div", { class: "host-id__ip" }, [
            w.icon(expanded ? "chevron-down" : "chevron-right"),
            h("span", { text: host.target }),
            it.attacked ? K.badge("badge--active", I.t("ho.inattack"), "flame") : null,
            (host.direction === "outgoing" && dir === "outgoing") ? K.badge("badge--elev", I.label("direction", "outgoing"), "arrow-up") : null
          ]),
          h("div", { class: "host-id__grp", text: I.t("col.group") + ": " + host.group })
        ]),
        multNode,
        blInfo.bar,
        h("div", { class: "host-rates" }, [h("b", { text: I.pps(it.r.pps) }), " · ", I.mbps(it.r.mbps), " · ", I.fps(it.r.flows_per_sec)])
      ]);

      var detail = h("div", { class: "host-detail" + (expanded ? "" : "") }, hostDetail(it.r, dir));
      if (!expanded) detail.style.display = "none"; else detail.style.display = "block";
      return [row, detail];
    });

    K.mount(root, [
      viewHead(I.t("nav.hosts"), I.t("ho.headline"), [dirSeg]),
      ctx.hosts.length
        ? h("div", { class: "card" }, h("div", {}, [].concat.apply([], rows)))
        : h("div", { class: "card" }, K.empty("server", I.t("ho.empty.title"), I.t("ho.empty.sub"), "muted"))
    ]);
  }

  function hostDetail(r, dir) {
    var cells = [
      ["tcp_pps", r.tcp_pps, "pps"], ["udp_pps", r.udp_pps, "pps"], ["icmp_pps", r.icmp_pps, "pps"],
      ["tcp_syn_pps", r.tcp_syn_pps, "pps"], ["frag_pps", r.frag_pps, "pps"], ["flows_per_sec", r.flows_per_sec, "fps"]
    ];
    return h("div", {}, [
      h("div", { class: "section-label", style: { marginTop: "var(--s-2)" } }, [w.icon("layers"), h("span", { text: I.t("ho.protocols") })]),
      h("div", { class: "proto-grid" }, cells.map(function (c) {
        return h("div", { class: "proto-cell" }, [h("div", { class: "proto-cell__name", text: c[0] }), h("div", { class: "proto-cell__val", text: I.abbr(c[1], c[2]) })]);
      }))
    ]);
  }

  w.Views = {
    overview: overview, attacks: attacks, bans: bans, hosts: hosts,
    attackCard: attackCard, statsGrid: statsGrid, trafficStrip: trafficStrip,
    viewHead: viewHead, th: th, thNum: thNum, dryRunBanner: dryRunBanner
  };
})(window);
