/* views.js — per-screen render functions. Each renders into a view root that
   app.js clears every 3s poll. UI state (filters/sort/expanded) lives in
   app.js and is passed in via ctx so it survives re-renders. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h;

  /* keyboard activation for click-only rows (Enter / Space) */
  function keyAct(fn) { return function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fn(e); } }; }

  /* ===== shared building blocks ===== */
  /* A view in a section with tabs (Mitigation, the edge zones, Settings) is headed by
     the section's name with the tabs on the right; app.js supplies both
     through Views.section(), and null leaves the view's own title. */
  function viewHead(title, sub, actions) {
    var sec = w.Views.section ? w.Views.section() : null;
    var right = [].concat(actions || [], sec ? [sec.tabs] : []);
    return h("div", { class: "view-head" }, [
      h("div", {}, [h("h1", { class: "view-head__title", text: sec ? sec.title : title }), sub ? h("div", { class: "view-head__sub", text: sub }) : null]),
      right.length ? h("div", { class: "view-head__actions" }, right) : null
    ]);
  }

  /* ---------- DRY-RUN BANNERS ----------
     Returns null when there is nothing to say, so callers render it
     UNCONDITIONALLY. That matters: the loudest case here fires precisely when
     the global dry_run is FALSE, and the old `ctx.dryRun ? dryRunBanner() : null`
     guard would have skipped exactly the warning that needed shouting.

     The divergence being guarded is real and silent. dataplane dry_run lives in a
     kernel map, and an ADOPTED pin set carries the previous process's flag — so an
     operator can set dry_run: false, restart, watch every badge in this console
     flip to LIVE, and still have a datapath rewriting every drop into a pass.
     Nothing else on the page would contradict it. Hence a separate, louder banner
     rather than a nuance inside the existing one.

     Direction matters too, and the two directions are not symmetrical:

       dataplane simulating while the rest is live  -> DANGEROUS. The operator
         believes packets are being dropped and they are not. Loud, and shown to
         every role: a viewer looking at a drop that is not dropping should not be
         the last to know.

       dataplane enforcing while the rest simulates -> SURPRISING. Real packets
         are being dropped by a box the operator put in dry-run. Also loud, but
         only renderable for an admin, because "a data plane exists" is only
         knowable from the admin-only block — telling a viewer their data plane is
         enforcing when there may not be one at all would be a fabrication. */
  function dryRunBanner(ctx) {
    var globalDry = !!ctx.dryRun;
    var dpDry = !!ctx.status.dataplane_dry_run;
    var dpBlock = ctx.status.dataplane;                       /* admin-only */
    /* dpDry implies a data plane exists; the block is the only other evidence. */
    var dpKnownEnabled = dpDry || !!(dpBlock && dpBlock.enabled);

    if (dpDry && !globalDry) return banner(true, "dryrun.dp.simulating");
    if (globalDry && dpDry) return banner(false, "dryrun.banner", "dryrun.dp.also");
    if (globalDry && dpKnownEnabled) return banner(true, "dryrun.dp.enforcing");
    if (globalDry) return banner(false, "dryrun.banner");
    return null;

    /* loud adds the pulsing treatment and role="alert" so a screen reader
       announces it; both variants are class-only, never an inline style
       attribute, because the dashboard runs under style-src 'self'. */
    function banner(loud, key, extraKey) {
      var kids = [w.icon("shield-alert"), h("span", { class: "banner__txt", text: I.t(key) })];
      if (extraKey) kids.push(h("span", { class: "banner__more", text: I.t(extraKey) }));
      return h("div", {
        class: "banner " + (loud ? "banner--dry-loud" : "banner--dry"),
        attrs: loud ? { role: "alert" } : null
      }, kids);
    }
  }

  /* ---------- FILTER-BYPASS BANNER ----------
     The one signal on this dashboard that means the operator's rules did not
     run. The data plane walks a bounded number of IPv6 extension headers; a
     packet carrying more hits the cap and is FORWARDED without any rule being
     evaluated — allow-list, drop rule and rate limit alike. The verdict is PASS
     by charter (a parse budget must never become a default-deny), so being SEEN
     is the entire mitigation.

     Why a page-level banner and not just a counter in the data-plane card:
     nothing legitimate chains eight extension headers, so any non-zero value is
     worth a human's attention — but as one row among twenty-one parser
     statistics it reads as noise, and it stays SMALL in a real attack. A few
     thousand packets that skipped the filter will never win an attention
     contest against a drop counter in the millions, so it is not made to
     compete: it gets its own alert-role banner at the top of the page.

     Returns null when there is nothing to say, so callers render it
     unconditionally — the same contract as dryRunBanner.

     ADMIN-ONLY by construction, not by an explicit role check: the verdict
     counters ride in `status.dataplane`, which the API omits for a scoped
     token. A viewer therefore sees nothing here rather than a claim this
     console cannot substantiate. */
  function filterBypassBanner(ctx) {
    var dp = ctx.status.dataplane;
    if (!dp || !dp.enabled || !dp.verdicts) return null;
    var c = dp.verdicts["pass_exthdr_cap"];
    var pkts = (c && c.packets) || 0;
    if (!pkts) return null;
    return h("div", { class: "banner banner--dry-loud", attrs: { role: "alert" } }, [
      w.icon("shield-alert"),
      h("span", { class: "banner__txt", text: I.t("dp.bypass.banner", { n: I.abbr(pkts) }) }),
      h("span", { class: "banner__more", text: I.t("dp.bypass.act") })
    ]);
  }

  function th(key) { return h("th", { text: I.t(key) }); }
  function thNum(key) { return h("th", { class: "num", text: I.t(key) }); }

  /* ===== BANS / MITIGATION ===== */
  function bans(root, ctx) {
    var data = ctx.bans;
    var manualForm = ctx.role === "operator" ? banForm(ctx) : viewerNote();
    /* the node column exists only when managed scrubbing nodes are configured
       — the regression guard for everyone else: their tables stay unchanged */
    var withNode = ctx.status.nodes_total > 0;
    function nodeCell(b) {
      return h("td", {}, b.node ? K.badge("badge--muted", b.node, "divert") : h("span", { class: "td-muted", text: "—" }));
    }

    var activeRows = data.active.map(function (b) {
      var expires = b.expires_at ? I.t("bn.expiresin", { t: I.duration((new Date(b.expires_at) - Date.now()) / 1000) }) : I.t("bn.noexpire");
      return h("tr", {}, [
        h("td", { class: "target-cell" }, [h("span", { text: b.target }), h("span", { class: "td-muted", text: b.prefix })]),
        h("td", { class: "mono td-muted", text: b.route }),
        h("td", {}, K.methodPill(b.method)),
        withNode ? nodeCell(b) : null,
        // What the kernel MEASURED for this ban, not what it was asked to do.
        // Empty for every mitigation with no rules in this box's XDP maps.
        h("td", { class: "num" }, K.dropCell(b.dataplane)),
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
            h("thead", {}, h("tr", {}, [th("col.target"), th("col.route"), th("col.method"), withNode ? th("col.node") : null, thNum("col.dropped"), th("col.state"), th("col.mode"), th("col.expires"), th("col.type2"), h("th", {})])),
            h("tbody", {}, activeRows)
          ]))
        : h("div", { class: "card__body" }, K.empty("shield-check", I.t("bn.empty.title"), I.t("bn.empty.sub")))
    ]);

    var histRows = data.history.map(function (b) {
      var rejected = b.state === "rejected";
      return h("tr", {}, [
        h("td", { class: "target-cell" }, [h("span", { text: b.target }), h("span", { class: "td-muted", text: b.prefix })]),
        h("td", { class: "mono td-muted", text: b.route }),
        h("td", {}, K.badge("badge--muted", I.label("method", b.method), K.methodIcon(b.method))),
        withNode ? nodeCell(b) : null,
        // The FINAL tally. Kept on a withdrawn ban on purpose: the kernel
        // counters were reaped with the rules, so this record is the only
        // remaining answer to "how much did that mitigation actually catch".
        h("td", { class: "num" }, K.dropCell(b.dataplane)),
        h("td", {}, K.badge(rejected ? "badge--elev" : "badge--muted", I.label("banState", b.state))),
        h("td", {}, K.badge(b.manual ? "badge--accent" : "badge--muted", b.manual ? I.t("bn.manualtag") : I.t("bn.autotag"))),
        h("td", { class: "td-muted", text: rejected ? rejectReason(b.reason) : (b.withdrawn_at ? I.rel(new Date(b.withdrawn_at)) : "") })
      ]);
    });
    var histBlock = h("div", { class: "card" }, [
      h("div", { class: "card__head" }, h("div", { class: "card__title" }, [w.icon("history"), h("span", { text: I.t("bn.history") })])),
      data.history.length
        ? h("div", { class: "tablewrap" }, h("table", { class: "tbl" }, [
            h("thead", {}, h("tr", {}, [th("col.target"), th("col.route"), th("col.method"), withNode ? th("col.node") : null, thNum("col.dropped"), th("col.state"), th("col.type2"), th("col.reason")])),
            h("tbody", {}, histRows)
          ]))
        : h("div", { class: "card__body" }, h("p", { class: "td-muted", text: I.t("bn.history.empty") }))
    ]);

    K.mount(root, [
      viewHead(I.t("nav.bans"), null),
      dryRunBanner(ctx),
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

  /* Aggregate traffic summary above the host list — current rate for the
     selected direction + a sparkline of the recent window (reuses ctx.buf). */
  function hostsAgg(ctx, dir) {
    var agg = ctx.agg, out = dir === "outgoing";
    var mbps = out ? agg.out_mbps : agg.in_mbps;
    var pps = out ? agg.out_pps : agg.in_pps;
    var spark = out ? ctx.buf.aggOut : ctx.buf.aggIn;
    var color = out ? "var(--chart-out)" : "var(--chart-in)";
    return h("div", { class: "card" }, h("div", { class: "card__body host-agg" }, [
      h("div", {}, [
        h("div", { class: "host-agg__label", text: out ? I.t("ov.egress") : I.t("ov.ingress") }),
        h("div", { class: "host-agg__val mono" }, [I.mbps(mbps), h("span", { class: "host-agg__sub", text: "  ·  " + I.pps(pps) + " " + I.t("ov.now") })])
      ]),
      h("div", { class: "host-agg__chart" }, K.areaChart(spark && spark.length ? spark : [0, 0], { color: color, height: 48 }))
    ]));
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
    /* attacked hosts first, then by throughput (mbps) desc; tie-break on the
       target so the order is STABLE across the 3s poll re-render — otherwise
       hosts tied on rate (e.g. all still LEARNING) reshuffle every poll, which
       makes rows jump out from under the cursor and expand-clicks miss. */
    list.sort(function (a, b) {
      if (a.attacked !== b.attacked) return a.attacked ? -1 : 1;
      var dm = (b.r.mbps || 0) - (a.r.mbps || 0);
      if (dm) return dm;
      return a.host.target < b.host.target ? -1 : a.host.target > b.host.target ? 1 : 0;
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
        tabindex: "0", role: "button", "data-target": host.target, onclick: function () { ctx.actions.toggleHost(host.target); }, onkeydown: keyAct(function () { ctx.actions.toggleHost(host.target); }) }, [
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

    /* keep keyboard focus on the SAME host across the live re-sort (rows are
       morphed by position, so re-focus the row matching the prior target). */
    var af = document.activeElement;
    var keepTarget = (af && af.classList && af.classList.contains("host-row")) ? af.getAttribute("data-target") : null;
    K.mount(root, [
      viewHead(I.t("nav.hosts"), I.t("ho.headline"), [dirSeg]),
      ctx.hosts.length ? hostsAgg(ctx, dir) : null,
      ctx.hosts.length
        ? h("div", { class: "card", style: { marginTop: "var(--s-4)" } }, h("div", {}, [].concat.apply([], rows)))
        : h("div", { class: "card" }, K.empty("server", I.t("ho.empty.title"), I.t("ho.empty.sub"), "muted"))
    ]);
    if (keepTarget) { var rf = root.querySelector('.host-row[data-target="' + keepTarget + '"]'); if (rf) rf.focus(); }
  }

  function hostDetail(r, dir) {
    var cells = [
      ["tcp_pps", r.tcp_pps, "pps"], ["udp_pps", r.udp_pps, "pps"], ["icmp_pps", r.icmp_pps, "pps"],
      ["tcp_syn_pps", r.tcp_syn_pps, "pps"], ["frag_pps", r.frag_pps, "pps"], ["flows_per_sec", r.flows_per_sec, "fps"]
    ];
    return h("div", {}, [
      h("div", { class: "section-label", style: { marginTop: "var(--s-2)" } }, [w.icon("layers"), h("span", { text: I.t("ho.protocols") })]),
      h("div", { class: "proto-grid" }, cells.map(function (c) {
        /* per-protocol fields are omitempty: absent (undefined) means zero, not
           NaN — coerce so a calm/TCP-only host shows "0 pps", never "NaN pps". */
        return h("div", { class: "proto-cell" }, [h("div", { class: "proto-cell__name", text: c[0] }), h("div", { class: "proto-cell__val", text: I.abbr(c[1] || 0, c[2]) })]);
      }))
    ]);
  }

  w.Views = {
    bans: bans, hosts: hosts,
    viewHead: viewHead, th: th, thNum: thNum, dryRunBanner: dryRunBanner,
    filterBypassBanner: filterBypassBanner
  };
})(window);
