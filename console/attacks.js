/* attacks.js — the Attacks section: every attack in one place (a card for
   each one going on, a table of the ones that ended) and one attack's own
   page, which replaced the side drawer.

   Read from what the console already polls (attacks, bans, hosts, status);
   no new endpoint. The charts draw what app.js samples on every poll for
   each live attack (state.buf.atk): the attack's own rates, which the engine
   re-reads on every request, so a card shows the attack as it is now, not as
   it was when it was caught. What the API does not keep is not made up: a
   peak is shown only where this page saw it, and the time of each rung is
   the ladder's (start + after_seconds), which is when the engine moves up. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h, V = w.Views;
  var A = K.atk, ACT = A.ACT, actName = A.actName, actTone = A.actTone, targetOf = A.targetOf,
      mult = A.mult, multText = A.multText, startedMs = A.startedMs, protOf = A.protOf,
      nextRung = A.nextRung, countdown = K.countdown, splitUnit = K.splitUnit, arrowBtn = K.arrowBtn;

  /* ===================== reading an attack ===================== */
  function isGroup(a) { return a.scope === "group"; }
  function endedMs(a) { return a.ended_at ? new Date(a.ended_at).getTime() : 0; }
  function groupOf(ctx, name) {
    for (var i = 0; i < ctx.groups.length; i++) if (ctx.groups[i].name === name) return ctx.groups[i];
    return null;
  }
  function toneOf(act) { return act === "none" ? "alert" : actTone(act); }
  function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }
  /* a value in the unit of the metric that fired: Gb/s for the bandwidth
     metrics, the metric's own name beside a count (pps, udp_pps, …) */
  function fmtMetric(v, metric) {
    v = v || 0;
    if (metric === "mbps") return I.mbps(v);
    if (/_mbps$/.test(metric)) return I.mbps(v) + " " + metric.slice(0, -5);
    if (metric === "flows_per_sec") return I.fps(v);
    return I.abbr(v, metric || "");
  }
  /* A translated phrase with the target spliced in where {t} stands: the
     phrase keeps its own word order and the address can still be mono. */
  function phrase(key, vars, target, mono) {
    var s = I.t(key, vars), i = s.indexOf("{t}");
    if (i < 0) return [s];
    return [s.slice(0, i), h("span", { class: mono ? "mono" : null, text: target }), s.slice(i + 3)];
  }
  /* a time of day, with the date when it was not today; to the second for
     the summary, where it lands in a ticket */
  function whenText(ms, seconds) {
    var d = new Date(ms);
    if (d.toDateString() !== new Date().toDateString()) return I.datetime(d);
    return seconds ? I.time(d) : I.timeShort(d);
  }
  /* the gap between two rungs: "45 s", "2 min", or "1m 45s" for the rest */
  function delayText(sec) {
    if (sec < 60) return I.t("ov.plan.sec", { n: I.num(sec) });
    if (sec % 60 === 0) return I.t("ov.plan.min", { n: I.num(sec / 60) });
    return I.duration(sec);
  }

  /* The bans by address, built once per render: an ended attack looks its
     own up, and the history holds one ban for every address ever banned. */
  function bansBy(ctx) {
    if (ctx.bansBy) return ctx.bansBy;
    var by = {};
    ctx.bans.active.concat(ctx.bans.history).forEach(function (b) { (by[b.target] = by[b.target] || []).push(b); });
    return (ctx.bansBy = by);
  }
  /* The ban an attack's mitigation lived on. The engine keeps one ban per
     address, the newest, so an attack finds its own only until a later attack
     on the same address replaces it. Matched by time: a ban is created with
     its attack, never before it. */
  function banOf(a, ctx) {
    if (isGroup(a)) return null;
    var list = bansBy(ctx)[a.target] || [], t0 = startedMs(a) - 5000, t1 = a.active ? Infinity : endedMs(a) + 5000;
    for (var i = 0; i < list.length; i++) {
      var bs = new Date(list[i].started_at).getTime();
      if (bs >= t0 && bs <= t1) return list[i];
    }
    return null;
  }
  /* The ladder and the rung it reached. A live attack's is its ban's (api.js
     joined it); an ended one's comes from its ban in the history while the
     engine still has it, else from the group's ladder by elapsed time, which
     is how the engine moves up. A group attack's is the alert alone. */
  function ladderOf(a, ctx) {
    var b = a.active ? null : banOf(a, ctx);
    var own = b && b.escalation && b.escalation.length;
    var esc = own ? b.escalation : a.escalation, step = own ? b.escalation_step : a.escalation_step;
    if (!esc || !esc.length) esc = [{ after_seconds: 0, action: "none" }];
    return { esc: esc, step: Math.max(0, Math.min(step || 0, esc.length - 1)) };
  }
  /* How an ended attack ended: the method it was held with at the end, and
     why that stopped, from its ban while the engine still has it. */
  var WHY = { "attack ended": "at.end.calm", "ttl expired": "at.end.ttl", "manual unban": "at.end.manual",
              "target left configured networks": "at.end.left" };
  function endOf(a, ctx) {
    if (isGroup(a)) return { method: "none", note: I.t("at.rung.group") };
    var b = banOf(a, ctx);
    if (a.ban_state === "rejected" || (b && b.state === "rejected")) return { method: "none", note: I.t("at.end.rejected"), ban: b };
    if (b) {
      var m = b.method || "none";
      if (b.state === "active") return { method: m, note: I.t("at.end.held"), ban: b };
      var key = WHY[b.reason], t = b.withdrawn_at ? I.timeShort(new Date(b.withdrawn_at)) : "";
      var note = key ? I.t(key, { t: t }) : (b.reason || "");
      if (m === "dataplane" && a.dataplane && a.dataplane.packets) note += " · " + I.t("at.end.dropped", { n: I.abbr(a.dataplane.packets) });
      return { method: m, note: note, ban: b };
    }
    var g = groupOf(ctx, a.group);
    if (g && !g.ban_enabled) return { method: "none", note: I.t("at.end.alertonly") };
    /* a later attack on the address replaced this one's ban */
    var L = ladderOf(a, ctx);
    return { method: L.esc[L.step].action, note: "" };
  }
  /* the protection an attack has now, or the one it ended with */
  function protNow(a, ctx) { return a.active ? (isGroup(a) ? "none" : protOf(a, ctx)) : endOf(a, ctx).method; }

  /* what app.js sampled for the attack: [{t, v}] of one field */
  function samples(ctx, a, field) {
    var b = ctx.buf.atk[A.key(a)], out = [];
    if (!b) return out;
    for (var i = 0; i < b.t.length; i++) if (b[field][i] != null) out.push({ t: b.t[i], v: b[field][i] });
    return out;
  }
  /* at most n bars, each the mean of its samples; a bar is the attack's when
     any of its samples fell inside it */
  function buckets(pts, n, t0, t1) {
    var size = Math.max(1, Math.ceil(pts.length / n)), out = [];
    for (var j = 0; j < pts.length; j += size) {
      var chunk = pts.slice(j, j + size), sum = 0, hot = false;
      for (var k = 0; k < chunk.length; k++) { sum += chunk[k].v; if (chunk[k].t >= t0 && chunk[k].t <= t1) hot = true; }
      out.push({ v: sum / chunk.length, hot: hot, t: chunk[chunk.length - 1].t });
    }
    return out;
  }
  /* a round top for a scale, close above the value: 520k reads against 600k,
     not against a million that leaves half the chart empty */
  var NICE = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
  function niceCeil(v) {
    if (!(v > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log(v) / Math.LN10)), n = v / p;
    for (var i = 0; i < NICE.length; i++) if (n <= NICE[i] + 1e-9) return NICE[i] * p;
    return 10 * p;
  }
  function chip(method) {
    return h("span", { class: "at-chip tone-" + toneOf(method) }, [h("span", { class: "at-chip__dot", attrs: { "aria-hidden": "true" } }), actName(method)]);
  }
  function withdrawBtn(a, ctx, large) {
    return h("button", { class: "btn at-withdraw" + (large ? " is-lg" : ""), attrs: { type: "button" }, text: I.t("at.withdraw"),
      onclick: function (e) { ctx.actions.withdraw(e.currentTarget, a.target); } });
  }
  function openLabel(a) { return I.t(isGroup(a) ? "at.open.group" : "ov.at.open", { t: targetOf(a) }); }
  function targetName(a) { return isGroup(a) ? I.t("at.card.group", { g: a.group }) : targetOf(a); }

  /* ===================== the list ===================== */
  /* "udp to 443 and 80 · 96% of the traffic": what the sample says the
     vector is made of */
  function vectorSub(a) {
    var s = a.sample, c = a.classification || {}, head = "";
    var proto = s && s.protocols && s.protocols.length ? s.protocols[0].key : "";
    if (proto && c.src_port) head = I.t("at.vsub.from", { proto: proto, port: c.src_port });
    else if (proto) {
      var ports = (s.top_dst_ports || []).slice(0, 2).map(function (p) { return p.key; });
      head = ports.length ? I.t("at.vsub.to", { proto: proto, ports: ports.join(I.t("ov.at.and")) }) : proto;
    }
    var share = c.confidence ? I.t("at.vsub.share", { p: I.pct(c.confidence) }) : "";
    return [head, share].filter(Boolean).join(" · ");
  }

  /* The card's chart: the attack's metric over the minutes this page has
     seen, red from the moment it was caught, the threshold dashed across. */
  var SPARK_BARS = 30;
  function spark(a, ctx) {
    var pts = samples(ctx, a, "v");
    if (pts.length < 2) return h("div", { class: "at-spark is-empty" }, h("span", { text: I.t("at.spark.wait") }));
    var bars = buckets(pts, SPARK_BARS, startedMs(a), a.active ? Infinity : endedMs(a));
    var max = a.threshold || 0;
    bars.forEach(function (x) { if (x.v > max) max = x.v; });
    max = (max || 1) * 1.1;
    var aria = I.t("at.spark.aria", { m: a.metric, t: targetName(a), from: fmtMetric(pts[0].v, a.metric),
      to: fmtMetric(pts[pts.length - 1].v, a.metric), thr: fmtMetric(a.threshold, a.metric) });
    var kids = [h("div", { class: "at-spark__bars", attrs: { role: "img", "aria-label": aria } }, bars.map(function (x) {
      var el = h("span", { class: "at-spark__bar" + (x.hot ? " is-attack" : "") });
      el.style.height = Math.max(4, Math.round(x.v / max * 100)) + "%";
      return el;
    }))];
    if (a.threshold) {
      var line = h("span", { class: "at-spark__thr", attrs: { "aria-hidden": "true" } });
      line.style.bottom = Math.round(a.threshold / max * 100) + "%";
      kids.push(line);
    }
    return h("div", { class: "at-spark" }, kids);
  }

  /* the ladder as segments, the rungs reached in their colours, each named
     below; the sentence under it says the same in words, for every reader */
  function stepsBar(a, ctx) {
    var L = ladderOf(a, ctx), cols = "repeat(" + L.esc.length + ", minmax(0, 1fr))";
    var bars = h("div", { class: "at-steps__bars" }, L.esc.map(function (st, i) {
      return h("span", { class: "at-steps__bar" + (i <= L.step ? " tone-" + toneOf(st.action) : "") });
    }));
    var names = h("div", { class: "at-steps__names" }, L.esc.map(function (st, i) {
      return h("span", { class: i === L.step ? "is-on" : null, text: actName(st.action) });
    }));
    bars.style.gridTemplateColumns = cols;
    names.style.gridTemplateColumns = cols;
    return h("div", { class: "at-steps", attrs: { "aria-hidden": "true" } }, [bars, names]);
  }
  /* what is being done, and what comes next */
  function rungLine(a, ctx) {
    var prot = protNow(a, ctx), nx = nextRung(a);
    var kids = [h("b", { text: actName(prot) }), " — " + (isGroup(a) ? I.t("at.rung.group") : ACT[prot] ? I.t(ACT[prot].now) : "")];
    if (nx) kids.push("; " + I.t("at.rung.next", { action: actName(nx.action) }) + " ", countdown(nx.atMs));
    else if (prot !== "none") kids.push("; " + I.t("at.rung.hold"));
    return h("div", { class: "at-rung" }, kids);
  }

  function card(a, ctx) {
    var m = mult(a), group = isGroup(a), t0 = startedMs(a), r = a.rates || {};
    var meta = [
      group ? I.t("at.card.sum") : I.t("at.card.group", { g: a.group }),
      I.t(a.direction === "outgoing" ? "at.dir.out" : "at.dir.in"),
      I.t("at.card.since", { t: I.timeShort(new Date(t0)), d: I.duration((Date.now() - t0) / 1000) })
    ].join(" · ");
    var acts = [];
    if (ctx.role === "operator" && !group && protOf(a, ctx) !== "none") acts.push(withdrawBtn(a, ctx));
    return h("article", { class: "at-card", attrs: { "aria-label": I.t("at.card.aria", { t: targetName(a) }) } }, [
      h("div", { class: "at-card__head" }, [
        h("div", { class: "at-card__id" }, [
          h("div", { class: "at-card__ip" + (group ? "" : " mono"), text: targetName(a) }),
          h("div", { class: "at-card__meta", text: meta })
        ]),
        arrowBtn(openLabel(a), function () { ctx.actions.openAttack(a); })
      ]),
      h("div", { class: "at-card__vec" }, [
        h("span", { class: "at-vec", text: I.label("attackType", a.classification.type) }),
        h("span", { class: "at-card__vsub", text: vectorSub(a) })
      ]),
      h("div", { class: "at-card__force" }, [
        h("div", {}, [
          h("div", { class: "at-card__mag" + (m != null && m >= 1 ? " is-attack" : ""), text: m != null ? multText(m) + "×" : "—" }),
          h("div", { class: "at-card__cap", text: I.t(m != null && m < 1 ? "at.card.ofthr" : "ac.overthreshold") })
        ]),
        h("div", { class: "at-card__rate" }, [
          h("div", { class: "mono at-card__now", text: I.pps(r.pps || 0) + " · " + I.mbps(r.mbps || 0) }),
          h("div", { class: "mono at-card__thr", text: I.t("at.card.thr", { v: fmtMetric(a.threshold, a.metric) }) })
        ])
      ]),
      spark(a, ctx),
      h("div", { class: "at-card__rungs" }, [stepsBar(a, ctx), rungLine(a, ctx)]),
      acts.length ? h("div", { class: "at-card__acts" }, acts) : null
    ]);
  }

  /* ---------- the filters ---------- */
  function matcher(f, ctx) {
    var q = (f.q || "").trim().toLowerCase();
    return function (a) {
      if (f.scope === "host" && isGroup(a)) return false;
      if (f.scope === "group" && !isGroup(a)) return false;
      if (f.dir && (a.direction === "outgoing" ? "outgoing" : "incoming") !== f.dir) return false;
      if (f.type && a.classification.type !== f.type) return false;
      if (f.group && a.group !== f.group) return false;
      if (f.prot && protNow(a, ctx) !== f.prot) return false;
      if (q && String(targetOf(a) || "").toLowerCase().indexOf(q) < 0 && String(a.group || "").toLowerCase().indexOf(q) < 0) return false;
      return true;
    };
  }
  function anyFilter(f) { return !!(f.scope || f.dir || f.type || f.group || f.prot || f.q); }
  function resetBtn(ctx) {
    return h("button", { class: "btn btn--ghost btn--sm", attrs: { type: "button" }, text: I.t("at.f.reset"), onclick: function () { ctx.actions.resetFilters(); } });
  }

  /* The filter row. A choice counts the attacks going on, since that is
     what an operator under pressure filters; a protection or a vector shows
     up as a choice only while some attack has it. */
  function filterRow(ctx, act, rec) {
    var f = ctx.state.filters, n = act.length, all = act.concat(rec);
    function count(pred) { var c = 0; act.forEach(function (a) { if (pred(a)) c++; }); return c; }
    function lbl(text, c) { return n ? text + " · " + I.num(c) : text; }
    function seg(key, label, items) {
      return h("div", { class: "seg at-seg", attrs: { role: "group", "aria-label": label } }, items.map(function (it) {
        var on = (f[key] || "") === it.v;
        return h("button", { class: "seg__btn" + (on ? " is-on" : ""), attrs: { type: "button", "aria-pressed": String(on) }, text: it.label,
          onclick: function () { ctx.actions.setFilter(key, it.v); } });
      }));
    }
    /* A pill showing "Vector: any" with the native select laid over it,
       transparent: the whole pill opens the list, and the list is the
       platform's own, keyboard and screen reader included. */
    function pick(key, label, anyLabel, options) {
      var cur = anyLabel;
      options.forEach(function (o) { if (o.v === f[key]) cur = o.label; });
      var sel = h("select", { class: "at-pick__sel", dataset: { filter: key }, attrs: { "aria-label": label },
        onchange: function (e) { ctx.actions.setFilter(key, e.target.value); } },
        [h("option", { attrs: { value: "" }, text: anyLabel })].concat(options.map(function (o) {
          return h("option", { attrs: { value: o.v, selected: f[key] === o.v ? "" : null }, text: o.label });
        })));
      return h("span", { class: "at-pick" + (f[key] ? " is-on" : "") }, [
        h("span", { class: "at-pick__k", attrs: { "aria-hidden": "true" }, text: label + ":" }),
        h("span", { class: "at-pick__v", attrs: { "aria-hidden": "true" }, text: cur }),
        w.icon("chevron-down"), sel
      ]);
    }
    function isOut(a) { return a.direction === "outgoing"; }

    var prots = {}, types = {}, groups = {};
    all.forEach(function (a) { prots[protNow(a, ctx)] = true; types[a.classification.type] = true; if (a.group) groups[a.group] = true; });
    ctx.groups.forEach(function (g) { groups[g.name] = true; });
    if (f.prot) prots[f.prot] = true;
    if (f.type) types[f.type] = true;
    if (f.group) groups[f.group] = true;
    prots.none = true;
    var order = ["none", "flowspec", "dataplane", "divert", "blackhole"];
    Object.keys(prots).forEach(function (p) { if (order.indexOf(p) < 0) order.push(p); });

    var kids = [
      seg("dir", I.t("at.f.dir"), [
        { v: "", label: lbl(I.t("at.f.all"), n) },
        { v: "incoming", label: lbl(I.t("at.f.in"), count(function (a) { return !isOut(a); })) },
        { v: "outgoing", label: lbl(I.t("at.f.out"), count(isOut)) }
      ]),
      seg("scope", I.t("at.f.scope"), [
        { v: "", label: I.t("at.f.anytarget") }, { v: "host", label: I.t("at.f.hosts") }, { v: "group", label: I.t("at.f.groups") }
      ]),
      seg("prot", I.t("at.f.prot"), [{ v: "", label: I.t("at.f.anyprot") }].concat(order.filter(function (p) { return prots[p]; }).map(function (p) {
        return { v: p, label: lbl(p === "none" ? I.t("at.f.unprot") : actName(p), count(function (a) { return protNow(a, ctx) === p; })) };
      }))),
      pick("type", I.t("at.f.vector"), I.t("at.f.anyvector"), Object.keys(types).map(function (t) { return { v: t, label: I.label("attackType", t) }; })
        .sort(function (x, y) { return x.label.localeCompare(y.label); })),
      pick("group", I.t("at.f.group"), I.t("at.f.anygroup"), Object.keys(groups).sort().map(function (g) { return { v: g, label: g }; }))
    ];
    if (anyFilter(f)) kids.push(resetBtn(ctx));
    return h("div", { class: "at-filters" }, kids);
  }

  /* ---------- the ones that ended ---------- */
  var ENDED_ROWS = 25;
  function endedRow(a, ctx) {
    var e = endOf(a, ctx), open = function () { ctx.actions.openAttack(a); };
    return h("tr", { class: "is-clickable", onclick: open }, [
      h("td", { class: "mono at-tbl__muted at-tbl__when", text: whenText(startedMs(a)) }),
      h("td", {}, [
        h("button", { class: "at-link" + (isGroup(a) ? "" : " mono"), attrs: { type: "button", "aria-label": openLabel(a) }, text: targetName(a),
          onclick: function (ev) { ev.stopPropagation(); open(); } }),
        h("span", { class: "at-tbl__muted", text: " · " + (isGroup(a) ? I.t("at.card.sum") : a.group) })
      ]),
      h("td", { text: I.label("attackType", a.classification.type) }),
      h("td", { class: "num", text: I.duration((endedMs(a) - startedMs(a)) / 1000) }),
      h("td", { class: "at-tbl__end" }, [chip(e.method), e.note ? h("span", { class: "at-tbl__muted", text: " " + e.note }) : null])
    ]);
  }
  function endedCard(ctx, rec, ended) {
    var expanded = ctx.state.expanded.has("atk:ended"), rows = expanded ? ended : ended.slice(0, ENDED_ROWS);
    var longest = ended.reduce(function (m, a) { return Math.max(m, endedMs(a) - startedMs(a)); }, 0);
    var sub = ended.length
      ? I.plural(ended.length, "atEndedCount") + (longest > 0 ? " · " + I.t("at.ended.longest", { d: I.duration(longest / 1000) }) : "")
      : I.t("at.ended.filtered");
    if (rec.length >= 100) sub += " · " + I.t("at.ended.cap");
    var th = function (k, cls) { return h("th", { class: cls || null, attrs: { scope: "col" }, text: I.t(k) }); };
    var kids = [h("div", { class: "ov-card__head" }, h("div", {}, [
      h("h2", { class: "ov-card__title", id: "at-ended-title", text: I.t("at.ended.title") }),
      h("p", { class: "ov-card__sub", text: sub })
    ]))];
    if (ended.length) {
      kids.push(h("div", { class: "at-tbl__wrap" }, h("table", { class: "at-tbl" }, [
        h("thead", {}, h("tr", {}, [th("at.col.start"), th("at.col.target"), th("at.col.vector"), th("at.col.lasted", "num"), th("at.col.end")])),
        h("tbody", {}, rows.map(function (a) { return endedRow(a, ctx); }))
      ])));
    }
    if (ended.length > ENDED_ROWS) {
      kids.push(h("button", { class: "btn btn--ghost btn--sm at-more", attrs: { type: "button" },
        text: expanded ? I.t("at.less") : I.t("at.all", { n: I.num(ended.length) }), onclick: function () { ctx.actions.toggleHost("atk:ended"); } }));
    }
    return h("section", { class: "ov-card at-ended", attrs: { "aria-labelledby": "at-ended-title" } }, kids);
  }

  /* ===================== the Attacks screen ===================== */
  function attacks(root, ctx) {
    var f = ctx.state.filters, act = ctx.attacks.active, rec = ctx.attacks.recent, match = matcher(f, ctx);
    var shown = act.filter(match).sort(function (x, y) {
      return ((mult(y) || 0) - (mult(x) || 0)) || (String(targetOf(x)) < String(targetOf(y)) ? -1 : 1);
    });
    var day = Date.now() - 86400000, endedDay = rec.filter(function (a) { return endedMs(a) >= day; }).length;
    var sub = (act.length ? I.plural(act.length, "atNow") : I.t("at.sub.none")) + " · " + I.plural(endedDay, "atEndedDay");
    var search = h("label", { class: "at-search" }, [
      w.icon("search"),
      h("span", { class: "sr-only", text: I.t("at.search.label") }),
      h("input", { class: "at-search__in mono", type: "search", placeholder: I.t("at.search.ph"), autocomplete: "off", spellcheck: "false",
        dataset: { filter: "q" }, value: f.q || "", oninput: function (e) { ctx.actions.setFilter("q", e.target.value); } })
    ]);

    var body;
    if (!act.length) {
      body = h("section", { class: "ov-card at-calm" }, [
        h("h2", { class: "at-calm__title", text: I.t("at.empty.title") }),
        h("p", { class: "ov-card__sub", text: I.t(rec.length ? "at.empty.sub" : "ov.at.never") })
      ]);
    } else if (!shown.length) {
      body = h("section", { class: "ov-card at-calm" }, [h("p", { class: "ov-card__sub", text: I.t("at.none.filtered") }), h("div", {}, resetBtn(ctx))]);
    } else {
      body = h("div", { class: "at-grid" }, shown.map(function (a) { return card(a, ctx); }));
    }

    K.mount(root, [
      V.viewHead(I.t("nav.attacks"), sub, act.length || rec.length ? [search] : null),
      act.length || rec.length ? filterRow(ctx, act, rec) : null,
      body,
      rec.length ? endedCard(ctx, rec, rec.filter(match)) : null
    ]);
    /* a select or the search box keeps what the operator chose in it, and a
       reset has to show in them too: the state is written back as the truth */
    root.querySelectorAll("[data-filter]").forEach(function (el) {
      var v = f[el.dataset.filter] || "";
      if (el.value !== v) el.value = v;
    });
  }

  /* ===================== one attack's page ===================== */
  function findAttack(ctx, key) {
    if (!key) return null;
    var all = ctx.attacks.active.concat(ctx.attacks.recent);
    for (var i = 0; i < all.length; i++) if (A.key(all[i]) === key) return all[i];
    return null;
  }
  function section(id, cls, kids) {
    return h("section", { class: "ov-card " + cls, attrs: { "aria-labelledby": id } }, kids);
  }
  function title(id, key, extra) {
    var t = h("h2", { class: "ov-card__title", id: id, text: I.t(key) });
    return extra ? h("div", { class: "at-sec__head" }, [t].concat(extra)) : t;
  }
  function note(text) { return h("p", { class: "at-note", text: text }); }

  function crumbs(ctx, a) {
    return h("nav", { class: "at-crumbs", attrs: { "aria-label": I.t("at.p.crumbs") } }, [
      h("button", { class: "at-crumbs__back", attrs: { type: "button" }, onclick: function () { ctx.actions.setView("attacks"); } },
        [w.icon("arrow-left"), h("span", { text: I.t("nav.attacks") })]),
      a ? h("span", { class: "at-crumbs__sep", attrs: { "aria-hidden": "true" }, text: "/" }) : null,
      a ? h("span", { class: isGroup(a) ? null : "mono", text: targetOf(a) }) : null
    ]);
  }

  function pageHead(a, ctx) {
    var group = isGroup(a), type = I.label("attackType", a.classification.type);
    var pills = [];
    if (a.active) pills.push(h("span", { class: "at-pill is-attack" }, [h("span", { class: "at-pill__dot", attrs: { "aria-hidden": "true" } }), I.t("at.p.going") + " ", K.since(startedMs(a))]));
    else pills.push(h("span", { class: "at-pill", text: I.t("at.p.ended", { t: I.time(new Date(endedMs(a))), d: I.duration((endedMs(a) - startedMs(a)) / 1000) }) }));
    pills.push(h("span", { class: "at-pill is-line", text: group ? I.t("at.card.sum") : I.t("at.card.group", { g: a.group }) }));
    pills.push(h("span", { class: "at-pill is-line", text: I.t(a.direction === "outgoing" ? "at.p.out" : "at.dir.in") }));
    var acts = [h("button", { class: "btn at-btn", attrs: { type: "button" }, onclick: function () { copySummary(a, ctx); } },
      [w.icon("copy"), h("span", { text: I.t("at.p.copy") })])];
    if (ctx.role === "operator" && a.active && !group && protOf(a, ctx) !== "none") acts.push(withdrawBtn(a, ctx, true));
    return h("div", { class: "at-head" }, [
      h("div", { class: "at-head__main" }, [
        h("h1", { class: "at-head__title" }, phrase(group ? "at.p.title.group" : "at.p.title", { type: type }, targetOf(a), !group)),
        h("div", { class: "at-head__pills" }, pills)
      ]),
      h("div", { class: "at-head__acts" }, acts)
    ]);
  }

  /* ---------- the force of the attack ----------
     The chart's units: the metric that fired first when it is a protocol's
     own (udp_pps …), then the totals. The threshold is drawn only in the
     unit it is set in. */
  var UNIT_FIELD = { pps: "pps", mbps: "mbps", flows_per_sec: "fps" };
  function unitsOf(a) { return (UNIT_FIELD[a.metric] ? [] : [a.metric]).concat(["pps", "mbps", "flows_per_sec"]); }
  function nowIn(a, unit) {
    var r = a.rates || {};
    if (unit === a.metric) return a.rate;
    return unit === "pps" ? r.pps : unit === "mbps" ? r.mbps : r.flows_per_sec;
  }
  function bigNum(text, caption, hot) {
    var p = splitUnit(text);
    return h("div", { class: "at-num" }, [
      h("div", { class: "at-num__fig" }, [h("span", { class: "ov-big" + (hot ? " is-attack" : ""), text: p[0] }), p[1] ? h("span", { class: "ov-big__unit", text: p[1] }) : null]),
      h("div", { class: "at-num__cap", text: caption })
    ]);
  }
  var PAGE_BARS = 60;
  /* a value on the scale, short enough for its gutter: the count alone where
     the unit is a count (the switch above names it), Gb/s or Mb/s in full */
  function scaleText(v, unit) { return /mbps$/.test(unit) ? I.mbps(v) : I.abbr(v); }
  function force(a, ctx) {
    var units = unitsOf(a), unit = units.indexOf(ctx.state.atkMetric) >= 0 ? ctx.state.atkMetric : a.metric;
    if (units.indexOf(unit) < 0) unit = units[0];
    var fmt = function (v) { return fmtMetric(v, unit); };
    var pts = samples(ctx, a, unit === a.metric ? "v" : UNIT_FIELD[unit]);
    var t0 = startedMs(a), t1 = a.active ? Infinity : endedMs(a), r = a.rates || {};

    var seg = h("div", { class: "seg", attrs: { role: "group", "aria-label": I.t("ov.tr.units") } }, units.map(function (u) {
      var on = u === unit;
      var label = u === "pps" ? "pps" : u === "mbps" ? splitUnit(I.mbps(r.mbps || 0))[1] : u === "flows_per_sec" ? I.t("at.unit.flows") : u;
      return h("button", { class: "seg__btn" + (on ? " is-on" : ""), attrs: { type: "button", "aria-pressed": String(on) }, text: label,
        onclick: function () { ctx.actions.setAtkMetric(u); } });
    }));

    var peak = null;
    pts.forEach(function (p) { if (p.t >= t0 && p.t <= t1 && (!peak || p.v > peak.v)) peak = p; });
    var nums = [];
    if (a.active) {
      nums.push(bigNum(fmt(nowIn(a, unit)), I.t("at.p.now")));
      nums.push(unit === "mbps" ? bigNum(I.pps(r.pps || 0), I.t("at.p.packets")) : bigNum(I.mbps(r.mbps || 0), I.t("at.p.bw")));
      var m = mult(a);
      if (m != null) nums.push(bigNum(multText(m) + "×", I.t(m < 1 ? "at.card.ofthr" : "ac.overthreshold"), m >= 1));
    } else {
      nums.push(h("div", { class: "at-num" }, [h("div", { class: "at-num__fig" }, h("span", { class: "ov-big", text: I.duration((endedMs(a) - t0) / 1000) })),
        h("div", { class: "at-num__cap", text: I.t("at.p.lasted") })]));
      nums.push(bigNum(fmtMetric(a.threshold, a.metric), I.t("at.p.thr")));
    }
    if (peak) nums.push(bigNum(fmt(peak.v), I.t("at.p.peak", { t: I.time(new Date(peak.t)) })));

    var kids = [title("at-force-title", "at.force.title", [seg]), h("div", { class: "at-nums" }, nums)];
    if (pts.length < 2) kids.push(note(I.t(a.active ? "at.chart.wait" : "at.chart.none")));
    else kids = kids.concat(bigChart(a, ctx, pts, unit, fmt, t0, t1));
    return section("at-force-title", "at-force", kids);
  }

  /* The page's chart: bars of the attack's force over the minutes this page
     has seen, red while it was on; the threshold dashed in its own unit; a
     line where the ladder moved up. Markers sit on the bar they fall in, so
     they line up with the bars however the polls were spaced. */
  function bigChart(a, ctx, pts, unit, fmt, t0, t1) {
    var bars = buckets(pts, PAGE_BARS, t0, t1), n = bars.length;
    var thr = unit === a.metric ? a.threshold : 0, top = thr;
    bars.forEach(function (x) { if (x.v > top) top = x.v; });
    top = niceCeil(top * 1.02);
    function barAt(t) {
      for (var i = 0; i < n; i++) if (bars[i].t >= t) return i;
      return -1;
    }
    var L = ladderOf(a, ctx), marks = [];
    for (var i = 0; i <= L.step; i++) {
      var tm = t0 + L.esc[i].after_seconds * 1000, k = tm >= pts[0].t ? barAt(tm) : -1;
      if (k >= 0) marks.push({ x: (k + 0.5) / n * 100, label: actName(L.esc[i].action) });
    }
    /* two rows of labels, so two rungs a minute apart do not print over each other */
    var lastX = [-100, -100];
    marks.forEach(function (mk) {
      mk.row = mk.x - lastX[0] >= 14 ? 0 : mk.x - lastX[1] >= 14 ? 1 : 0;
      lastX[mk.row] = mk.x;
    });

    /* the scale's two lines run the full width, their values in a gutter on
       the right; the bars, the threshold and the rung lines sit in the plot
       beside it, so no label is ever drawn over a bar */
    var chart = h("div", { class: "at-chart" + (marks.length ? " has-marks" : "") + (marks.some(function (mk) { return mk.row; }) ? " has-rows" : "") });
    chart.appendChild(h("div", { class: "at-chart__grid is-top", attrs: { "aria-hidden": "true" } }, h("span", { class: "mono", text: scaleText(top, unit) })));
    chart.appendChild(h("div", { class: "at-chart__grid is-mid", attrs: { "aria-hidden": "true" } }, h("span", { class: "mono", text: scaleText(top / 2, unit) })));
    var plot = h("div", { class: "at-chart__plot" });
    chart.appendChild(plot);
    var span = I.duration((pts[pts.length - 1].t - pts[0].t) / 1000);
    plot.appendChild(h("div", { class: "at-chart__bars", attrs: { role: "img",
      "aria-label": I.t("at.chart.aria", { m: unit, t: targetName(a), d: span, from: fmt(pts[0].v), to: fmt(pts[pts.length - 1].v) }) } },
      bars.map(function (x) {
        var el = h("span", { class: "at-chart__bar" + (x.hot ? " is-attack" : "") });
        el.style.height = Math.max(1, Math.round(x.v / top * 1000) / 10) + "%";
        return el;
      })));
    if (thr) {
      var line = h("div", { class: "at-chart__thr", attrs: { "aria-hidden": "true" } });
      line.style.bottom = Math.round(thr / top * 1000) / 10 + "%";
      plot.appendChild(line);
    }
    marks.forEach(function (mk) {
      var ln = h("div", { class: "at-chart__mark", attrs: { "aria-hidden": "true" } });
      ln.style.left = mk.x + "%";
      var lb = h("span", { class: "at-chart__label mono" + (mk.row ? " is-row2" : "") + (mk.x > 85 ? " is-end" : mk.x < 15 ? " is-start" : ""), attrs: { "aria-hidden": "true" }, text: mk.label });
      lb.style.left = mk.x + "%";
      plot.appendChild(ln);
      plot.appendChild(lb);
    });

    /* five times under the bars, to the second: the window is minutes long,
       and a minute alone would read as going back in time beside them */
    var labels = [];
    [0, 0.25, 0.5, 0.75, 1].forEach(function (q) {
      var s = I.time(new Date(bars[Math.round(q * (n - 1))].t));
      if (labels.indexOf(s) < 0) labels.push(s);
    });
    var axis = h("div", { class: "at-chart__axis mono", attrs: { "aria-hidden": "true" } }, labels.map(function (s) { return h("span", { text: s }); }));
    var legend = h("div", { class: "tr__legend" }, [
      bars.some(function (x) { return !x.hot; }) ? h("span", {}, [h("span", { class: "tr__key" }), I.t("at.leg.before")]) : null,
      bars.some(function (x) { return x.hot; }) ? h("span", {}, [h("span", { class: "tr__key is-attack" }), I.t("at.leg.attack")]) : null,
      thr ? h("span", {}, [h("span", { class: "at-key-thr" }), I.t("at.card.thr", { v: fmt(thr) })]) : null,
      marks.length ? h("span", {}, [h("span", { class: "at-key-mark" }), I.t("at.leg.rung")]) : null
    ]);
    return [chart, axis, legend];
  }

  /* ---------- why it fired ---------- */
  var SHARE_PROTO = { udp_flood: "udp", syn_flood: "tcp", tcp_flood: "tcp", icmp_flood: "icmp" };
  function why(a, ctx) {
    var r = a.reason, kids = [title("at-why-title", "at.why.title")];
    if (!r) { kids.push(note(I.t("at.why.none"))); return section("at-why-title", "at-why", kids); }
    var thr = fmtMetric(a.threshold, a.metric), g = a.group, fm = function (v) { return fmtMetric(v, a.metric); };
    var b = r.threshold_source === "baseline" ? r.baseline : null;
    if (isGroup(a)) kids.push(note(I.t("at.why.group", { g: g, thr: thr })));
    else if (b) {
      var raw = b.normal * b.factor, f = I._nf1.format(b.factor);
      kids.push(note(I.t(raw > b.ceiling ? "at.why.base.ceil" : raw < b.floor ? "at.why.base.floor" : "at.why.base.mid", { f: f, g: g, thr: thr })));
      var rows = [[I.t("at.why.normal"), fm(b.normal)], [I.t("at.why.times", { f: f }), fm(raw)], [I.t("at.why.floor"), fm(b.floor)],
        [I.t("at.why.ceil"), fm(b.ceiling)], [I.t("at.why.eff"), thr, true]];
      kids.push(h("dl", { class: "at-math" }, rows.map(function (row) {
        return h("div", { class: "at-math__row" + (row[2] ? " is-eff" : "") }, [h("dt", { text: row[0] }), h("dd", { class: "mono", text: row[1] })]);
      })));
    } else if (r.warming_up) {
      kids.push(note(I.t("at.why.warm", { g: g, thr: thr, d: I.duration(r.warmup_remaining_seconds || 0) })));
    } else if (r.baseline_configured) {
      kids.push(note(I.t("at.why.static.metric", { m: a.metric, g: g, thr: thr })));
    } else {
      kids.push(note(I.t("at.why.static", { g: g, thr: thr })));
    }

    /* what the traffic was made of: UDP, TCP and ICMP do not overlap, so they
       stack; SYN is part of TCP and fragments cut across both, so they are
       named in the sentence rather than drawn */
    var sh = r.shares || {}, type = a.classification.type, gate = I.pct(r.dominant_share_gate || 0.5);
    var dom = SHARE_PROTO[type] || (/_amplification$/.test(type) ? "udp" : "");
    var parts = [["udp", "UDP"], ["tcp", "TCP"], ["icmp", "ICMP"]].map(function (p) { return { k: p[0], name: p[1], v: sh[p[0]] || 0 }; })
      .filter(function (p) { return p.v >= 0.005; });
    var rest = 1 - parts.reduce(function (s, p) { return s + p.v; }, 0);
    if (parts.length && rest >= 0.005) parts.push({ k: "other", name: I.t("at.why.mix.other"), v: rest });
    if (parts.length) {
      var bar = h("div", { class: "at-mix", attrs: { role: "img", "aria-label": parts.map(function (p) { return p.name + " " + I.pct(p.v); }).join(", ") } },
        parts.map(function (p) {
          var s = h("span", { class: "at-mix__part" + (p.k === dom ? " is-attack" : p.k === "other" ? " is-other" : "") });
          s.style.width = (p.v * 100).toFixed(1) + "%";
          return s;
        }));
      var keys = h("div", { class: "at-mix__keys" }, parts.map(function (p) {
        return h("span", { class: "at-mix__key" + (p.k === dom ? "" : " is-muted") }, [
          h("span", { class: "at-mix__sw" + (p.k === dom ? " is-attack" : p.k === "other" ? " is-other" : ""), attrs: { "aria-hidden": "true" } }),
          p.name + " ", h("span", { class: "mono", text: I.pct(p.v) })
        ]);
      }));
      var say;
      if (type === "mixed") say = I.t("at.why.mix.mixed", { gate: gate });
      else if (a.classification.src_port) say = I.t("at.why.mix.amp", { p: I.pct(a.classification.confidence || 0), port: a.classification.src_port, type: I.label("attackType", type) });
      else {
        var key = type === "syn_flood" ? ["SYN", sh.syn] : type === "fragment_flood" ? [I.t("at.why.frags"), sh.frag] : dom ? [dom.toUpperCase(), sh[dom]] : null;
        say = key ? I.t("at.why.mix.dom", { name: key[0], p: I.pct(key[1] || 0), gate: gate, type: I.label("attackType", type) }) : "";
      }
      kids.push(h("div", { class: "at-sec" }, [h("h3", { class: "at-sec__title", text: I.t("at.why.mix.title") }), bar, keys, say ? note(say) : null]));
    }
    return section("at-why-title", "at-why", kids);
  }

  /* ---------- what Kapkan did ---------- */
  function steps(a, ctx) {
    var L = ladderOf(a, ctx), t0 = startedMs(a), e = a.active ? null : endOf(a, ctx);
    var notify = ctx.status.notify || {};
    var via = Object.keys(notify).filter(function (k) { return notify[k]; }).map(cap);
    var detect = I.t("at.step.detect", { type: I.label("attackType", a.classification.type), thr: fmtMetric(a.threshold, a.metric) }) + " " +
      (via.length ? I.t("at.step.told.via", { list: via.join(", ") }) : I.t("at.step.told"));
    var items = [];
    var rejected = a.ban_state === "rejected" || (e && e.ban && e.ban.state === "rejected");
    var last = isGroup(a) || rejected ? 0 : a.active ? L.esc.length - 1 : L.step;
    for (var i = 0; i <= last; i++) {
      var st = L.esc[i], at = t0 + st.after_seconds * 1000, state = i < L.step || (!a.active && i === L.step) ? "done" : i === L.step ? "now" : "next";
      var text = [];
      if (i === 0) text.push(detect);
      if (state === "now") {
        if (st.action !== "none" && ACT[st.action]) text.push(cap(I.t(ACT[st.action].now)) + ".");
        if (!nextRung(a) && (st.action !== "none" || i > 0)) text.push(I.t("at.step.hold"));
      } else if (state === "next") {
        text.push(ACT[st.action] ? I.t(ACT[st.action].plan) + "," : "");
        text.push(I.t("at.step.future"));
      } else if (i < L.step) {
        text.push(I.t("at.step.notcalm", { d: delayText(L.esc[i + 1].after_seconds - st.after_seconds) }));
      }
      if (i === 0 && isGroup(a)) text.push(I.t("at.step.group"));
      items.push({ n: String(i + 1), name: actName(st.action), time: I.time(new Date(at)), note: text.filter(Boolean).join(" "), state: state, tone: toneOf(st.action) });
    }
    if (rejected) items.push({ n: "!", name: cap(I.t("at.end.rejected")), time: "", note: rejectWhy(e && e.ban ? e.ban : banOf(a, ctx)), state: "end", tone: "alert" });
    if (!a.active) items.push({ n: "✓", name: I.t("at.step.end"), time: I.time(new Date(endedMs(a))), note: e && !rejected && e.note ? cap(e.note) + "." : "", state: "end", tone: "calm" });

    var list = h("ol", { class: "at-steps-list" }, items.map(function (it, k) {
      return h("li", { class: "at-step is-" + it.state }, [
        h("div", { class: "at-step__rail" }, [
          h("span", { class: "at-step__dot tone-" + it.tone, attrs: { "aria-hidden": "true" }, text: it.n }),
          k < items.length - 1 ? h("span", { class: "at-step__line", attrs: { "aria-hidden": "true" } }) : null
        ]),
        h("div", { class: "at-step__body" }, [
          h("div", { class: "at-step__head" }, [h("span", { class: "at-step__name", text: it.name }), it.time ? h("span", { class: "at-step__time mono", text: it.time }) : null]),
          it.note ? h("div", { class: "at-step__note", text: it.note }) : null
        ])
      ]);
    }));
    return section("at-steps-title", "at-steps-card", [title("at-steps-title", "at.steps.title"), list]);
  }
  function rejectWhy(b) {
    var key = b && { whitelisted: "reject.whitelisted", outside_networks: "reject.outside", cap: "reject.cap" }[b.reason];
    return key ? I.t(key) : (b && b.reason) || "";
  }

  /* ---------- the mitigation now, or how it ended ---------- */
  var MIT_TEXT = { blackhole: "at.mit.blackhole", flowspec: "at.mit.flowspec", dataplane: "at.mit.dataplane", divert: "at.mit.divert" };
  function mitigation(a, ctx) {
    var id = "at-mit-title";
    if (!a.active) {
      var e = endOf(a, ctx), kids = [title(id, "at.col.end", [chip(e.method)])];
      if (e.note) kids.push(note(cap(e.note) + "."));
      if (e.method === "dataplane" && a.dataplane) kids.push(K.kernelRules(a));
      return section(id, "at-mit", kids);
    }
    var prot = isGroup(a) ? "none" : protOf(a, ctx), ban = null;
    ctx.bans.active.forEach(function (b) { if (b.target === a.target) ban = b; });
    var kids2 = [title(id, "at.mit.title", [chip(prot)])];
    if (prot === "none") {
      var nx = nextRung(a);
      kids2.push(note(I.t(isGroup(a) ? "at.mit.group" : "at.mit.none")));
      if (nx) kids2.push(h("p", { class: "at-note" }, [I.t("at.mit.next", { action: actName(nx.action), t: I.time(new Date(nx.atMs)) }) + " ", countdown(nx.atMs)]));
      else if (!isGroup(a)) kids2.push(note(I.t("at.mit.top", { g: a.group })));
      return section(id, "at-mit", kids2);
    }
    kids2.push(note(MIT_TEXT[prot] ? I.t(MIT_TEXT[prot]) : actName(prot)));
    if (prot === "dataplane") kids2.push(K.kernelRules(a));
    else {
      var lines = [];
      if (a.flowspec && a.flowspec.length) a.flowspec.forEach(function (r) { lines.push(r.match + " → " + r.action); });
      else {
        lines.push(a.target + (ban && ban.prefix ? ban.prefix : ""));
        if (a.next_hop) lines.push(pad("next-hop") + a.next_hop);
        if (a.community) lines.push(pad("community") + a.community);
        if (a.local_pref != null) lines.push(pad("local-pref") + a.local_pref);
      }
      kids2.push(h("pre", { class: "at-route mono", text: lines.join("\n") }));
    }
    var L = ladderOf(a, ctx), since = startedMs(a) + L.esc[L.step].after_seconds * 1000, dry = ban ? ban.dry_run : a.dry_run;
    var rows = [];
    if (prot === "dataplane") rows.push([I.t("at.mit.k.rules"), I.t(dry ? "at.mit.notinstalled" : "at.mit.installed", { t: I.time(new Date(since)) })]);
    else {
      var peers = ctx.status.bgp && ctx.status.bgp.neighbors ? ctx.status.bgp.neighbors : [];
      rows.push([I.t("at.mit.k.sent"), I.t(dry ? "at.mit.notsent" : "at.mit.sent", { t: I.time(new Date(since)) }), dry ? "elev" : null]);
      rows.push([I.t("at.mit.k.peers"), peers.length ? peers.join(", ") : I.t("at.mit.nopeers"), null, peers.length > 0]);
    }
    if (ban && ban.node) rows.push([I.t("at.mit.k.node"), ban.node, null, true]);
    if (ban && ban.expires_at) rows.push([I.t("at.mit.k.until"), I.t("at.mit.until", { t: I.time(new Date(ban.expires_at)) })]);
    if (ban && ban.fell_back_from) rows.push([I.t("at.mit.k.fellback"), I.t("at.mit.fellback", { m: actName(ban.fell_back_from), why: ban.fell_back_reason || "" })]);
    kids2.push(h("dl", { class: "at-kv" }, rows.map(function (row) {
      return h("div", { class: "at-kv__row" }, [
        h("dt", { text: row[0] }),
        h("dd", { class: row[3] ? "mono" : null }, [row[2] ? h("span", { class: "at-kv__dot tone-" + row[2], attrs: { "aria-hidden": "true" } }) : null, row[1]])
      ]);
    })));
    return section(id, "at-mit", kids2);
  }
  function pad(k) { return (k + "            ").slice(0, 12); }

  /* ---------- where it comes from ---------- */
  function sources(a, ctx) {
    var s = a.sample, out = a.direction === "outgoing", id = "at-src-title";
    var kids = [title(id, out ? "at.src.title.out" : "at.src.title")];
    if (!s || !s.top_sources || !s.top_sources.length) {
      kids.push(note(I.t(s ? "at.src.none" : "at.src.nosample")));
      return section(id, "at-src", kids);
    }
    var total = s.total_packets || s.top_sources.reduce(function (m, x) { return m + (x.packets || 0); }, 0) || 1;
    kids.push(h("p", { class: "ov-card__sub", text: I.t("at.src.sub") }));
    kids.push(h("ul", { class: "at-src__list" }, s.top_sources.slice(0, 5).map(function (x) {
      var share = (x.packets || 0) / total, fill = h("span", { class: "at-src__fill" });
      fill.style.width = Math.max(1, Math.min(100, share * 100)).toFixed(1) + "%";
      return h("li", { class: "at-src__row" }, [
        h("div", { class: "at-src__line mono" }, [h("span", { text: x.key }), h("span", { class: "at-src__pct", text: I.pct(share) })]),
        h("span", { class: "at-src__bar", attrs: { "aria-hidden": "true" } }, fill)
      ]);
    })));
    if (s.top_asns && s.top_asns.length) {
      kids.push(h("div", { class: "at-sec" }, [
        h("h3", { class: "at-sec__title", text: I.t("at.src.asns") }),
        h("div", { class: "at-asns" }, s.top_asns.slice(0, 5).map(function (x) {
          return h("span", { class: "at-asn mono" }, [x.key + " ", h("span", { class: "at-asn__pct", text: I.pct((x.packets || 0) / total) })]);
        }))
      ]));
    }
    return section(id, "at-src", kids);
  }

  /* ---------- the sampled flows ---------- */
  var FLOW_ROWS = 10;
  function flows(a, ctx) {
    var s = a.sample;
    if (!s || !s.flows || !s.flows.length) return null;
    var expanded = ctx.state.expanded.has("atk:flows"), list = expanded ? s.flows : s.flows.slice(0, FLOW_ROWS);
    var total = s.total_packets || 0, sub = [I.plural(s.flows.length, "atFlowRecords")];
    if (total && s.top_dst_ports && s.top_dst_ports.length) {
      sub.push(I.t("at.flows.ports", { list: s.top_dst_ports.slice(0, 3).map(function (p) { return p.key + " — " + I.pct((p.packets || 0) / total); }).join(", ") }));
    }
    var rates = {};
    s.flows.forEach(function (f) { if (f.sampling_rate > 1) rates[f.sampling_rate] = true; });
    var rk = Object.keys(rates);
    if (rk.length === 1) sub.push(I.t("at.flows.sampling", { n: I.num(Number(rk[0])) }));
    var th = function (k, cls) { return h("th", { class: cls || null, attrs: { scope: "col" }, text: I.t(k) }); };
    var rows = list.map(function (f) {
      var src = [h("span", { text: f.src })];
      if (f.src_country) src.push(h("span", { class: "at-geo", attrs: { title: f.src_org || "" }, text: f.src_country }));
      return h("tr", {}, [
        h("td", {}, src),
        h("td", { class: "at-tbl__muted", text: String(f.src_port) }),
        h("td", { text: f.dst + ":" + f.dst_port }),
        h("td", {}, [f.proto, f.flags ? h("span", { class: "at-tbl__muted", text: " " + f.flags }) : null, f.fragment ? h("span", { class: "at-tbl__muted", text: " frag" }) : null]),
        h("td", { class: "num", text: I.num(f.packets || 0) }),
        h("td", { class: "num", text: K.bytesFmt(f.bytes) })
      ]);
    });
    var kids = [
      h("div", { class: "ov-card__head" }, h("div", {}, [
        h("h2", { class: "ov-card__title", id: "at-flows-title", text: I.t("at.flows.title") }),
        h("p", { class: "ov-card__sub", text: sub.join(" · ") })
      ])),
      h("div", { class: "at-tbl__wrap" }, h("table", { class: "at-tbl at-tbl--flows mono" }, [
        h("thead", {}, h("tr", {}, [th("at.col.src"), th("at.col.sport"), th("at.col.dst"), th("at.col.proto"), th("at.col.pkts", "num"), th("at.col.bytes", "num")])),
        h("tbody", {}, rows)
      ]))
    ];
    if (s.flows.length > FLOW_ROWS) {
      kids.push(h("button", { class: "btn btn--ghost btn--sm at-more", attrs: { type: "button" },
        text: expanded ? I.t("at.less") : I.t("at.all", { n: I.num(s.flows.length) }), onclick: function () { ctx.actions.toggleHost("atk:flows"); } }));
    }
    return section("at-flows-title", "at-flows", kids);
  }

  /* ---------- the summary, for a ticket or a chat ---------- */
  function copySummary(a, ctx) {
    var group = isGroup(a), type = I.label("attackType", a.classification.type), t0 = new Date(startedMs(a));
    var lines = [I.t(group ? "at.p.title.group" : "at.p.title", { type: type, t: targetOf(a) }) + " · " +
      (group ? I.t("at.card.sum") : I.t("at.card.group", { g: a.group })) + " · " + I.t(a.direction === "outgoing" ? "at.dir.out" : "at.dir.in")];
    if (a.active) {
      lines.push(I.t("at.copy.since", { t: whenText(t0.getTime(), true), d: I.duration((Date.now() - t0.getTime()) / 1000) }));
      var r = a.rates || {}, m = mult(a);
      lines.push(I.t("at.copy.rate", { rate: I.pps(r.pps || 0) + " · " + I.mbps(r.mbps || 0), m: m != null ? multText(m) + "×" : "—", thr: fmtMetric(a.threshold, a.metric) }));
      var prot = group ? "none" : protOf(a, ctx);
      lines.push(I.t("at.copy.prot", { name: actName(prot), what: group ? I.t("at.rung.group") : ACT[prot] ? I.t(ACT[prot].now) : "" }));
    } else {
      var e = endOf(a, ctx);
      lines.push(I.t("at.copy.ended", { t0: whenText(t0.getTime(), true), t1: whenText(endedMs(a), true), d: I.duration((endedMs(a) - t0.getTime()) / 1000) }));
      lines.push(I.t("at.copy.end", { name: actName(e.method), what: e.note || "—" }));
    }
    var s = a.sample;
    if (s && s.top_sources && s.top_sources.length) {
      var total = s.total_packets || 1;
      lines.push(I.t(a.direction === "outgoing" ? "at.copy.dst" : "at.copy.src", { list: s.top_sources.slice(0, 3).map(function (x) { return x.key + " " + I.pct((x.packets || 0) / total); }).join(", ") }));
    }
    copyText(lines.join("\n")).then(function (ok) { K.toast(I.t(ok ? "at.copy.ok" : "at.copy.fail"), ok ? "ok" : "err"); });
  }
  /* The clipboard API is there only in a secure context, and a kapkan is
     often reached over plain http on a private address: there the old
     select-and-copy still works. */
  function copyText(s) {
    function legacy() {
      var ta = h("textarea", { class: "at-clip", attrs: { readonly: "", "aria-hidden": "true" } });
      ta.value = s;
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      return ok;
    }
    if (w.navigator.clipboard && w.isSecureContext) return w.navigator.clipboard.writeText(s).then(function () { return true; }, legacy);
    return Promise.resolve(legacy());
  }

  /* ===================== the page ===================== */
  function attackPage(root, ctx) {
    var a = findAttack(ctx, ctx.state.attackKey);
    if (!a) {
      K.mount(root, [crumbs(ctx, null), h("section", { class: "ov-card at-calm" }, [
        h("h1", { class: "at-calm__title", text: I.t("at.p.gone.title") }),
        h("p", { class: "ov-card__sub", text: I.t("at.p.gone.sub") }),
        h("div", {}, h("button", { class: "btn btn--ghost btn--sm", attrs: { type: "button" }, text: I.t("ov.at.all"), onclick: function () { ctx.actions.setView("attacks"); } }))
      ])]);
      return;
    }
    K.mount(root, [
      crumbs(ctx, a),
      pageHead(a, ctx),
      h("div", { class: "ov-row" }, [force(a, ctx), why(a, ctx)]),
      h("div", { class: "ov-row" }, [steps(a, ctx), mitigation(a, ctx), sources(a, ctx)]),
      flows(a, ctx)
    ]);
  }

  V.attacks = attacks;
  V.attack = attackPage;
})(window);
