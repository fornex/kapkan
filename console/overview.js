/* overview.js — the Overview: what is happening, in plain words, in three
   seconds. Replaces views.js's posture banner and stats grid.

   Everything here is read from what the console already polls (status,
   attacks, hosts, bans) — no new endpoint. Where the API does not know a
   thing (BGP session state, a day of history), the screen says what it does
   know and never dresses a guess up as a status: a dot is green only for
   something measured. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h, V = w.Views;

  /* ---------- the actions, in one place ----------
     The rung an address stands on decides how it is protected. The tone is
     the escalation ramp's colour slot (style.css --rung-N), shared with the
     ladder so a colour means the same thing on every screen; 0 is "not yet
     acted on". An action this console does not know (a newer kapkan) keeps
     its raw name and a neutral tone rather than borrowing another's. */
  var ACT = {
    none:      { tone: 0, name: "ov.act.none",      plan: "ov.plan.none",      now: "ov.now.none" },
    flowspec:  { tone: 2, name: "ov.act.flowspec",  plan: "ov.plan.flowspec",  now: "ov.now.flowspec" },
    divert:    { tone: 3, name: "ov.act.divert",    plan: "ov.plan.divert",    now: "ov.now.divert" },
    dataplane: { tone: 5, name: "ov.act.dataplane", plan: "ov.plan.dataplane", now: "ov.now.dataplane" },
    blackhole: { tone: 4, name: "ov.act.blackhole", plan: "ov.plan.blackhole", now: "ov.now.blackhole" }
  };
  /* the protection rows, mildest first; "none" is the empty part of the ring */
  var PROT_ROWS = ["none", "flowspec", "dataplane", "divert", "blackhole"];
  function actName(act) { return ACT[act] ? I.t(ACT[act].name) : I.label("action", act); }
  function actTone(act) { return ACT[act] ? ACT[act].tone : 0; }

  /* the attack's target as the operator knows it */
  function targetOf(a) { return a.scope === "group" ? a.group : a.target; }
  function mult(a) { return a.threshold ? a.rate / a.threshold : null; }
  function multText(m) { return m >= 10 ? I.num(Math.round(m)) : I._nf1.format(m); }
  function startedMs(a) { return new Date(a.started_at).getTime(); }

  /* The protection an attacked address has right now: the method of its live
     ban — what the engine actually put in place, after any fallback — or
     "none" while the ladder is still on its alert rung. */
  function protOf(a, ctx) {
    var bans = ctx.bans.active;
    for (var i = 0; i < bans.length; i++) {
      if (bans[i].target === a.target) return bans[i].method || "none";
    }
    return "none";
  }
  /* The bans that mitigate. On a ladder's alert rung the engine already holds
     a ban for the target, with no method: it reports, it drops nothing, so it
     is counted as unprotected, never as mitigation. */
  function mitigating(ctx) {
    return ctx.bans.active.filter(function (b) { return b.method && b.method !== "none"; });
  }
  /* the next rung and when it fires, or null at the top of the ladder */
  function nextRung(a) {
    var esc = a.escalation || [], step = a.escalation_step || 0;
    if (!a.active || step + 1 >= esc.length) return null;
    return { action: esc[step + 1].action, atMs: startedMs(a) + esc[step + 1].after_seconds * 1000 };
  }
  /* a live countdown: app.js's 1s tick rewrites every [data-cd-target] */
  function countdown(atMs) {
    return h("span", { class: "mono", dataset: { cdTarget: atMs }, text: I.countdown((atMs - Date.now()) / 1000) });
  }

  /* I.mbps / I.pps render "9.8 Gb/s"; the big numbers set the unit smaller */
  function splitUnit(s) {
    var i = s.lastIndexOf(" ");
    return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)];
  }
  /* a span of time as one big number and its unit: minutes, hours, days */
  function spanParts(sec) {
    sec = Math.max(0, sec);
    if (sec < 3600) return [I.num(Math.max(1, Math.floor(sec / 60))), I.t("ov.unit.min")];
    if (sec < 172800) return [I.num(Math.floor(sec / 3600)), I.t("ov.unit.h")];
    return [I.num(Math.floor(sec / 86400)), I.t("ov.unit.d")];
  }
  function bigNum(value, unit, caption) {
    return h("div", { class: "hero__num" }, [
      h("div", { class: "hero__fig" }, [h("span", { class: "hero__big", text: value }), unit ? h("span", { class: "hero__unit", text: unit }) : null]),
      h("div", { class: "hero__cap", text: caption })
    ]);
  }
  function arrowBtn(label, onclick) {
    return h("button", { class: "icon-btn icon-btn--sm ov-go", attrs: { type: "button", "aria-label": label, title: label }, onclick: onclick }, w.icon("arrow-ne"));
  }
  function goSection(ctx, id) { return function () { ctx.actions.setSection(id); }; }

  /* ===================== the hero ===================== */
  function hero(ctx) {
    var active = ctx.attacks.active;
    var body = active.length ? heroAttack(ctx, active) : heroCalm(ctx);
    return h("section", { class: "hero", attrs: { "aria-labelledby": "ov-hero-title" } }, body);
  }

  function heroAttack(ctx, active) {
    var first = active.reduce(function (m, a) { return Math.min(m, startedMs(a)); }, Infinity);
    var n = active.length, groupScoped = active.some(function (a) { return a.scope === "group"; });
    var mitigated = active.filter(function (a) { return protOf(a, ctx) !== "none"; }).length;
    var sub;
    if (n === 1) sub = I.t(mitigated ? "ov.hero.sub.one.mit" : "ov.hero.sub.one.watch");
    else if (mitigated === n) sub = I.t("ov.hero.sub.all");
    else if (mitigated === 0) sub = I.t("ov.hero.sub.none");
    else sub = I.t("ov.hero.sub.some", { m: I.num(mitigated), n: I.num(n) });
    if (ctx.dryRun) sub += " " + I.t("ov.hero.sub.dry");

    var bps = splitUnit(I.mbps(ctx.agg.in_mbps)), pps = splitUnit(I.pps(ctx.agg.in_pps));
    var dur = spanParts((Date.now() - first) / 1000);
    var left = h("div", { class: "hero__main" }, [
      h("div", { class: "hero__lead" }, [h("span", { class: "hero__dot is-attack", attrs: { "aria-hidden": "true" } }), I.t("ov.hero.since", { t: I.time(new Date(first)) })]),
      h("div", {}, [
        h("h1", { class: "hero__title", id: "ov-hero-title", text: groupScoped ? I.plural(n, "ovHeroAttacks") : I.plural(n, "ovHeroTargets") }),
        h("p", { class: "hero__sub", text: sub })
      ]),
      h("div", { class: "hero__nums" }, [
        bigNum(bps[0], bps[1], I.t("ov.num.inbound")),
        bigNum(pps[0], pps[1], I.t("ov.num.pps")),
        bigNum(dur[0], dur[1], I.t("ov.num.duration"))
      ]),
      h("div", { class: "hero__actions" }, [
        h("button", { class: "btn hero__btn", attrs: { type: "button" }, onclick: goSection(ctx, "attacks") }, [h("span", { text: I.t("ov.btn.attacks") }), w.icon("arrow-right")]),
        h("button", { class: "btn hero__btn hero__btn--ghost", attrs: { type: "button" }, onclick: goSection(ctx, "mitigation"), text: I.t("nav.bans") })
      ])
    ]);
    return h("div", { class: "hero__grid" }, [left, protection(ctx, active)]);
  }

  /* "How the attacked addresses are protected": one ring, four steps. It
     scales from one address to twenty without changing shape; the addresses
     themselves are in Attacks. In watch-only it is what WOULD be in place. */
  function protection(ctx, active) {
    var counts = {}, soonest = null;
    active.forEach(function (a) {
      var p = protOf(a, ctx);
      counts[p] = (counts[p] || 0) + 1;
      if (p === "none") {
        var nx = nextRung(a);
        if (nx && (!soonest || nx.atMs < soonest.atMs)) soonest = nx;
      }
    });
    var total = active.length, none = counts.none || 0;
    /* known rows always (a zero is information: "no XDP yet"), divert only
       where something uses it, then any action this console does not know */
    var rows = PROT_ROWS.filter(function (p) { return p !== "divert" || counts.divert; });
    Object.keys(counts).forEach(function (p) { if (rows.indexOf(p) < 0) rows.push(p); });

    var C = 2 * Math.PI * 58, pos = 0, segs = [];
    rows.forEach(function (p) {
      var c = counts[p] || 0;
      if (p === "none" || !c) return;
      var len = C * c / total;
      segs.push(K.svg("circle", { cx: 74, cy: 74, r: 58, class: "donut__seg tone-" + actTone(p),
        "stroke-dasharray": Math.max(0, len - 4).toFixed(2) + " " + (C - len + 4).toFixed(2),
        "stroke-dashoffset": (-(pos + 2)).toFixed(2) }));
      pos += len;
    });
    var aria = I.t("ov.prot.aria", { n: I.num(total), list: rows.map(function (p) { return actName(p) + ": " + I.num(counts[p] || 0); }).join(", ") });
    var ring = h("div", { class: "donut" }, [
      K.svg("svg", { viewBox: "0 0 148 148", width: 148, height: 148, role: "img", "aria-label": aria },
        [K.svg("circle", { cx: 74, cy: 74, r: 58, class: "donut__track" })].concat(segs)),
      h("div", { class: "donut__mid", attrs: { "aria-hidden": "true" } }, [
        h("span", { class: "donut__n" + (none ? " is-attack" : ""), text: I.num(none) }),
        h("span", { class: "donut__cap" }, [I.t("ov.prot.of", { n: I.num(total) }), h("br"), I.t("ov.prot.unprotected")])
      ])
    ]);
    var list = h("ul", { class: "prot" }, rows.map(function (p) {
      var c = counts[p] || 0, label = [h("span", { text: p === "none" ? I.t("ov.prot.unprotected.row") : actName(p) })];
      if (p === "none" && c && soonest) {
        label.push(h("br"));
        label.push(h("span", { class: "prot__sub" }, [I.t("ov.prot.nextin", { action: actName(soonest.action) }) + " ", countdown(soonest.atMs)]));
      }
      return h("li", { class: "prot__row" + (c ? "" : " is-zero") }, [
        h("span", { class: "prot__key tone-" + actTone(p) + (p === "none" ? " is-ring" : ""), attrs: { "aria-hidden": "true" } }),
        h("span", { class: "prot__label" }, label),
        h("span", { class: "prot__n" + (p === "none" && c ? " is-attack" : ""), text: I.num(c) })
      ]);
    }));
    return h("div", { class: "hero__panel" }, [
      h("h2", { class: "hero__h2", text: I.t(ctx.dryRun ? "ov.prot.title.dry" : "ov.prot.title") }),
      h("div", { class: "prot__body" }, [ring, list])
    ]);
  }

  function heroCalm(ctx) {
    var hosts = ctx.hosts, nets = ctx.networks;
    var lastEnd = ctx.attacks.recent.reduce(function (m, a) { return a.ended_at ? Math.max(m, new Date(a.ended_at).getTime()) : m; }, 0);
    var quietSec = lastEnd ? (Date.now() - lastEnd) / 1000 : ctx.status.uptime_seconds;
    var sub;
    if (!hosts.length) sub = I.t("ov.calm.sub.empty");
    else if (nets.length) sub = I.t("ov.calm.sub", { hosts: I.plural(hosts.length, "ovCalmHosts"), nets: I.plural(nets.length, "ovCalmNets") });
    else sub = I.t("ov.calm.sub.nonets", { hosts: I.plural(hosts.length, "ovCalmHosts") });

    var learned = hosts.length ? hosts.filter(function (x) { return x.baseline; }).length / hosts.length : 0;
    var bps = splitUnit(I.mbps(ctx.agg.in_mbps)), pps = splitUnit(I.pps(ctx.agg.in_pps));
    var left = h("div", { class: "hero__main" }, [
      h("div", { class: "hero__lead", text: I.t(lastEnd ? "ov.calm.lead" : "ov.calm.lead.start", { t: I.duration(quietSec) }) }),
      h("div", {}, [
        h("h1", { class: "hero__title", id: "ov-hero-title", text: I.t("ov.calm.title") }),
        h("p", { class: "hero__sub", text: sub })
      ]),
      h("div", { class: "hero__nums" }, [
        bigNum(bps[0], bps[1], I.t("ov.num.inbound")),
        bigNum(pps[0], pps[1], I.t("ov.num.pps")),
        bigNum(I.num(Math.round(learned * 100)), "%", I.t("ov.num.learned"))
      ]),
      h("div", { class: "hero__actions" }, [
        h("button", { class: "btn hero__btn", attrs: { type: "button" }, onclick: goSection(ctx, "hosts") }, [h("span", { text: I.t("ov.btn.hosts") }), w.icon("arrow-right")]),
        h("button", { class: "btn hero__btn hero__btn--ghost", attrs: { type: "button" }, onclick: goSection(ctx, "attacks"), text: I.t("ov.btn.past") })
      ])
    ]);
    return h("div", { class: "hero__grid" }, [left, plan(ctx)]);
  }

  /* "If an attack starts": the ladder of the group most hosts are in, in
     words. The other groups' ladders are in Settings. */
  function plan(ctx) {
    var groups = ctx.groups || [];
    var byHosts = {};
    ctx.hosts.forEach(function (x) { byHosts[x.group] = (byHosts[x.group] || 0) + 1; });
    var g = groups.slice().sort(function (a, b) { return (byHosts[b.name] || 0) - (byHosts[a.name] || 0); })[0];
    var kids = [
      h("h2", { class: "hero__h2", text: I.t("ov.plan.title") }),
      h("p", { class: "hero__note", text: I.t("ov.plan.sub") })
    ];
    if (!g) {
      kids.push(h("p", { class: "hero__note", text: I.t("ov.plan.nogroups") }));
      return h("div", { class: "hero__panel" }, kids);
    }
    var steps = g.escalation && g.escalation.length ? g.escalation : [{ after_seconds: 0, action: g.mitigation || "none" }];
    var notify = ctx.status.notify || {};
    var via = Object.keys(notify).filter(function (k) { return notify[k]; }).map(function (k) { return k.charAt(0).toUpperCase() + k.slice(1); });
    kids.push(h("ol", { class: "plan" }, steps.map(function (s) {
      var what;
      if (s.action === "none") what = [via.length ? I.t("ov.plan.none.via", { list: via.join(", ") }) : I.t("ov.plan.none")];
      else what = [ACT[s.action] ? I.t(ACT[s.action].plan) : I.label("action", s.action), " ", h("span", { class: "hero__muted", text: "(" + actName(s.action) + ")" })];
      return h("li", { class: "plan__row" }, [h("span", { class: "plan__when", text: delayText(s.after_seconds) }), h("span", {}, what)]);
    })));
    var foot = I.t("ov.plan.group", { g: g.name });
    if (groups.length > 1) foot += " " + I.plural(groups.length - 1, "ovPlanOtherGroups");
    kids.push(h("p", { class: "hero__note hero__foot", text: foot }));
    return h("div", { class: "hero__panel" }, kids);
  }
  function delayText(sec) {
    if (!sec) return I.t("ov.plan.now");
    if (sec % 60 === 0) return I.t("ov.plan.min", { n: I.num(sec / 60) });
    return I.t("ov.plan.sec", { n: I.num(sec) });
  }

  /* ===================== the chronicle =====================
     What Kapkan did and when, newest first, rebuilt each poll from the attacks
     and bans the console already holds: a detection, every rung the ladder
     reached (start + its after_seconds), an attack's end and a ban withdrawn.
     Nothing here is inferred beyond those timestamps. */
  var JR_MAX = 7;
  function chronicle(ctx) {
    var ev = [];
    ctx.attacks.active.concat(ctx.attacks.recent).forEach(function (a) {
      var t0 = startedMs(a), tgt = targetOf(a), esc = a.escalation || [], step = a.escalation_step || 0;
      var m = mult(a);
      var detail = (m != null ? I.t("ov.jr.detected.d", { mult: multText(m), metric: a.metric || "", group: a.group || "" }) : "");
      if (esc.length && esc[0].action === "none" && step === 0 && a.active) detail += " · " + I.t("ov.jr.alertonly");
      ev.push({ t: t0, tone: "attack", lead: I.t("ov.jr.detected", { type: I.label("attackType", a.classification.type) }), ip: tgt, detail: detail });
      for (var i = 1; i <= Math.min(step, esc.length - 1); i++) {
        var act = esc[i].action;
        ev.push({ t: t0 + esc[i].after_seconds * 1000, tone: actTone(act), lead: I.t("ov.jr.rung", { action: actName(act) }), ip: tgt,
          detail: (ACT[act] ? I.t(ACT[act].now) : "") + " · " + I.t("ov.jr.step", { i: I.num(i + 1), n: I.num(esc.length) }) });
      }
      if (!a.active && a.ended_at) {
        var t1 = new Date(a.ended_at).getTime();
        ev.push({ t: t1, tone: "calm", lead: I.t("ov.jr.ended"), ip: tgt,
          detail: I.label("attackType", a.classification.type) + " · " + I.duration((t1 - t0) / 1000) });
      }
    });
    ctx.bans.history.forEach(function (b) {
      if (!b.withdrawn_at) return;
      var t = new Date(b.withdrawn_at).getTime();
      if (!(t > 0)) return;
      ev.push({ t: t, tone: "calm", lead: I.t("ov.jr.withdrawn"), ip: b.target, detail: b.method ? actName(b.method) : "" });
    });
    ev.sort(function (a, b) { return b.t - a.t; });
    var shown = ev.slice(0, JR_MAX);

    var head = h("div", { class: "ov-card__head" }, [
      h("div", {}, [
        h("h2", { class: "ov-card__title", id: "ov-jr-title", text: I.t("ov.jr.title") }),
        shown.length ? h("p", { class: "ov-card__sub", text: I.t("ov.jr.sub", { t: I.duration((Date.now() - shown[shown.length - 1].t) / 1000) }) }) : null
      ]),
      arrowBtn(I.t("ov.jr.more"), goSection(ctx, "attacks"))
    ]);
    var body = shown.length
      ? h("ol", { class: "jr" }, shown.map(function (e) {
          return h("li", { class: "jr__row" }, [
            h("span", { class: "jr__time mono", text: I.time(new Date(e.t)) }),
            h("span", { class: "jr__dot tone-" + e.tone, attrs: { "aria-hidden": "true" } }),
            h("div", { class: "jr__what" }, [
              h("div", {}, [e.lead + " ", h("span", { class: "mono", text: e.ip })]),
              e.detail ? h("div", { class: "jr__detail", text: e.detail }) : null
            ])
          ]);
        }))
      : h("p", { class: "ov-card__empty", text: I.t("ov.jr.empty") });
    return h("section", { class: "ov-card ov-jr", attrs: { "aria-labelledby": "ov-jr-title" } }, [head, body]);
  }

  /* ===================== inbound traffic =====================
     The aggregate inbound rate since this page opened (app.js keeps fifteen
     minutes of 3s samples), as bars: red where an attack was on, the last
     one marked. The dashed line is the sum of the hosts' learned baselines —
     "usually" — drawn only where there are baselines to sum. */
  var TR_BARS = 60;
  function traffic(ctx) {
    var b = ctx.buf, unit = ctx.state.ovUnit === "pps" ? "pps" : "bps";
    var series = unit === "pps" ? b.ovInPps : b.ovIn, times = b.ovT, hot = b.ovHot;
    var pts = [];
    for (var i = 0; i < series.length; i++) if (times[i]) pts.push({ v: series[i] || 0, t: times[i], hot: !!hot[i] });
    var now = unit === "pps" ? ctx.agg.in_pps : ctx.agg.in_mbps;
    var fmt = unit === "pps" ? function (v) { return I.pps(v); } : function (v) { return I.mbps(v); };

    var base = 0;
    ctx.hosts.forEach(function (x) {
      if (!x.baseline) return;
      base += unit === "pps" ? (x.baseline.pps || 0) : (x.baseline.mbps || 0);
    });

    var chip = null;
    if (base > 0) {
      var r = now / base;
      if (r >= 2) chip = h("span", { class: "ov-chip is-attack" }, [h("span", { class: "ov-chip__dot" }), I.plural(Math.round(r), "ovTrAbove")]);
      else if (r < 0.5) chip = h("span", { class: "ov-chip" }, [h("span", { class: "ov-chip__dot" }), I.t("ov.tr.below")]);
      else chip = h("span", { class: "ov-chip is-calm" }, [h("span", { class: "ov-chip__dot" }), I.t("ov.tr.usual")]);
    }
    var big = splitUnit(fmt(now));
    var seg = h("div", { class: "seg", attrs: { role: "group", "aria-label": I.t("ov.tr.units") } }, ["bps", "pps"].map(function (u) {
      var on = u === unit;
      return h("button", { class: "seg__btn" + (on ? " is-on" : ""), attrs: { type: "button", "aria-pressed": String(on) },
        text: u === "pps" ? "pps" : splitUnit(I.mbps(ctx.agg.in_mbps))[1], onclick: function () { ctx.actions.setOvUnit(u); } });
    }));
    var head = h("div", { class: "ov-card__head" }, [
      h("div", { class: "tr__lead" }, [
        h("h2", { class: "ov-card__title", id: "ov-tr-title", text: I.t("ov.tr.title") }),
        h("div", { class: "tr__now" }, [h("span", { class: "ov-big", text: big[0] }), h("span", { class: "ov-big__unit", text: big[1] }), chip])
      ]),
      h("div", { class: "tr__tools" }, [seg, arrowBtn(I.t("ov.tr.more"), goSection(ctx, "traffic"))])
    ]);

    /* bucket the window into at most TR_BARS bars; a bar is red if an attack
       was on at any sample in it */
    var size = Math.max(1, Math.ceil(pts.length / TR_BARS)), bars = [];
    for (var j = 0; j < pts.length; j += size) {
      var chunk = pts.slice(j, j + size), sum = 0, anyHot = false;
      chunk.forEach(function (p) { sum += p.v; anyHot = anyHot || p.hot; });
      bars.push({ v: sum / chunk.length, hot: anyHot, t: chunk[chunk.length - 1].t });
    }
    var max = Math.max(base, now, 1);
    bars.forEach(function (x) { if (x.v > max) max = x.v; });
    max *= 1.12;
    var chart = h("div", { class: "tr__chart" });
    var barsEl = h("div", { class: "tr__bars", attrs: { role: "img", "aria-label": I.t("ov.tr.aria", { t: pts.length > 1 ? I.duration((pts[pts.length - 1].t - pts[0].t) / 1000) : "—", v: fmt(now) }) } },
      bars.map(function (x, k) {
        var last = k === bars.length - 1;
        var bar = h("div", { class: "tr__bar" + (x.hot ? " is-attack" : last ? " is-last" : "") },
          last ? h("span", { class: "tr__tag mono", text: fmt(now) + " " + I.t("ov.now") }) : null);
        bar.style.height = Math.max(2, Math.round(x.v / max * 100)) + "%";
        return bar;
      }));
    chart.appendChild(barsEl);
    if (base > 0) {
      var line = h("div", { class: "tr__base", attrs: { "aria-hidden": "true" } });
      line.style.bottom = Math.round(base / max * 100) + "%";
      chart.appendChild(line);
    }
    /* four times under the bars, or as many distinct ones as the window has:
       a window shorter than a few minutes would print one minute four times */
    var axis = null;
    if (bars.length > 1) {
      var tA = bars[0].t, tB = bars[bars.length - 1].t, labels = [];
      [0, 1, 2, 3].forEach(function (q) {
        var s = I.timeShort(new Date(tA + (tB - tA) * q / 3));
        if (labels.indexOf(s) < 0) labels.push(s);
      });
      if (labels.length === 3) labels = [labels[0], labels[2]];
      axis = h("div", { class: "tr__axis mono" }, labels.map(function (s) { return h("span", { text: s }); }));
    }
    var legend = h("div", { class: "tr__legend" }, [
      h("span", {}, [h("span", { class: "tr__key" }), I.t("ov.tr.normal")]),
      bars.some(function (x) { return x.hot; }) ? h("span", {}, [h("span", { class: "tr__key is-attack" }), I.t("ov.tr.attack")]) : null,
      base > 0 ? h("span", {}, [h("span", { class: "tr__key is-base" }), I.t("ov.tr.baseline", { v: fmt(base) })]) : null
    ]);
    return h("section", { class: "ov-card ov-tr", attrs: { "aria-labelledby": "ov-tr-title" } },
      [head, pts.length ? chart : h("p", { class: "ov-card__empty", text: I.t("ov.tr.collecting") }), axis, legend]);
  }

  /* ===================== the four counts ===================== */
  function stats(ctx) {
    var s = ctx.status, act = ctx.attacks.active;
    var attackSub;
    if (act.length) {
      var out = act.filter(function (a) { return a.direction === "outgoing"; }).length;
      attackSub = out ? I.t("ov.st.attacks.mixed", { in: I.num(act.length - out), out: I.num(out) }) : I.t("ov.st.attacks.in");
    } else {
      var last = ctx.attacks.recent.slice().sort(function (a, b) { return startedMs(b) - startedMs(a); })[0];
      attackSub = last
        ? I.t("ov.st.attacks.last", { t: I.time(new Date(last.started_at)), d: last.ended_at ? I.duration((new Date(last.ended_at) - new Date(last.started_at)) / 1000) : "—" })
        : I.t("ov.st.attacks.none");
    }
    var byMethod = {}, mitigations = mitigating(ctx);
    mitigations.forEach(function (b) { byMethod[b.method] = (byMethod[b.method] || 0) + 1; });
    var banSub = Object.keys(byMethod).length
      ? Object.keys(byMethod).map(function (m) { return I.num(byMethod[m]) + " " + actName(m); }).join(" · ")
      : I.t("ov.st.bans.none");
    var hosts = ctx.hosts, attacked = hosts.filter(function (x) { return x.in_attack; }).length;
    var learned = hosts.length ? Math.round(hosts.filter(function (x) { return x.baseline; }).length / hosts.length * 100) : 0;
    var nets = ctx.networks, v6 = nets.filter(function (n) { return n.indexOf(":") >= 0; }).length;
    var cards = [
      { id: "attacks", label: I.t("nav.attacks"), value: I.num(s.active_attacks), hot: s.active_attacks > 0, sub: attackSub },
      { id: "mitigation", label: I.t("nav.bans"), value: I.num(mitigations.length), sub: banSub },
      { id: "hosts", label: I.t("nav.hosts"), value: I.num(hosts.length),
        sub: attacked ? I.t("ov.st.hosts.attacked", { n: I.num(attacked) }) : I.t("ov.st.hosts.learned", { p: I.num(learned) + "%" }) },
      { id: "settings", label: I.t("ov.st.networks"), value: nets.length ? I.num(nets.length) : "—",
        sub: nets.length ? I.t("ov.st.nets.split", { v4: I.num(nets.length - v6), v6: I.num(v6) }) : I.t("se.adminonly") }
    ];
    return h("div", { class: "ov-stats" }, cards.map(function (c) {
      return h("button", { class: "ov-stat", attrs: { type: "button" }, onclick: goSection(ctx, c.id) }, [
        h("span", { class: "ov-stat__label", text: c.label }),
        h("span", { class: "ov-big" + (c.hot ? " is-attack" : ""), text: c.value }),
        h("span", { class: "ov-stat__sub", text: c.sub })
      ]);
    }));
  }

  /* ===================== active attacks ===================== */
  function activeAttacks(ctx) {
    var act = ctx.attacks.active.slice().sort(function (a, b) { return (mult(b) || 0) - (mult(a) || 0); });
    var head = h("div", { class: "ov-card__head" }, [
      h("div", { class: "ov-card__titlerow" }, [
        h("h2", { class: "ov-card__title", id: "ov-at-title", text: I.t("at.active") }),
        h("span", { class: "nav__count" + (act.length ? " is-hot" : ""), text: I.num(act.length) })
      ]),
      arrowBtn(I.t("ov.at.all"), goSection(ctx, "attacks"))
    ]);
    if (!act.length) return h("section", { class: "ov-card ov-at", attrs: { "aria-labelledby": "ov-at-title" } }, [head, calmAttacks(ctx)]);

    var cols = h("div", { class: "atk atk--head", attrs: { "aria-hidden": "true" } }, [
      h("span", { text: I.t("col.target") }), h("span", { text: I.t("ov.at.vector") }), h("span", { text: I.t("ov.at.force") }), h("span", { text: I.t("ov.at.doing") }), h("span", {})
    ]);
    var rows = act.map(function (a) {
      var m = mult(a), esc = a.escalation || [], step = Math.min(a.escalation_step || 0, Math.max(0, esc.length - 1));
      var prot = protOf(a, ctx), nx = nextRung(a);
      var sample = a.sample, vsub = [];
      if (sample && sample.protocols && sample.protocols.length) vsub.push(sample.protocols[0].key);
      var ports = sample && sample.top_dst_ports ? sample.top_dst_ports.slice(0, 2).map(function (p) { return p.key; }) : [];
      var conf = I.pct(a.classification.confidence || 0);
      var vline = ports.length && vsub.length ? I.t("ov.at.vsub", { proto: vsub[0], ports: ports.join(I.t("ov.at.and")), conf: conf }) : (vsub.length ? vsub[0] + " · " + conf : conf);
      var segs = h("div", { class: "atk__steps", attrs: { "aria-hidden": "true" } }, esc.map(function (st, i) {
        return h("span", { class: "atk__step" + (i <= step ? " tone-" + (i === 0 && st.action === "none" ? "alert" : actTone(st.action)) : "") });
      }));
      var rsub = nx
        ? h("div", { class: "atk__sub" }, [I.t("ov.prot.nextin", { action: actName(nx.action) }) + " ", countdown(nx.atMs)])
        : h("div", { class: "atk__sub", text: ACT[prot] ? I.t(ACT[prot].now) : "" });
      var actions = [];
      if (ctx.role === "operator" && prot !== "none") {
        actions.push(h("button", { class: "btn btn--sm atk__withdraw", attrs: { type: "button" }, onclick: function (e) { ctx.actions.withdraw(e.currentTarget, a.target); }, text: I.t("ac.withdraw") }));
      }
      actions.push(arrowBtn(I.t("ov.at.open", { t: targetOf(a) }), function () { ctx.actions.openDrawer(a); }));
      return h("div", { class: "atk" }, [
        h("div", {}, [h("div", { class: "atk__ip mono", text: targetOf(a) }), h("div", { class: "atk__sub", text: (a.scope === "group" ? I.label("scope", "group") : a.group) + " · " + I.label("direction", a.direction) })]),
        h("div", {}, [h("div", { class: "atk__vec", text: I.label("attackType", a.classification.type) }), h("div", { class: "atk__sub", text: vline })]),
        h("div", {}, [h("div", { class: "atk__mag", text: m != null ? multText(m) + "×" : "—" }),
          h("div", { class: "atk__sub mono", text: I.t("ov.at.msub", { rate: I.abbr(a.rate, a.metric), thr: I.abbr(a.threshold) }) })]),
        h("div", { class: "atk__doing" }, [segs,
          h("div", {}, [h("span", { class: "atk__rung", text: actName(prot) }), " ", h("span", { class: "atk__sub", text: "· " + I.t("ov.jr.step", { i: I.num(step + 1), n: I.num(Math.max(1, esc.length)) }) })]),
          rsub]),
        h("div", { class: "atk__acts" }, actions)
      ]);
    });
    return h("section", { class: "ov-card ov-at", attrs: { "aria-labelledby": "ov-at-title" } },
      [head, h("div", { class: "atk__scroll" }, h("div", { class: "atk__table" }, [cols].concat(rows)))]);
  }
  function calmAttacks(ctx) {
    var last = ctx.attacks.recent.slice().sort(function (a, b) { return startedMs(b) - startedMs(a); })[0];
    var text = last
      ? I.t("ov.at.last", { type: I.label("attackType", last.classification.type), target: targetOf(last), t: I.time(new Date(last.started_at)),
          d: last.ended_at ? I.duration((new Date(last.ended_at) - new Date(last.started_at)) / 1000) : "—" })
      : I.t("ov.at.never");
    return h("div", { class: "ov-calm" }, [h("div", { class: "ov-calm__title", text: I.t("ov.at.none") }), h("p", { class: "ov-card__sub", text: text })]);
  }

  /* ===================== system health =====================
     Each row says what is known. BGP's session state is not in the API, so
     its dot stays neutral; the flow intake is measured (flows per second
     arriving now), the data plane reports itself, and the fleets' liveness
     comes from their inventories, fetched on their own freshness guards. */
  function health(ctx) {
    var s = ctx.status, rows = [];
    function row(label, dot, value, sub) {
      rows.push(h("div", { class: "hl__row" }, [
        h("dt", { class: "hl__k", text: label }),
        h("dd", { class: "hl__v" }, [h("div", { class: "hl__val" }, [h("span", { class: "hl__dot tone-" + dot, attrs: { "aria-hidden": "true" } }), value]),
          sub ? (sub.nodeType ? h("div", { class: "hl__sub" }, sub) : h("div", { class: "hl__sub", text: sub })) : null])
      ]));
    }
    if (s.bgp) {
      var announced = mitigating(ctx).filter(function (b) { return b.method !== "dataplane"; }).length;
      var peers = s.bgp.neighbors && s.bgp.neighbors.length ? I.t("ov.hl.bgp.peers", { list: s.bgp.neighbors.join(", ") }) : I.t("ov.hl.bgp.nopeers");
      row("BGP", "muted", ctx.dryRun ? I.t("ov.hl.bgp.dry") : announced ? I.plural(announced, "ovHlAnnounced") : I.t("ov.hl.bgp.none"), peers);
    }
    var fps = 0, withTraffic = 0;
    ctx.hosts.forEach(function (x) { var f = (x.rates.flows_per_sec || 0) + (x.out_rates.flows_per_sec || 0); fps += f; if (f > 0) withTraffic++; });
    row(I.t("ov.hl.flows"), fps > 0 ? "calm" : "elev", fps > 0 ? I.fps(fps) : I.t("ov.hl.flows.none"), fps > 0 ? I.plural(withTraffic, "ovHlTrafficHosts") : null);
    var dp = s.dataplane;
    if (dp) {
      var ifaces = (dp.interfaces || []).map(function (x) { return x.name; }).filter(Boolean).join(", ");
      var dpVal = !dp.enabled ? I.t("ov.hl.xdp.off") : dp.degraded ? I.t("ov.hl.xdp.degraded") : dp.dry_run ? I.t("ov.hl.xdp.watch") : I.t("ov.hl.xdp.on");
      row("XDP", !dp.enabled ? "muted" : dp.degraded || dp.dry_run ? "elev" : "calm", dpVal,
        dp.enabled ? I.t("ov.hl.xdp.ifaces", { list: ifaces || "—", a: I.num(dp.attached || 0), c: I.num(dp.configured || 0) }) : null);
    } else if (s.unscoped) {
      row("XDP", "muted", I.t("ov.hl.xdp.off"), null);
    }
    fleetRow(row, I.t("nav.nodes"), s.nodes_total, ctx.state.nodes);
    fleetRow(row, I.t("nav.edgenodes"), s.edge_nodes_total, ctx.state.edgeInv);
    if (s.version) {
      var upd = s.update_available && s.latest_version;
      row(I.t("se.version"), upd ? "accent" : "calm",
        upd ? I.t("ov.hl.update", { v: s.version, latest: s.latest_version }) : s.version,
        upd && s.latest_url ? h("a", { href: s.latest_url, target: "_blank", rel: "noopener", text: I.t("ov.hl.whatsnew", { v: s.latest_version }) }) : null);
    }
    return h("section", { class: "ov-card ov-hl", attrs: { "aria-labelledby": "ov-hl-title" } }, [
      h("div", {}, [
        h("h2", { class: "ov-card__title", id: "ov-hl-title", text: I.t("ov.hl.title") }),
        h("p", { class: "ov-card__sub", text: I.t("ov.hl.uptime", { t: I.duration(s.uptime_seconds) }) })
      ]),
      h("dl", { class: "hl" }, rows)
    ]);
  }
  /* a fleet: "2 of 2 online" once its inventory has answered, the count
     configured until then (or for a token that may not read it) */
  function fleetRow(row, label, total, inv) {
    if (!total) return;
    if (inv && inv.ok && inv.list) {
      var alive = inv.list.filter(function (n) { return n.alive; }).length;
      row(label, alive === inv.list.length ? "calm" : "elev", I.t("ov.hl.alive", { a: I.num(alive), n: I.num(inv.list.length) }),
        inv.list.map(function (n) { return n.name; }).join(", "));
    } else {
      row(label, "muted", I.t("ov.hl.configured", { n: I.num(total) }), null);
    }
  }

  /* ===================== the page ===================== */
  function overview(root, ctx) {
    /* the fleets' liveness, for the health card — each has its own freshness
       guard, so asking on every render costs nothing between refreshes */
    if (ctx.status.nodes_total > 0) ctx.actions.loadNodes();
    if (ctx.status.edge_nodes_total > 0) ctx.actions.loadEdgeInv();
    /* watch-only is said once, in the top bar; what stays here are the alarms
       about the data plane disagreeing with it, and the filter bypass */
    var dry = V.dryRunBanner(ctx);
    var alarms = [dry && dry.className.indexOf("banner--dry-loud") >= 0 ? dry : null, V.filterBypassBanner(ctx)];
    K.mount(root, alarms.concat([
      h("div", { class: "ov-row" }, [hero(ctx), chronicle(ctx)]),
      h("div", { class: "ov-row" }, [traffic(ctx), stats(ctx)]),
      h("div", { class: "ov-row" }, [activeAttacks(ctx), health(ctx)])
    ]));
  }

  V.overview = overview;
})(window);
