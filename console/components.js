/* components.js — DOM helpers + reusable + signature components.
   All user-controlled values are written via textContent (XSS-safe).
   Dynamic dimensions are set via the CSSOM (.style.x) — never inline style
   attributes in markup — so the strict CSP (style-src 'self') is satisfied. */
(function (w) {
  "use strict";
  var I = w.I18N;
  var SVGNS = "http://www.w3.org/2000/svg";

  /* ---------- DOM builder ---------- */
  function h(tag, props, children) {
    var e = document.createElement(tag);
    if (props) for (var k in props) {
      var v = props[k];
      if (v == null) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k === "html") e.innerHTML = v;                  // trusted constants only
      else if (k === "dataset") for (var d in v) e.dataset[d] = v[d];
      else if (k === "style") for (var s in v) e.style[s] = v[s];
      else if (k === "attrs") { for (var an in v) if (v[an] != null) e.setAttribute(an, v[an]); }
      else if (k.indexOf("on") === 0 && typeof v === "function") e[k.toLowerCase()] = v;  // property, not addEventListener: lets reconcile() carry the fresh closure
      else e.setAttribute(k, v);
    }
    append(e, children);
    return e;
  }
  function append(e, c) {
    if (c == null) return;
    if (Array.isArray(c)) c.forEach(function (x) { append(e, x); });
    else if (c.nodeType) e.appendChild(c);
    else e.appendChild(document.createTextNode(String(c)));
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }

  /* ---------- incremental DOM reconcile ----------
     Morphs a parent's existing children to match a freshly-built node list,
     mutating in place so untouched nodes keep their identity. That preserves
     input focus/caret/value, scroll position, an open confirm popover's anchor,
     and CSS animations on unchanged nodes (e.g. the posture pulse) — so the 3s
     poll re-renders with no flicker and no focus-skip workarounds. mount() now
     reconciles instead of clear+append. */
  var EV_PROPS = ["onclick", "onchange", "oninput", "onkeydown", "onkeyup", "onsubmit", "onfocus", "onblur", "onmousedown", "onmouseup"];
  function flattenNodes(c, out) {
    if (c == null) return;
    if (Array.isArray(c)) { c.forEach(function (x) { flattenNodes(x, out); }); return; }
    out.push(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function syncAttrs(oldEl, newEl) {
    var na = newEl.attributes, oa = oldEl.attributes, i;
    for (i = 0; i < na.length; i++) { if (oldEl.getAttribute(na[i].name) !== na[i].value) oldEl.setAttribute(na[i].name, na[i].value); }
    for (i = oa.length - 1; i >= 0; i--) { if (!newEl.hasAttribute(oa[i].name)) oldEl.removeAttribute(oa[i].name); }
  }
  function morphNode(oldN, newN) {
    if (oldN.nodeType !== newN.nodeType) return newN;
    if (oldN.nodeType === 3) { if (oldN.nodeValue !== newN.nodeValue) oldN.nodeValue = newN.nodeValue; return oldN; }
    if (oldN.nodeType !== 1 || oldN.tagName !== newN.tagName || oldN.namespaceURI !== newN.namespaceURI) return newN;
    syncAttrs(oldN, newN);
    /* carry event-handler closures (set as properties by h()) from the fresh tree */
    for (var i = 0; i < EV_PROPS.length; i++) { var p = EV_PROPS[i]; if (oldN[p] !== newN[p]) oldN[p] = newN[p] || null; }
    /* never write a focusable input's live value/caret — only its attributes get synced above */
    reconcileChildren(oldN, newN);
    return oldN;
  }
  function reconcileChildren(oldEl, newEl) {
    var next = [], k = newEl.childNodes, i;
    for (i = 0; i < k.length; i++) next.push(k[i]); /* snapshot: appending moves nodes out of newEl */
    for (i = 0; i < next.length; i++) {
      var on = oldEl.childNodes[i];
      if (!on) { oldEl.appendChild(next[i]); continue; }
      var m = morphNode(on, next[i]);
      if (m !== on) oldEl.replaceChild(m, on);
    }
    while (oldEl.childNodes.length > next.length) oldEl.removeChild(oldEl.lastChild);
  }
  function reconcile(parent, children) {
    var next = []; flattenNodes(children, next);
    for (var i = 0; i < next.length; i++) {
      var on = parent.childNodes[i];
      if (!on) { parent.appendChild(next[i]); continue; }
      var m = morphNode(on, next[i]);
      if (m !== on) parent.replaceChild(m, on);
    }
    while (parent.childNodes.length > next.length) parent.removeChild(parent.lastChild);
    return parent;
  }
  function mount(e, children) { return reconcile(e, children); }

  function svg(tag, attrs, children) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    if (children) (Array.isArray(children) ? children : [children]).forEach(function (c) { if (c) e.appendChild(c); });
    return e;
  }

  /* ---------- atoms ---------- */
  function badge(cls, label, iconName) {
    return h("span", { class: "badge " + cls }, [iconName ? w.icon(iconName) : null, h("span", { text: label })]);
  }
  function dirBadge(dir) {
    var out = dir === "outgoing";
    return h("span", { class: "badge " + (out ? "badge--active" : "badge--muted"), attrs: { title: I.label("direction", dir) } },
      [w.icon(out ? "arrow-up" : "arrow-down"), h("span", { text: I.label("direction", dir) })]);
  }
  function modeBadge(dry) {
    return dry
      ? badge("badge--dry", I.t("mode.dryrun"), "shield-alert")
      : badge("badge--calm", I.t("mode.live"), "shield-check");
  }
  function posturePill(state) {
    var map = { calm: "posture--calm", attack: "posture--attack", mitigating: "posture--mitigating" };
    var key = { calm: "posture.calm", attack: "posture.attack", mitigating: "posture.mitigating" }[state];
    return h("span", { class: "posture " + map[state] }, [h("span", { class: "posture__dot" }), h("span", { text: I.t(key) })]);
  }

  /* ---------- charts (hand-rolled SVG) ---------- */
  function buildPath(values, wd, ht, pad) {
    var n = values.length; if (n < 2) values = values.concat(values), n = values.length;
    var mn = Math.min.apply(null, values), mx = Math.max.apply(null, values);
    if (mx === mn) { mx = mn + 1; }
    var rng = mx - mn, innerH = ht - pad * 2, innerW = wd;
    var pts = values.map(function (v, i) {
      var x = (i / (n - 1)) * innerW;
      var y = pad + innerH - ((v - mn) / rng) * innerH;
      return [x, y];
    });
    var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
    var area = line + " L" + innerW + " " + ht + " L0 " + ht + " Z";
    return { line: line, area: area };
  }
  function sparkline(values, opts) {
    opts = opts || {};
    var wd = 100, ht = opts.height || 34, color = opts.color || "var(--accent)";
    var p = buildPath(values, wd, ht, 3);
    var el = svg("svg", { viewBox: "0 0 " + wd + " " + ht, preserveAspectRatio: "none" }, [
      opts.area !== false ? svg("path", { d: p.area, class: "spark-area" }) : null,
      svg("path", { d: p.line, class: "spark-line" })
    ]);
    var area = el.querySelector(".spark-area"), line = el.querySelector(".spark-line");
    if (area) area.style.fill = color;
    line.style.stroke = color;
    return el;
  }
  function areaChart(values, opts) {
    opts = opts || {};
    var wd = 300, ht = opts.height || 72, color = opts.color || "var(--chart-in)";
    var p = buildPath(values, wd, ht, 4);
    var children = [];
    [0.25, 0.5, 0.75].forEach(function (f) {
      children.push(svg("line", { x1: 0, x2: wd, y1: ht * f, y2: ht * f, class: "chart-axis" }));
    });
    if (opts.markerFrac != null) {
      var mx = opts.markerFrac * wd;
      children.push(svg("rect", { x: mx, y: 0, width: wd - mx, height: ht, fill: "var(--active-soft)" }));
      children.push(svg("line", { x1: mx, x2: mx, y1: 0, y2: ht, stroke: "var(--active)", "stroke-width": 1, "stroke-dasharray": "3 3" }));
    }
    children.push(svg("path", { d: p.area, class: "spark-area" }));
    children.push(svg("path", { d: p.line, class: "spark-line" }));
    var el = svg("svg", { viewBox: "0 0 " + wd + " " + ht, preserveAspectRatio: "none" }, children);
    el.querySelector(".spark-area").style.fill = color;
    el.querySelector(".spark-line").style.stroke = color;
    return el;
  }

  /* ---------- ESCALATION LADDER (hero) ---------- */
  var ACTION_TONE = { none: 1, flowspec: 2, divert: 3, blackhole: 4 };
  var ACTION_ICON = { none: "bell", flowspec: "zap", divert: "divert", blackhole: "slash" };

  function ladder(escalation, currentStep, opts) {
    opts = opts || {};
    var compact = opts.compact, config = opts.config, startedMs = opts.startedMs, live = opts.live;
    var rungs = escalation.map(function (stage, i) {
      var action = stage.action, tone = ACTION_TONE[action];
      var state = config ? "config" : (i < currentStep ? "is-done" : i === currentStep ? "is-current" : "is-future");
      var nameFull = I.label("action", action), nameShort = I.labelShort("action", action);

      var sub = null;
      if (config) {
        sub = h("div", { class: "rung__sub", text: i === 0 ? I.t("lad.alertonly") : "@ " + stage.after_seconds + "s" });
      } else if (state === "is-current" && live) {
        if (i >= escalation.length - 1) {
          sub = h("div", { class: "rung__sub", text: action === "blackhole" ? I.t("lad.atmax") : I.t("lad.holding") });
        } else {
          var nextMs = startedMs + escalation[i + 1].after_seconds * 1000;
          sub = h("div", { class: "rung__sub" }, [
            I.t("lad.nextin") + " ",
            h("span", { class: "mono", dataset: { cdTarget: nextMs } , text: I.countdown((nextMs - Date.now()) / 1000) })
          ]);
        }
      } else if (state === "is-done") {
        sub = h("div", { class: "rung__sub", text: "✓" });
      }

      /* progress bar */
      var barFill = h("i");
      if (config) { barFill.style.width = "0%"; }
      else if (state === "is-done") { barFill.style.width = "100%"; }
      else if (state === "is-current" && live && i < escalation.length - 1) {
        var startMs = startedMs + stage.after_seconds * 1000;
        var endMs = startedMs + escalation[i + 1].after_seconds * 1000;
        barFill.dataset.barStart = startMs; barFill.dataset.barEnd = endMs;
        var frac = (Date.now() - startMs) / (endMs - startMs);
        barFill.style.width = Math.max(0, Math.min(100, frac * 100)) + "%";
      } else if (state === "is-current") { barFill.style.width = "100%"; }
      else { barFill.style.width = "0%"; }

      var node = (state === "is-done")
        ? h("span", { class: "rung__node" }, w.icon("check-sm"))
        : h("span", { class: "rung__node" }, w.icon(ACTION_ICON[action]));

      return h("div", { class: "rung " + (state === "config" ? "" : state), dataset: { tone: tone }, attrs: { title: nameFull } }, [
        h("div", { class: "rung__head" }, [node, h("span", { class: "rung__name", text: compact ? nameShort : nameFull })]),
        h("div", { class: "rung__bar" }, barFill),
        sub
      ]);
    });
    return h("div", { class: "ladder" + (compact ? " ladder--compact" : "") + (config ? " ladder--config" : "") }, rungs);
  }

  /* ---------- gauge: metric vs threshold ---------- */
  function gauge(metricKey, rate, threshold) {
    var mult = rate / threshold;
    var scaleMax = Math.max(rate * 1.08, threshold * 2);
    var sev = mult >= 3 ? "sev-active" : "sev-elev";
    var fill = h("div", { class: "gauge__fill" }); fill.style.width = Math.min(100, rate / scaleMax * 100) + "%";
    var tick = h("div", { class: "gauge__thresh" }); tick.style.left = (threshold / scaleMax * 100) + "%";
    return h("div", { class: "gauge" }, [
      h("div", { class: "gauge__top" }, [
        h("span", { class: "gauge__metric", text: metricKey }),
        h("span", { class: "gauge__mult " + sev }, [I.abbr(mult, "") + "× ", h("span", { style: { fontSize: "var(--t-sm)", fontWeight: "600" }, text: I.t("ac.overthreshold") })])
      ]),
      h("div", { class: "gauge__track" }, [fill, tick]),
      h("div", { class: "gauge__scale" }, [
        h("span", { text: "0" }),
        h("span", { text: I.t("ac.threshold") + " " + I.abbr(threshold) }),
        h("span", { text: I.abbr(scaleMax) })
      ])
    ]);
  }

  /* ---------- confidence bar ---------- */
  function confidence(conf) {
    var bar = h("i"); bar.style.width = Math.round(conf * 100) + "%";
    return h("span", { class: "conf" }, [
      h("span", { class: "conf__bar" }, bar),
      h("span", { class: "conf__val", text: I.pct(conf) + " " + I.t("ac.confidence") })
    ]);
  }

  /* ---------- rate vs baseline bar (hosts) ---------- */
  function baselineBar(rate, baseline) {
    var wrap = h("div", { class: "bl-bar" });
    if (baseline == null || baseline <= 0) {
      var f0 = h("div", { class: "bl-bar__fill" }); f0.style.width = "8%"; wrap.appendChild(f0);
      return { bar: wrap, mult: null };
    }
    var mult = rate / baseline;
    var fillW = Math.min(100, Math.sqrt(mult / 16) * 100);
    var fill = h("div", { class: "bl-bar__fill" + (mult >= 3 ? " sev-active" : "") }); fill.style.width = fillW + "%";
    var base = h("div", { class: "bl-bar__base" }); base.style.left = "25%";
    wrap.appendChild(fill); wrap.appendChild(base);
    return { bar: wrap, mult: mult };
  }

  /* ---------- mitigation / route display ---------- */
  function routeRow(k, vNode) { return h("div", { class: "route__line" }, [h("span", { class: "route__k", text: k }), h("span", { class: "route__v" }, vNode)]); }
  function routeDisplay(obj, dry) {
    var rows = [];
    var method = obj.method;
    rows.push(routeRow(I.t("col.method"), h("span", { class: "badge " + (method === "blackhole" ? "badge--active" : method === "divert" ? "badge--elev" : "badge--accent") }, [w.icon(method === "blackhole" ? "slash" : method === "divert" ? "divert" : "zap"), h("span", { text: I.label("method", method) })])));
    if (obj.flowspec && obj.flowspec.length) {
      obj.flowspec.forEach(function (r, i) {
        rows.push(routeRow(i === 0 ? I.t("ac.flowspec") : "", h("span", { class: "route__rule" }, [
          h("span", { text: r.match + " → " }),
          h("span", { class: r.action === "discard" ? "op-discard" : "op-rate", text: r.action })
        ])));
      });
    } else if (obj.route) {
      rows.push(routeRow(I.t("ac.route"), h("span", { class: "mono", text: obj.route })));
    }
    if (obj.next_hop) rows.push(routeRow(I.t("ac.nexthop"), h("span", { class: "mono", text: obj.next_hop })));
    if (obj.community) rows.push(routeRow(I.t("ac.community"), h("span", { class: "mono", text: obj.community })));
    if (obj.local_pref != null) rows.push(routeRow(I.t("ac.localpref"), h("span", { class: "mono", text: String(obj.local_pref) })));
    /* the dry-run cue is the dashed amber border + a badge in the section header
       (rendered by the caller), so the box itself carries no inline tag. */
    return h("div", { class: "route" + (dry ? " is-dry" : "") }, rows);
  }

  /* ---------- share bars (sample) ---------- */
  function shareGroup(title, list, opts) {
    opts = opts || {};
    var total = list.reduce(function (s, x) { return s + (x.packets || 1); }, 0);
    var rows = list.slice(0, 5).map(function (x) {
      var pct = (x.packets || 1) / total;
      var bar = h("i"); bar.style.width = Math.max(2, pct * 100) + "%";
      return h("div", { class: "share" }, [
        h("span", { class: "share__key", text: opts.labelEnum ? I.label(opts.labelEnum, x.key) : x.key }),
        h("span", { class: "share__pct", text: I.pct(pct) }),
        h("span", { class: "share__bar" + (opts.src ? " is-src" : "") }, bar)
      ]);
    });
    return h("div", { class: "share-group" }, [h("div", { class: "share-group__title", text: title }), rows]);
  }

  /* ---------- ban lifecycle timeline ---------- */
  function timeline(attack) {
    var items = [], esc = attack.escalation || [], step = attack.escalation_step || 0;
    var start = new Date(attack.started_at);
    items.push({ when: start, what: I.t("ac.detected"), detail: I.label("attackType", attack.classification.type) + " · " + I.pct(attack.classification.confidence) + " " + I.t("ac.confidence"), cls: "is-done" });
    esc.forEach(function (stage, i) {
      if (i === 0) return;
      var done = i <= step;
      var when = new Date(start.getTime() + stage.after_seconds * 1000);
      items.push({ when: when, what: I.label("action", stage.action), detail: done ? "" : "pending", cls: done ? (i === step && attack.active ? "is-active" : "is-warn") : "" });
    });
    if (!attack.active && attack.ended_at) items.push({ when: new Date(attack.ended_at), what: I.label("banState", "withdrawn"), detail: "", cls: "is-done" });
    return h("div", { class: "timeline" }, items.map(function (it) {
      return h("div", { class: "tl-item" }, [
        h("span", { class: "tl-dot " + it.cls }),
        h("div", {}, [
          h("div", { class: "tl-when", text: I.time(it.when) }),
          h("div", { class: "tl-what", text: it.what }),
          it.detail ? h("div", { class: "tl-detail", text: it.detail }) : null
        ])
      ]);
    }));
  }

  /* ---------- rejection callout ---------- */
  function rejection(reason) {
    var key = { whitelisted: "reject.whitelisted", outside_networks: "reject.outside", cap: "reject.cap" }[reason] || "reject.label";
    return h("div", { class: "reject" }, [w.icon("info"), h("div", {}, [h("b", { text: I.t("reject.label") + ": " }), I.t(key)])]);
  }

  /* ---------- toast ---------- */
  function toast(msg, kind) {
    var host = document.getElementById("toasts");
    var ic = kind === "err" ? "x" : kind === "warn" ? "alert" : "check";
    var t = h("div", { class: "toast toast--" + (kind || "ok"), attrs: { role: "status" } }, [w.icon(ic), h("span", { text: msg })]);
    host.appendChild(t);
    setTimeout(function () { t.style.opacity = "0"; t.style.transform = "translateY(8px)"; setTimeout(function () { t.remove(); }, 250); }, 3200);
  }

  /* ---------- confirm popover ---------- */
  function confirm(anchor, opts) {
    closeConfirm();
    var pop = h("div", { class: "confirm", id: "__confirm" }, [
      h("div", { class: "confirm__title", text: opts.title }),
      h("div", { class: "confirm__txt", text: opts.text }),
      h("div", { class: "confirm__actions" }, [
        h("button", { class: "btn btn--ghost btn--sm", text: I.t("confirm.cancel"), onclick: closeConfirm }),
        h("button", { class: "btn " + (opts.danger ? "btn--danger" : "btn--primary") + " btn--sm", text: opts.confirmLabel || I.t("confirm.confirm"),
          onclick: function () { closeConfirm(); opts.onConfirm && opts.onConfirm(); } })
      ])
    ]);
    document.body.appendChild(pop);
    var r = anchor.getBoundingClientRect();
    var top = Math.min(r.bottom + 8, window.innerHeight - pop.offsetHeight - 12);
    var left = Math.min(r.left, window.innerWidth - pop.offsetWidth - 12);
    pop.style.top = top + "px"; pop.style.left = Math.max(12, left) + "px";
    setTimeout(function () { document.addEventListener("mousedown", outside); }, 0);
    function outside(e) { if (!pop.contains(e.target)) closeConfirm(); }
    pop._outside = outside;
  }
  function closeConfirm() {
    var p = document.getElementById("__confirm");
    if (p) { if (p._outside) document.removeEventListener("mousedown", p._outside); p.remove(); }
  }

  /* ---------- empty / loading / error blocks ---------- */
  function empty(iconName, title, sub, tone) {
    var ic = h("div", { class: "empty__icon" }, w.icon(iconName));
    if (tone === "muted") { ic.style.color = "var(--muted)"; ic.style.background = "#ffffff0a"; ic.style.borderColor = "var(--border)"; }
    return h("div", { class: "empty" }, [ic, h("div", { class: "empty__title", text: title }), h("div", { class: "empty__sub", text: sub })]);
  }
  function skeletonRows(n) {
    var rows = []; for (var i = 0; i < n; i++) rows.push(h("div", { class: "skel skel-row" }));
    return h("div", {}, rows);
  }

  w.K = {
    h: h, svg: svg, clear: clear, mount: mount, append: append,
    badge: badge, dirBadge: dirBadge, modeBadge: modeBadge, posturePill: posturePill,
    sparkline: sparkline, areaChart: areaChart,
    ladder: ladder, gauge: gauge, confidence: confidence, baselineBar: baselineBar,
    routeDisplay: routeDisplay, shareGroup: shareGroup, timeline: timeline,
    rejection: rejection, toast: toast, confirm: confirm, closeConfirm: closeConfirm,
    empty: empty, skeletonRows: skeletonRows,
    ACTION_ICON: ACTION_ICON
  };
})(window);
