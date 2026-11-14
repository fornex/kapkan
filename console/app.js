/* app.js — shell, routing, polling, state. Boots after all modules load.
   Data comes from the real same-origin /api/v1 endpoints via the api.js
   adapter: the synchronous getters read its cache, refreshed each 3s poll. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h, API = w.API, V = w.Views, Theme = w.KapkanTheme;

  /* The console's sections: the pill bar in the top bar, Settings behind the
     gear. A section with more than one view shows them as tabs in its head
     (views.js viewHead asks V.section() for them). `views[0]` is where a
     section opens the first time; after that it reopens on the tab the
     operator left it on. */
  var SECTIONS = [
    { id: "overview", key: "nav.overview", icon: "grid", views: ["overview"] },
    { id: "attacks", key: "nav.attacks", icon: "activity", views: ["attacks"], count: "attacks" },
    { id: "mitigation", key: "nav.bans", icon: "ban", views: ["bans", "nodes"], count: "bans" },
    { id: "hosts", key: "nav.hosts", icon: "server", views: ["hosts"] },
    { id: "traffic", key: "nav.traffic", icon: "chart", views: ["traffic"] },
    { id: "edge", key: "nav.edge", icon: "globe", views: ["edge", "edgenodes"] },
    { id: "settings", key: "nav.settings", icon: "settings", views: ["settings", "hostgroups"], gear: true }
  ];
  /* a view's tab label, where its section has tabs */
  var TAB_KEY = { bans: "tab.bans", nodes: "nav.nodes", edge: "nav.edge", edgenodes: "nav.edgenodes", settings: "tab.settings", hostgroups: "nav.hostgroups" };
  /* Views a deployment may not have. Packet filters show only when /status
     reports nodes_total > 0 — most deployments have no managed scrubbing nodes
     and must not carry a permanently-empty tab; the edge zones and their
     request filters only where edge nodes front zones (edge_nodes_total). A
     section whose views are all gated off leaves the bar. */
  var VIEW_GATE = {
    nodes: function (s) { return s.nodes_total > 0; },
    edge: function (s) { return s.edge_nodes_total > 0; },
    edgenodes: function (s) { return s.edge_nodes_total > 0; }
  };
  /* the phone's tab bar holds four places; the rest are under More */
  var PHONE_BAR = ["overview", "attacks", "mitigation"];
  var WINDOW = 60;
  /* the Overview's inbound chart: fifteen minutes of 3s polls */
  var OV_WINDOW = 300;

  /* The Edge view's tenant filter survives a reload of the page but not the
     browser session: it narrows what an operator is LOOKING at, and a filter
     silently still in force a week later is how a zone goes unwatched.
     sessionStorage may throw (a locked-down profile), so every access is
     guarded and an unreadable store simply means "no filter". */
  var TENANT_KEY = "kapkan.edgeTenant";
  function savedTenant() { try { return sessionStorage.getItem(TENANT_KEY) || ""; } catch (e) { return ""; } }

  var state = {
    view: "overview",
    role: "viewer", /* least privilege until /status reports the caller's role */
    /* did the last poll reach the engine? Until one does, the top bar shows
       "no connection" rather than a duty light for a mode it has not read. */
    online: false,
    /* the tab each section was left on */
    lastTab: {},
    moreOpen: false,
    hostDir: "incoming",
    filters: { scope: "", dir: "", type: "", group: "", q: "" },
    expanded: new Set(),
    drawer: { open: false, live: false, key: null, attack: null },
    buf: { aggIn: [], aggOut: [], aggInPps: [], aggOutPps: [], attacks: [], bans: [], hosts: [], inAttack: [], hostPps: {}, hostMbps: {},
      ovIn: [], ovInPps: [], ovT: [], ovHot: [] },
    /* the Overview chart's unit: "bps" or "pps" */
    ovUnit: "bps",
    traffic: { key: null, available: false, points: [], loading: false, fetchedAt: 0 },
    /* scrubbing nodes — fetched on demand with a freshness guard, NOT in the
       3s poll: liveness moves at stale_after (15s) pace and the endpoint walks
       the ban table, so refreshing it with the firehose buys nothing */
    nodes: { loading: false, fetchedAt: 0, ok: false, forbidden: false, total: 0, staleAfter: 15, list: [] },
    /* edge zones status (E4.5) — the same on-demand + freshness-guard shape:
       it merges the nodes' last ten-second windows, so a 10s refresh is the
       data's own pace */
    /* `skew` is the brain's clock minus the browser's, as of the last read: the
       lever's countdown is a brain-stamped interval and is rendered against it */
    edge: { loading: false, fetchedAt: 0, stale: false, skew: 0, ok: false, forbidden: false, nodesAlive: 0, nodesReporting: 0, zonesTruncated: 0, zones: [] },
    /* the edge-node inventory (E6.7), fetched on its own guard and read by
       BOTH edge views: the Edge nodes table renders all of it, the Edge
       view's HTTP/3 cell only each node's terminator.h3. Unscoped-only, so
       `forbidden` is a first-class state rather than an error. */
    edgeInv: { loading: false, fetchedAt: 0, ok: false, forbidden: false, total: 0, staleAfter: 15, list: [], unbound: [] },
    /* which tenant's zones the Edge view shows; "" is every tenant */
    edgeTenant: savedTenant(),
    /* one zone's stored history (E6.7): opened by clicking a zone row, closed
       by clicking it again. Same on-demand + freshness-guard shape as the
       status above, and for a stronger reason — these reads hit ClickHouse and
       the windows behind them are ten seconds long, so joining the 3s poll
       would buy nothing and cost a query every three seconds. */
    /* seq is the read that owns this state: only the newest may write it (see
       loadEdgeHistory), so a zone switch cannot be captioned by the answer to
       the zone before it. */
    edgeHist: { zone: null, range: "1h", key: "", loading: false, fetchedAt: 0, seq: 0,
      ok: false, forbidden: false, notFound: false, available: false, stepSeconds: 0, points: [],
      srcOk: false, srcAvailable: false, sources: [] },
    /* the fleet's events, last 24h — unscoped tokens only (they name nodes);
       absent when the kapkan is older than the endpoint */
    edgeEvents: { loading: false, fetchedAt: 0, ok: false, forbidden: false, absent: false, available: false, events: [] },
    last: { rung: -1 }
  };

  /* The history card's ranges: the period and the bucket asked for it. The
     brain may RAISE the step (a range holds at most 5000 buckets) or cap it at
     a day, so the response's step_seconds — not this one — is what the buckets
     were built with. views2.js renders the switch from the same three ids. */
  var EDGE_RANGES = {
    "1h":  { seconds: 3600,   step: 60 },
    "24h": { seconds: 86400,  step: 600 },
    "7d":  { seconds: 604800, step: 3600 }
  };
  var EDGE_EVENTS_SECONDS = 86400;

  /* ---------- buffers ---------- */
  /* `at` is the poll's time. The boot-time prefill passes none: it repeats the
     first answer so the sparklines start full, and the Overview's traffic
     chart, which draws real time, must not take those copies for history. */
  function pushBuf(at) {
    var s = API.getStatus(), agg = API.aggregate(), hostsData = API.getHosts().hosts;
    var b = state.buf;
    push(b.aggIn, agg.in_mbps); push(b.aggOut, agg.out_mbps);
    push(b.aggInPps, agg.in_pps); push(b.aggOutPps, agg.out_pps);
    push(b.attacks, s.active_attacks); push(b.bans, s.active_bans);
    push(b.hosts, hostsData.length); push(b.inAttack, s.active_attacks > 0);
    if (at) {
      pushOv(b.ovIn, agg.in_mbps); pushOv(b.ovInPps, agg.in_pps);
      pushOv(b.ovT, at); pushOv(b.ovHot, s.active_attacks > 0);
    }
    hostsData.forEach(function (host) {
      if (!b.hostPps[host.target]) b.hostPps[host.target] = [];
      push(b.hostPps[host.target], host.rates.pps);
      if (!b.hostMbps[host.target]) b.hostMbps[host.target] = [];
      push(b.hostMbps[host.target], host.rates.mbps);
    });
  }
  function push(arr, v) { arr.push(v); if (arr.length > WINDOW) arr.shift(); }
  function pushOv(arr, v) { arr.push(v); if (arr.length > OV_WINDOW) arr.shift(); }
  function prefill() { for (var i = 0; i < 24; i++) pushBuf(null); }

  /* ---------- posture ---------- */
  function derivePosture(attacks) {
    var a = attacks.active[0];
    if (!a) return "calm";
    return a.escalation_step >= 1 ? "mitigating" : "attack";
  }

  /* ---------- ctx ---------- */
  function buildCtx() {
    var status = API.getStatus(), attacks = API.getAttacks(), hosts = API.getHosts().hosts,
        bans = API.getBans(), groups = API.getHostgroups(), networks = API.getNetworks(), agg = API.aggregate();
    return {
      status: status, attacks: attacks, hosts: hosts, bans: bans, groups: groups, networks: networks,
      agg: agg, buf: state.buf, posture: derivePosture(attacks), dryRun: status.dry_run, role: state.role, online: state.online,
      state: state, actions: actions
    };
  }

  /* ---------- sections ---------- */
  function sectionOf(view) {
    for (var i = 0; i < SECTIONS.length; i++) if (SECTIONS[i].views.indexOf(view) >= 0) return SECTIONS[i];
    return SECTIONS[0];
  }
  function sectionById(id) {
    for (var i = 0; i < SECTIONS.length; i++) if (SECTIONS[i].id === id) return SECTIONS[i];
    return SECTIONS[0];
  }
  /* A gated view shows once /status says the deployment has it — and is never
     hidden out from under the operator who is LOOKING at it. Before the first
     /status answer the status is empty and gated views stay hidden, so a
     zero-node deployment never sees them flash. */
  function viewShown(view, status) {
    var gate = VIEW_GATE[view];
    return !gate || state.view === view || !!(status && gate(status));
  }
  function sectionViews(sec, status) {
    return sec.views.filter(function (v) { return viewShown(v, status); });
  }
  /* the operator's choice of language and theme live in Settings; the bar
     keeps only a quick night/paper switch */
  function themeLabel() { return I.t(Theme.effective() === "paper" ? "theme.toNight" : "theme.toPaper"); }

  /* The head of a sectioned view: the section's name, and its tabs while it
     has more than one view to show. views.js viewHead calls this through
     V.section; null leaves the view's own title alone. Each view renders its
     own copy, so arrow-key focus lands on the copy in the new view. */
  function sectionHead() {
    var sec = sectionOf(state.view), status = API.getStatus();
    var shown = sectionViews(sec, status);
    if (shown.length < 2) return null;
    var tabs = h("div", { class: "seg seg--tabs", attrs: { role: "tablist", "aria-label": I.t(sec.key) } }, shown.map(function (v, i) {
      var on = v === state.view;
      return h("button", {
        class: "seg__btn" + (on ? " is-on" : ""),
        attrs: { type: "button", role: "tab", "aria-selected": String(on), "aria-controls": "view-" + v, tabindex: on ? "0" : "-1" },
        dataset: { view: v },
        text: I.t(TAB_KEY[v]),
        onclick: function () { actions.setView(v); },
        onkeydown: function (e) {
          var step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
          if (!step) return;
          e.preventDefault();
          var next = shown[(i + step + shown.length) % shown.length];
          actions.setView(next);
          var t = document.querySelector('#view-' + next + ' [role="tab"][data-view="' + next + '"]');
          if (t) t.focus();
        }
      });
    }));
    return { title: I.t(sec.key), tabs: tabs };
  }
  V.section = sectionHead;

  /* ---------- shell (built once / on locale change) ---------- */
  function buildShell() {
    var brand = document.getElementById("brand");
    K.clear(document.getElementById("brandMark")).appendChild(w.icon("brandmark"));
    K.clear(document.getElementById("brandName")).appendChild(w.icon("wordmark"));
    brand.setAttribute("aria-label", I.t("nav.home"));
    brand.onclick = function () { actions.setSection("overview"); };

    /* the section pills; data-view is the view each opens first, so a
       script driving the console can open a view by its id */
    var nav = K.clear(document.getElementById("nav"));
    nav.setAttribute("aria-label", I.t("nav.label"));
    SECTIONS.forEach(function (sec) {
      if (sec.gear) return;
      var countEl = sec.count ? h("span", { class: "nav__count", dataset: { count: sec.count }, attrs: { hidden: "" }, text: "0" }) : null;
      var btn = h("button", { class: "nav__item", attrs: { type: "button" }, dataset: { view: sec.views[0], section: sec.id },
        onclick: function () { actions.setSection(sec.id); } },
        [h("span", { text: I.t(sec.key) }), countEl]);
      if (!sectionViews(sec, API.getStatus()).length) btn.hidden = true;
      nav.appendChild(btn);
    });

    var tb = K.clear(document.getElementById("themeBtn"));
    tb.appendChild(w.icon(Theme.effective() === "paper" ? "sun" : "moon"));
    tb.setAttribute("aria-label", themeLabel()); tb.title = themeLabel();
    tb.onclick = function () { actions.setTheme(Theme.effective() === "paper" ? "night" : "paper"); };

    /* operator-only (visibility set per poll from the role) */
    var rb = K.clear(document.getElementById("reloadBtn"));
    rb.appendChild(w.icon("refresh"));
    rb.setAttribute("aria-label", I.t("btn.reload")); rb.title = I.t("btn.reload.title");
    rb.onclick = function (e) { actions.reload(e.currentTarget); };

    var gb = K.clear(document.getElementById("gearBtn"));
    gb.appendChild(w.icon("settings"));
    gb.setAttribute("aria-label", I.t("nav.settings")); gb.title = I.t("nav.settings");
    gb.onclick = function () { actions.setSection("settings"); };

    buildTabbar();
    markActive();
  }

  /* The phone's bar (below 900px): Overview, Attacks, Mitigation, and More for
     the rest, opened as a sheet above it. */
  function buildTabbar() {
    var bar = K.clear(document.getElementById("tabbar"));
    bar.setAttribute("aria-label", I.t("nav.label"));
    state.moreOpen = false;
    function item(icon, label, extra) {
      var kids = [w.icon(icon)];
      if (extra) kids.push(extra);
      return [h("span", { class: "tabbar__icon" }, kids), h("span", { text: label })];
    }
    PHONE_BAR.forEach(function (id) {
      var sec = sectionById(id);
      var count = sec.count === "attacks" ? h("span", { class: "tabbar__count", attrs: { hidden: "" }, text: "0" }) : null;
      bar.appendChild(h("button", { class: "tabbar__item", attrs: { type: "button" }, dataset: { section: id },
        onclick: function () { actions.setSection(id); } }, item(sec.icon, I.t(sec.key), count)));
    });
    var moreItems = SECTIONS.filter(function (s) { return PHONE_BAR.indexOf(s.id) < 0; }).map(function (sec) {
      return h("button", { class: "more-pop__item", attrs: { type: "button" }, dataset: { section: sec.id },
        onclick: function () { actions.setSection(sec.id); } }, [w.icon(sec.icon), h("span", { text: I.t(sec.key) })]);
    });
    var pop = h("div", { class: "more-pop", id: "morePop", attrs: { hidden: "" } }, moreItems);
    var more = h("button", { class: "tabbar__item", id: "moreBtn", attrs: { type: "button", "aria-haspopup": "true", "aria-expanded": "false", "aria-controls": "morePop" },
      onclick: function (e) { e.stopPropagation(); setMore(!state.moreOpen); } }, item("more", I.t("nav.more")));
    bar.appendChild(more);
    bar.appendChild(pop);
  }
  function setMore(open) {
    state.moreOpen = open;
    var pop = document.getElementById("morePop"), btn = document.getElementById("moreBtn");
    if (!pop || !btn) return;
    pop.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
  }

  /* ---------- dynamic topbar (every poll) ---------- */
  function renderShellDynamic(ctx) {
    var s = ctx.status;
    /* What is happening, then the mode. With no connection neither can be
       claimed: "no connection" takes the posture's place and the watch-only
       chip goes, since the mode it names has not been read. */
    K.mount(document.getElementById("posturePill"), ctx.online
      ? K.postureChip(ctx.posture, function () { actions.setSection("attacks"); })
      : K.offlineChip());
    K.mount(document.getElementById("modeBadge"), ctx.online && s.dry_run
      ? K.watchChip(function () { actions.setSection("settings"); })
      : []);

    /* the clock is the time of the last good poll; with no connection the dot
       greys and the time stays where the data stopped */
    var live = document.getElementById("liveInd");
    live.classList.toggle("is-down", !ctx.online);
    if (ctx.online) document.getElementById("lastUpdated").textContent = I.time(new Date());
    var stamp = document.getElementById("lastUpdated").textContent;
    live.querySelector(".live__txt").textContent = I.t(ctx.online ? "live.label" : "duty.offline");
    live.title = I.t(ctx.online ? "live.title" : "live.title.down", { t: stamp });

    /* section counts: attacks in the alarm tint, mitigations in neutral */
    /* Mitigation counts the bans that mitigate: a ladder's alert rung holds a
       ban with no method, which drops nothing (the Overview shows those as
       unprotected) */
    var mitigating = API.getBans().active.filter(function (b) { return b.method && b.method !== "none"; }).length;
    var counts = { attacks: s.active_attacks || 0, bans: mitigating };
    document.querySelectorAll(".nav__count").forEach(function (el) {
      var v = counts[el.dataset.count];
      el.textContent = I.num(v);
      el.classList.toggle("is-hot", el.dataset.count === "attacks" && v > 0);
      el.hidden = !(v > 0);
    });
    document.querySelectorAll(".tabbar__count").forEach(function (el) {
      el.textContent = I.num(counts.attacks);
      el.hidden = !(counts.attacks > 0);
    });

    /* gated sections leave the bar (and the More sheet) while they have
       nothing to show */
    SECTIONS.forEach(function (sec) {
      var shown = sectionViews(sec, s).length > 0;
      document.querySelectorAll('[data-section="' + sec.id + '"]').forEach(function (el) { el.hidden = !shown; });
    });

    document.getElementById("reloadBtn").hidden = ctx.role !== "operator";
  }

  /* ---------- update-available banner (opt-in update check) ---------- */
  /* Dismissal is keyed by the latest version, so dismissing v1.3.0 hides it
     until a DIFFERENT version appears (then the banner returns). Persisted in
     localStorage so a reload does not re-nag. */
  var UPD_DISMISS_KEY = "kapkan.updateDismissed";
  function renderUpdateBanner(ctx) {
    var slot = document.getElementById("updateBanner");
    if (!slot) return;
    var s = ctx.status;
    var dismissed = false;
    try { dismissed = localStorage.getItem(UPD_DISMISS_KEY) === s.latest_version; } catch (e) {}
    if (!s.update_available || !s.latest_version || dismissed) {
      K.clear(slot); slot.hidden = true; return;
    }
    slot.hidden = false;
    var sec = !!s.latest_is_security;
    var children = [
      w.icon(sec ? "alert" : "bell"),
      h("span", { class: "banner__txt", text: I.t(sec ? "update.banner.security" : "update.banner", { version: s.latest_version }) })
    ];
    if (s.latest_url) {
      children.push(h("a", { class: "btn btn--ghost btn--sm", href: s.latest_url, target: "_blank", rel: "noopener", text: I.t("update.view") }));
    }
    children.push(h("button", {
      class: "icon-btn icon-btn--sm", "aria-label": I.t("update.dismiss"),
      onclick: function () {
        try { localStorage.setItem(UPD_DISMISS_KEY, s.latest_version); } catch (e) {}
        renderUpdateBanner(ctx);
      }
    }, w.icon("x")));
    K.mount(slot, h("div", { class: "banner " + (sec ? "banner--error" : "banner--info") }, children));
  }

  /* ---------- view render ---------- */
  function renderView(ctx) {
    ctx = ctx || buildCtx();
    markActive();
    var root = document.getElementById("view-" + state.view);
    var fn = V[state.view];
    if (fn) fn(root, ctx);
  }
  /* which view is shown, and which section control says so */
  function markActive() {
    var cur = sectionOf(state.view);
    SECTIONS.forEach(function (sec) {
      var on = sec === cur;
      sec.views.forEach(function (v) {
        var view = document.getElementById("view-" + v);
        if (view) view.hidden = (state.view !== v);
      });
      document.querySelectorAll('.nav__item[data-section="' + sec.id + '"], .tabbar__item[data-section="' + sec.id + '"], .more-pop__item[data-section="' + sec.id + '"]').forEach(function (el) {
        el.classList.toggle("is-active", on);
        if (on) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
      });
    });
    var gear = document.getElementById("gearBtn");
    gear.classList.toggle("is-active", cur.gear === true);
    if (cur.gear) gear.setAttribute("aria-current", "page"); else gear.removeAttribute("aria-current");
    /* More lights up for whichever section it holds */
    var more = document.getElementById("moreBtn");
    if (more) more.classList.toggle("is-active", PHONE_BAR.indexOf(cur.id) < 0);
  }

  /* ---------- drawer ---------- */
  function openDrawer(a) {
    state.drawer = { open: true, live: !!a.active, key: a.id || a.target, attack: a, returnFocus: document.activeElement };
    renderDrawer();
    document.getElementById("scrim").classList.add("is-open");
    var d = document.getElementById("drawer");
    d.classList.add("is-open"); d.removeAttribute("inert"); d.setAttribute("aria-hidden", "false");
    var f = d.querySelector("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
    (f || d).focus();
  }
  function renderDrawer() {
    if (!state.drawer.open) return;
    var a = state.drawer.attack;
    if (state.drawer.live) { var live = API.getAttacks().active[0]; if (live) { a = live; state.drawer.attack = a; } }
    var d = document.getElementById("drawer");
    K.mount(d, V.attackDetail(a, buildCtx()));
    /* if a re-render removed the focused control (e.g. attack ended → Withdraw
       button gone), keep focus inside the modal instead of dropping to <body> */
    if (document.activeElement === document.body) {
      var f = d.querySelector("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
      if (f) f.focus();
    }
  }
  function closeDrawer() {
    if (!state.drawer.open) return;
    var rf = state.drawer.returnFocus;
    state.drawer.open = false;
    document.getElementById("scrim").classList.remove("is-open");
    var d = document.getElementById("drawer");
    d.classList.remove("is-open"); d.setAttribute("inert", ""); d.setAttribute("aria-hidden", "true");
    if (rf && typeof rf.focus === "function") { try { rf.focus(); } catch (e) {} }
  }

  /* ---------- live region ---------- */
  function announce(msg) { var r = document.getElementById("liveRegion"); r.textContent = ""; setTimeout(function () { r.textContent = msg; }, 60); }
  function announceRung(ctx) {
    var a = ctx.attacks.active[0];
    var rung = a ? a.escalation_step : -1;
    if (rung === state.last.rung) return;
    if (a) {
      if (state.last.rung < 0) announce(I.t("posture.attack") + ": " + (a.scope === "group" ? a.group : a.target) + " — " + I.label("attackType", a.classification.type));
      else if (rung > 0 && a.escalation[rung]) announce(I.label("action", a.escalation[rung].action) + " — " + (a.target || a.group));
    }
    state.last.rung = rung;
  }

  /* ---------- actions ---------- */
  var actions = {
    setView: function (v) {
      state.view = v;
      state.lastTab[sectionOf(v).id] = v;
      setMore(false);
      renderView();
    },
    /* a section opens on the tab it was left on, if that tab is still there */
    setSection: function (id) {
      var sec = sectionById(id), shown = sectionViews(sec, API.getStatus());
      var v = state.lastTab[id];
      actions.setView(shown.indexOf(v) >= 0 ? v : (shown[0] || sec.views[0]));
      document.getElementById("main").scrollTop = 0;
    },
    setLocale: function (loc) { I.set(loc); buildShell(); renderShellDynamic(buildCtx()); renderView(); if (state.drawer.open) renderDrawer(); },
    setTheme: function (pref) { Theme.set(pref); },
    setFilter: function (k, v) { state.filters[k] = v; renderView(); },
    setHostDir: function (d) { state.hostDir = d; renderView(); },
    setOvUnit: function (u) { state.ovUnit = u; renderView(); },
    toggleHost: function (ip) { if (state.expanded.has(ip)) state.expanded.delete(ip); else state.expanded.add(ip); renderView(); },
    loadTraffic: function (key) {
      var t = state.traffic;
      if (t.loading) return;
      if (t.key === key && t.fetchedAt && Date.now() - t.fetchedAt < 30000) return; /* fresh enough */
      t.loading = true;
      var to = new Date(), from = new Date(Date.now() - 3600000);
      API.getTraffic(key, from.toISOString(), to.toISOString(), 60).then(function (r) {
        t.loading = false; t.key = key; t.fetchedAt = Date.now();
        t.available = r.available; t.points = r.points || [];
        if (state.view === "traffic") renderView();
      });
    },
    /* nodes inventory — same on-demand + freshness-guard shape as loadTraffic.
       10s: half a stale_after, so a lost node is never shown as up for longer
       than the API itself would claim it. */
    loadNodes: function () {
      var n = state.nodes;
      if (n.loading) return;
      /* half a stale_after (the value the API itself reports), capped at 10s:
         a lost node must never be shown as up longer than the API would say */
      var fresh = Math.min(10000, (n.staleAfter || 15) * 500);
      if (n.fetchedAt && Date.now() - n.fetchedAt < fresh) return;
      n.loading = true;
      API.getNodes().then(function (r) {
        n.loading = false; n.fetchedAt = Date.now();
        n.ok = r.ok; n.forbidden = !!r.forbidden;
        n.total = r.total; n.staleAfter = r.staleAfter; n.list = r.nodes;
        if (state.view === "nodes") renderView();
      });
    },
    /* edge zones status — the nodes' last windows merged; 10s freshness, the
       window's own length. The inventory is fetched alongside because only a
       node's own report says WHY it serves a zone over TCP (E5.5); the status
       alone decides whether the view renders, so an inventory that fails or is
       refused leaves the table intact and only the tooltip poorer. Each
       fetch carries its own freshness guard, so neither is ever lost to the
       other's timing. */
    /* `force` is the lever's (E6.8): after a write the row has to show what
       the operator just did, not what the last ten-second read saw. It is a
       FLAG rather than a cleared timestamp because a read may be in flight —
       that one stamps its own fetchedAt on the way out, which would swallow a
       cleared one; the flag survives it and the next render re-reads. */
    loadEdge: function (force) {
      actions.loadEdgeInv();
      var e = state.edge;
      if (force) e.stale = true;
      if (e.loading) return;
      if (!e.stale && e.fetchedAt && Date.now() - e.fetchedAt < 10000) return;
      e.stale = false;
      e.loading = true;
      API.getEdgeZones().then(function (r) {
        e.loading = false; e.fetchedAt = Date.now();
        e.ok = r.ok; e.forbidden = !!r.forbidden; e.skew = r.skew || 0;
        e.nodesAlive = r.nodesAlive; e.nodesReporting = r.nodesReporting; e.zonesTruncated = r.zonesTruncated || 0; e.zones = r.zones;
        if (state.view === "edge") renderView();
      });
    },
    /* ---- edge zone history (E6.7) ---- */
    /* Clicking the open zone's row again shuts the card: the row is the only
       control, so it has to be able to undo itself. */
    toggleEdgeZone: function (zone) {
      var e = state.edgeHist;
      if (e.zone === zone) { e.zone = null; renderView(); return; }
      /* `loading` is deliberately NOT cleared: a read for the zone just left
         may still be in flight, and clearing it would let this render start a
         second pair of ClickHouse queries beside it. The in-flight one is the
         one that resolves, sees the zone has changed and re-renders — which is
         where the new zone's read starts, once and not twice. */
      e.zone = zone; e.key = ""; e.fetchedAt = 0;
      e.ok = false; e.forbidden = false; e.notFound = false; e.available = false;
      e.stepSeconds = 0; e.points = []; e.srcOk = false; e.srcAvailable = false; e.sources = [];
      renderView();
    },
    setEdgeHistRange: function (r) {
      var e = state.edgeHist;
      if (!EDGE_RANGES[r] || e.range === r) return;
      e.range = r; e.key = ""; e.fetchedAt = 0;
      renderView();
    },
    /* The zone card's two reads, fetched together so the sources table and the
       charts always describe the SAME period — a partial refresh would caption
       one period's sources with another's range. Both resolve, neither
       rejects, so one failing never loses the other. */
    loadEdgeHistory: function () {
      var e = state.edgeHist;
      if (!e.zone || e.loading) return;
      var range = EDGE_RANGES[e.range] || EDGE_RANGES["1h"];
      var key = e.zone + "|" + e.range;
      if (e.key === key && e.fetchedAt && Date.now() - e.fetchedAt < 10000) return;
      e.loading = true;
      var zone = e.zone, rangeID = e.range, seq = ++e.seq;
      var to = new Date(), from = new Date(to.getTime() - range.seconds * 1000);
      var fromISO = from.toISOString(), toISO = to.toISOString();
      Promise.all([
        API.getEdgeHistory(zone, fromISO, toISO, range.step),
        API.getEdgeHistorySources(zone, fromISO, toISO, "")
      ]).then(function (res) {
        var h = res[0], s = res[1];
        /* only the newest read may write this state or release the guard: an
           answer overtaken by a later one has nothing left to say, and
           clearing `loading` for it would start a third read beside the
           second */
        if (seq !== e.seq) return;
        e.loading = false;
        /* the operator may have clicked another zone or another range while
           this was in flight — a late answer must not caption itself with the
           new selection; the re-render is where that selection's own read
           starts */
        if (e.zone !== zone || e.range !== rangeID) { renderView(); return; }
        e.fetchedAt = Date.now(); e.key = key;
        e.ok = h.ok; e.forbidden = !!h.forbidden; e.notFound = !!h.notFound;
        e.available = h.available; e.stepSeconds = h.stepSeconds || range.step; e.points = h.points;
        e.srcOk = s.ok; e.srcAvailable = s.available; e.sources = s.sources;
        if (state.view === "edge") renderView();
      });
    },
    loadEdgeEvents: function () {
      var v = state.edgeEvents;
      if (v.loading) return;
      /* a kapkan without the endpoint will not grow one while the page is
         open: asked once, answered 404, never asked again */
      if (v.absent) return;
      if (v.fetchedAt && Date.now() - v.fetchedAt < 10000) return;
      v.loading = true;
      var to = new Date(), from = new Date(to.getTime() - EDGE_EVENTS_SECONDS * 1000);
      API.getEdgeEvents(from.toISOString(), to.toISOString()).then(function (r) {
        v.loading = false; v.fetchedAt = Date.now();
        v.ok = r.ok; v.forbidden = !!r.forbidden; v.absent = !!r.absent; v.available = r.available; v.events = r.events;
        if (state.view === "edge") renderView();
      });
    },
    /* edge-node inventory (E6.7) — the loadNodes shape again: on demand, half
       a stale_after capped at 10s, so a node the brain has given up on is
       never shown as up for longer than the API itself would claim. A 403 is
       a state, not a failure: the inventory is unscoped-only. */
    loadEdgeInv: function () {
      var n = state.edgeInv;
      if (n.loading) return;
      var fresh = Math.min(10000, (n.staleAfter || 15) * 500);
      if (n.fetchedAt && Date.now() - n.fetchedAt < fresh) return;
      n.loading = true;
      API.getEdgeNodes().then(function (r) {
        n.loading = false; n.fetchedAt = Date.now();
        n.ok = r.ok; n.forbidden = !!r.forbidden;
        n.total = r.total; n.staleAfter = r.staleAfter;
        n.list = r.nodes; n.unbound = r.unbound || [];
        if (state.view === "edgenodes" || state.view === "edge") renderView();
      });
    },
    /* ---- the lever (E6.8) ----
       The only write in the Edge view. Both hand the whole answer back to the
       dialog that asked — it is the one place a refusal can be read, and it
       stays open to show it — and on success force the zones status to be
       re-read at once rather than up to ten seconds later. `done` is called
       for a failure too: a dialog left spinning on a refused call would be the
       console pretending the brain never answered. */
    setEdgeChallenge: function (zone, mode, ttlSeconds, reason, done) {
      API.setEdgeChallenge(zone, mode, ttlSeconds, reason).then(function (r) {
        if (r.ok) actions.loadEdge(true);
        done(r);
      });
    },
    clearEdgeChallenge: function (zone, done) {
      API.clearEdgeChallenge(zone).then(function (r) {
        if (r.ok) actions.loadEdge(true);
        done(r);
      });
    },
    /* the Edge view's tenant chips; "" is every tenant */
    setEdgeTenant: function (t) {
      state.edgeTenant = t;
      try { sessionStorage.setItem(TENANT_KEY, t); } catch (e) {}
      renderView();
    },
    /* Forget a saved choice that names no tenant on screen. The view calls it
       WHILE rendering — it has just decided to draw the unfiltered table — so
       it must not render again; it only makes the store agree with what the
       operator is looking at, instead of leaving behind a filter that would
       switch itself back on when that tenant's zones returned. The key is
       written in this file and nowhere else. */
    clearEdgeTenant: function () {
      state.edgeTenant = "";
      try { sessionStorage.removeItem(TENANT_KEY); } catch (e) {}
    },
    openDrawer: openDrawer, closeDrawer: closeDrawer,
    withdraw: function (anchor, target) {
      K.confirm(anchor, { title: I.t("ac.withdraw"), text: I.t("ac.withdraw.confirm", { t: target }), danger: true, confirmLabel: I.t("ac.withdraw"),
        onConfirm: function () { API.unban(target).then(function (r) { K.toast(r.ok ? I.t("ac.withdraw.ok") : I.t("reject.label"), r.ok ? "ok" : "err"); if (state.drawer.live) closeDrawer(); poll(); }); } });
    },
    ban: function (ip) {
      API.ban(ip).then(function (res) {
        if (res.ok) K.toast(I.t("bn.ban.ok", { t: ip }), "ok");
        else K.toast(I.t("reject.label") + ": " + ({ whitelisted: I.t("reject.whitelisted"), outside_networks: I.t("reject.outside"), cap: I.t("reject.cap") }[res.reason] || res.reason), "err");
        poll();
      });
    },
    unban: function (anchor, ip) {
      if (anchor) { K.confirm(anchor, { title: I.t("bn.unban"), text: I.t("bn.unban.confirm", { t: ip }), confirmLabel: I.t("bn.unban"), onConfirm: function () { doUnban(ip); } }); }
      else doUnban(ip);
    },
    reload: function (anchor) {
      K.confirm(anchor, { title: I.t("reload.confirm.title"), text: I.t("reload.confirm.text"), onConfirm: function () { API.reload().then(function (r) { K.toast(r.ok ? I.t("reload.ok") : I.t("reject.label"), r.ok ? "ok" : "err"); poll(); }); } });
    }
  };
  function doUnban(ip) { API.unban(ip).then(function (r) { K.toast(r.ok ? I.t("bn.unban.ok", { t: ip }) : I.t("reject.label"), r.ok ? "ok" : "err"); poll(); }); }

  /* ---------- render + poll (3s) ---------- */
  /* Incremental reconcile (K.mount) keeps node identity, so the poll re-renders
     unconditionally without stealing focus, wiping drafts, resetting scroll, or
     restarting animations — no focus-skip / preserve workarounds needed. */
  function render() {
    var st = API.getStatus(); if (st && st.role) state.role = st.role;
    var ctx = buildCtx();
    renderShellDynamic(ctx);
    renderUpdateBanner(ctx);
    renderView(ctx);
    if (state.drawer.open) renderDrawer();
    announceRung(ctx);
  }
  function poll() {
    return API.refresh().then(function () {
      state.online = true; pushBuf(Date.now()); render();
    }, function (e) {
      if (w.console) w.console.warn("poll failed", e);
      state.online = false;
      renderShellDynamic(buildCtx());   /* the duty light goes out; the views keep the last good data */
    }).catch(function (e) { if (w.console) w.console.warn("render failed", e); });
  }

  /* ---------- ticker (1s) — countdowns + bars only ---------- */
  function tick() {
    var now = Date.now();
    document.querySelectorAll("[data-cd-target]").forEach(function (el) {
      el.textContent = I.countdown((parseInt(el.dataset.cdTarget, 10) - now) / 1000);
    });
    document.querySelectorAll("[data-bar-start]").forEach(function (el) {
      var s = parseInt(el.dataset.barStart, 10), e = parseInt(el.dataset.barEnd, 10);
      el.style.width = Math.max(0, Math.min(100, (now - s) / (e - s) * 100)) + "%";
    });
  }

  /* close the More sheet on an outside click / esc */
  document.addEventListener("click", function (e) {
    if (state.moreOpen && !document.getElementById("tabbar").contains(e.target)) setMore(false);
  });
  document.getElementById("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      if (state.moreOpen) { setMore(false); var mb = document.getElementById("moreBtn"); if (mb) mb.focus(); }
      closeDrawer(); K.closeConfirm(); return;
    }
    /* trap Tab within the open drawer (skip while a confirm popover is up) */
    if (e.key === "Tab" && state.drawer.open && !document.getElementById("__confirm")) {
      var d = document.getElementById("drawer");
      var f = d.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (!d.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });

  /* ---------- boot ---------- */
  function boot() {
    I.init();
    API.init();
    buildShell();
    /* a theme change (the bar's switch, Settings, or the OS while "as the
       system" is chosen) re-labels the switch and redraws the view, so the
       Settings choice it shows stays true */
    Theme.onChange(function () { buildShell(); renderShellDynamic(buildCtx()); renderView(); });
    API.refresh().then(function () { state.online = true; prefill(); pushBuf(Date.now()); }).catch(function () {}).then(function () {
      render();
      setInterval(poll, API.POLL_MS);
      setInterval(tick, 1000);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})(window);
