/* app.js — shell, routing, polling, state. Boots after all modules load.
   Data comes from the real same-origin /api/v1 endpoints via the api.js
   adapter: the synchronous getters read its cache, refreshed each 3s poll. */
(function (w) {
  "use strict";
  var K = w.K, I = w.I18N, h = K.h, API = w.API, V = w.Views;

  var NAV = [
    { id: "overview", icon: "shield", key: "nav.overview", section: "monitor" },
    { id: "attacks", icon: "alert", key: "nav.attacks", section: "monitor", count: "attacks" },
    { id: "bans", icon: "ban", key: "nav.bans", section: "monitor", count: "bans" },
    { id: "hosts", icon: "server", key: "nav.hosts", section: "monitor" },
    { id: "hostgroups", icon: "layers", key: "nav.hostgroups", section: "config" },
    { id: "traffic", icon: "chart", key: "nav.traffic", section: "config" },
    { id: "settings", icon: "settings", key: "nav.settings", section: "config" }
  ];
  var WINDOW = 60;

  var state = {
    view: "overview",
    role: "viewer", /* least privilege until /status reports the caller's role */
    collapsed: false,
    hostDir: "incoming",
    filters: { scope: "", dir: "", type: "", group: "", q: "" },
    expanded: new Set(),
    drawer: { open: false, live: false, key: null, attack: null },
    localeOpen: false,
    buf: { aggIn: [], aggOut: [], attacks: [], bans: [], hosts: [], inAttack: [], hostPps: {} },
    traffic: { key: null, available: false, points: [], loading: false, fetchedAt: 0 },
    last: { rung: -1 }
  };

  /* ---------- buffers ---------- */
  function pushBuf() {
    var s = API.getStatus(), agg = API.aggregate(), hostsData = API.getHosts().hosts;
    var b = state.buf;
    push(b.aggIn, agg.in_mbps); push(b.aggOut, agg.out_mbps);
    push(b.attacks, s.active_attacks); push(b.bans, s.active_bans);
    push(b.hosts, hostsData.length); push(b.inAttack, s.active_attacks > 0);
    hostsData.forEach(function (host) {
      if (!b.hostPps[host.target]) b.hostPps[host.target] = [];
      push(b.hostPps[host.target], host.rates.pps);
    });
  }
  function push(arr, v) { arr.push(v); if (arr.length > WINDOW) arr.shift(); }
  function prefill() { for (var i = 0; i < 24; i++) pushBuf(); }

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
      agg: agg, buf: state.buf, posture: derivePosture(attacks), dryRun: status.dry_run, role: state.role,
      state: state, actions: actions
    };
  }

  /* ---------- shell (built once / on locale change) ---------- */
  function buildShell() {
    K.clear(document.getElementById("brandMark")).appendChild(w.icon("shield"));

    /* nav */
    var nav = K.clear(document.getElementById("nav"));
    var sections = { monitor: I.t("nav.section.monitor"), config: I.t("nav.section.config") };
    var lastSection = null;
    NAV.forEach(function (item) {
      if (item.section !== lastSection) { nav.appendChild(h("div", { class: "nav__label", text: sections[item.section] })); lastSection = item.section; }
      var countEl = item.count ? h("span", { class: "nav__count", dataset: { count: item.count }, text: "0" }) : null;
      var btn = h("button", { class: "nav__item" + (state.view === item.id ? " is-active" : ""), dataset: { view: item.id },
        onclick: function () { actions.setView(item.id); } },
        [w.icon(item.icon, "ico"), h("span", { class: "nav__item__txt", text: I.t(item.key) }), countEl]);
      nav.appendChild(btn);
    });

    /* role indicator slot (read-only; the real role comes from the API token) */
    K.clear(document.getElementById("roleToggle"));

    /* collapse */
    var cb = K.clear(document.getElementById("collapseBtn")); cb.appendChild(w.icon("menu"));
    cb.onclick = function () { state.collapsed = !state.collapsed; document.getElementById("app").classList.toggle("is-collapsed", state.collapsed); };

    /* live indicator label */
    document.querySelector("#liveInd .live__txt").textContent = I.t("live.label");
    document.getElementById("liveInd").classList.add("is-polling");

    /* locale menu */
    buildLocaleMenu();

    /* no demo controls in production */
    K.clear(document.getElementById("demoCtl"));

    /* reload button (visibility set per-poll from role) */
    var rb = K.clear(document.getElementById("reloadBtn"));
    rb.appendChild(w.icon("refresh")); rb.appendChild(h("span", { text: I.t("btn.reload") }));
    rb.onclick = function (e) { actions.reload(e.currentTarget); };
    rb.style.display = "none";
  }

  function buildLocaleMenu() {
    var menu = K.clear(document.getElementById("localeMenu"));
    menu.className = "menu" + (state.localeOpen ? " is-open" : "");
    var btn = h("button", { class: "icon-btn", attrs: { "aria-haspopup": "true", "aria-expanded": String(state.localeOpen), title: I.t("locale.title") },
      onclick: function (e) { e.stopPropagation(); state.localeOpen = !state.localeOpen; buildLocaleMenu(); } },
      [w.icon("globe")]);
    var loaded = { en: 1, de: 1, ru: 1, fr: 1, es: 1 };
    var items = I.available.map(function (l) {
      var on = l.code === I.locale, isLoaded = loaded[l.code];
      return h("button", { class: "menu__item" + (on ? " is-on" : ""), attrs: isLoaded ? {} : { disabled: "true", title: I.t("locale.soon.title") },
        onclick: isLoaded ? function () { actions.setLocale(l.code); } : null }, [
        h("span", { class: "menu__flag", text: l.flag }),
        h("span", { text: l.label }),
        isLoaded ? null : K.badge("badge--muted", I.t("locale.soon")),
        w.icon("check-sm", "check")
      ]);
    });
    var pop = h("div", { class: "menu__pop" }, items);
    menu.appendChild(btn); menu.appendChild(pop);
  }

  /* ---------- dynamic topbar (every poll) ---------- */
  function renderShellDynamic(ctx) {
    K.mount(document.getElementById("posturePill"), K.posturePill(ctx.posture));
    K.mount(document.getElementById("modeBadge"), K.modeBadge(ctx.status.dry_run));

    var counters = K.clear(document.getElementById("counters"));
    var defs = [
      { key: "counter.attacks", val: ctx.status.active_attacks, hot: ctx.status.active_attacks > 0 },
      { key: "counter.bans", val: ctx.status.active_bans, hot: ctx.status.active_bans > 0 },
      { key: "counter.hosts", val: ctx.hosts.length },
      { key: "counter.networks", val: ctx.networks.length }
    ];
    defs.forEach(function (d) {
      counters.appendChild(h("div", { class: "counter" + (d.hot ? " is-hot" : "") }, [
        h("span", { class: "counter__val", text: I.num(d.val) }), h("span", { class: "counter__lbl", text: I.t(d.key) })
      ]));
    });

    /* nav counts */
    document.querySelectorAll(".nav__count").forEach(function (el) {
      var v = el.dataset.count === "attacks" ? ctx.status.active_attacks : ctx.status.active_bans;
      el.textContent = I.num(v);
      el.classList.toggle("is-hot", v > 0);
      el.style.display = v > 0 ? "" : "none";
    });

    document.getElementById("lastUpdated").textContent = I.time(new Date());

    /* operator-only reload button */
    var rb = document.getElementById("reloadBtn");
    if (rb) rb.style.display = ctx.role === "operator" ? "" : "none";
  }

  /* ---------- view render ---------- */
  function renderView(ctx) {
    ctx = ctx || buildCtx();
    NAV.forEach(function (item) {
      var el = document.querySelector('.nav__item[data-view="' + item.id + '"]');
      if (el) el.classList.toggle("is-active", state.view === item.id);
      var view = document.getElementById("view-" + item.id);
      if (view) view.hidden = (state.view !== item.id);
    });
    var root = document.getElementById("view-" + state.view);
    var fn = V[state.view];
    if (fn) preserveAround(document.getElementById("main"), function () { fn(root, ctx); });
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
    var bodyEl = d.querySelector(".drawer__body"), sc = bodyEl ? bodyEl.scrollTop : 0;
    K.mount(d, V.attackDetail(a, buildCtx()));
    var nb = d.querySelector(".drawer__body"); if (nb) nb.scrollTop = sc;
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
    setView: function (v) { state.view = v; renderView(); },
    setLocale: function (loc) { I.set(loc); state.localeOpen = false; buildShell(); renderShellDynamic(buildCtx()); renderView(); if (state.drawer.open) renderDrawer(); },
    setFilter: function (k, v) { state.filters[k] = v; renderView(); },
    setHostDir: function (d) { state.hostDir = d; renderView(); },
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
  /* Skip the structural re-render while the user is mid-interaction so the 3s
     poll never steals focus, wipes a draft, or closes an open menu/popover. */
  function userBusy() {
    if (document.getElementById("__confirm")) return true;
    if (state.localeOpen) return true;
    var a = document.activeElement;
    return !!(a && (a.tagName === "INPUT" || a.tagName === "SELECT" || a.tagName === "TEXTAREA"));
  }
  /* Re-mount destroys nodes; capture+restore focus, caret, an uncontrolled
     input's draft, and scroll so a re-render is visually/behaviorally seamless. */
  function preserveAround(scrollEl, fn) {
    var a = document.activeElement, fk = null;
    if (a && a.id && (a.tagName === "INPUT" || a.tagName === "TEXTAREA")) {
      fk = { id: a.id, value: a.value };
      try { fk.start = a.selectionStart; fk.end = a.selectionEnd; } catch (e) {}
    } else if (a && a.id && a.tagName === "SELECT") {
      fk = { id: a.id };
    }
    var sc = scrollEl ? scrollEl.scrollTop : 0;
    fn();
    if (scrollEl) scrollEl.scrollTop = sc;
    if (fk) {
      var el = document.getElementById(fk.id);
      if (el) {
        if (fk.value != null && !el.value) el.value = fk.value;
        try { el.focus(); if (fk.start != null && el.setSelectionRange) el.setSelectionRange(fk.start, fk.end); } catch (e) {}
      }
    }
  }
  function render() {
    var st = API.getStatus(); if (st && st.role) state.role = st.role;
    var ctx = buildCtx();
    renderShellDynamic(ctx);
    if (!userBusy()) {
      renderView(ctx);
      /* don't re-mount the drawer out from under keyboard focus inside it */
      var dr = document.getElementById("drawer");
      if (state.drawer.open && !dr.contains(document.activeElement)) renderDrawer();
    }
    announceRung(ctx);
  }
  function poll() {
    return API.refresh().then(function () { pushBuf(); render(); })
      .catch(function (e) { if (w.console) w.console.warn("poll failed", e); });
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

  /* close menus on outside click / esc */
  document.addEventListener("click", function (e) {
    if (state.localeOpen && !document.getElementById("localeMenu").contains(e.target)) { state.localeOpen = false; buildLocaleMenu(); }
  });
  document.getElementById("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { closeDrawer(); K.closeConfirm(); if (state.localeOpen) { state.localeOpen = false; buildLocaleMenu(); } return; }
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
    API.refresh().then(function () { prefill(); }).catch(function () {}).then(function () {
      render();
      setInterval(poll, API.POLL_MS);
      setInterval(tick, 1000);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})(window);
