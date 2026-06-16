/* api.js — production data layer for the operator console.
   Replaces the prototype's mock-api.js. It calls the real same-origin
   /api/v1 endpoints (connect-src 'self') and normalizes their JSON into the
   exact field vocabulary the views/components already consume, so the UI code
   is left untouched.

   The UI reads data SYNCHRONOUSLY (API.getStatus(), getHosts(), ...). fetch is
   async, so this layer keeps a CACHE that the synchronous getters read, and an
   async refresh() (driven by app.js's 3s poll) that re-fetches and re-maps.

   Auth: a bearer token (sessionStorage) is attached to every request; a 401
   prompts for one and retries once. Mutating POSTs send application/json. */
(function (w) {
  "use strict";

  var POLL_MS = 3000;
  var TOKEN_KEY = "kapkan.token";

  /* ---- cache the synchronous getters read ---- */
  var cache = {
    status: { dry_run: false, uptime_seconds: 0, active_attacks: 0, active_bans: 0,
      hostgroups: [], networks: [], thresholds: null, role: "viewer" },
    attacks: { active: [], recent: [] },
    hosts: [],
    bansActive: [],
    bansHistory: [],
    groups: [],
    networks: []
  };
  /* rejected manual bans aren't in GET /bans (rejections are returned by POST
     /ban as a 409 body); keep them client-side so the history shows them. */
  var rejections = [];

  /* ============ auth ============ */
  function getToken() { try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; } }
  function setToken(t) { try { sessionStorage.setItem(TOKEN_KEY, t); } catch (e) {} }

  function request(path, opts, retried) {
    opts = opts || {};
    var headers = {};
    var k; for (k in (opts.headers || {})) headers[k] = opts.headers[k];
    var t = getToken();
    if (t) headers["Authorization"] = "Bearer " + t;
    var init = { method: opts.method || "GET", headers: headers, credentials: "same-origin" };
    if (opts.body != null) init.body = opts.body;
    return fetch(path, init).then(function (res) {
      if (res.status === 401 && !retried) {
        var entered = w.prompt("Kapkan API token");
        if (entered) { setToken(entered); return request(path, opts, true); }
      }
      return res;
    });
  }
  function getJSON(path) {
    return request(path).then(function (res) {
      if (!res.ok) throw new Error(path + " -> " + res.status);
      return res.json();
    });
  }

  /* ============ mapping helpers ============ */

  /* TCP flag bitmask -> short string (FIN SYN RST PSH ACK URG ECE CWR). */
  function flagsToString(bits) {
    if (!bits) return "";
    var names = [[1, "F"], [2, "S"], [4, "R"], [8, "P"], [16, "A"], [32, "U"], [64, "E"], [128, "C"]];
    var out = "";
    names.forEach(function (n) { if (bits & n[0]) out += n[1]; });
    return out;
  }
  var PROTO_NAME = { 1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6" };
  function protoName(p) { return PROTO_NAME[p] || (p ? String(p) : "any"); }

  /* real mitigate.FlowSpecRule -> {match, action} display object the UI wants. */
  function flowspecRule(r) {
    var parts = [];
    if (r.dst) parts.push("dst " + r.dst);
    if (r.src) parts.push("src " + r.src);
    if (r.proto) parts.push("proto " + protoName(r.proto));
    if (r.src_port) parts.push("src-port " + r.src_port);
    if (r.dst_port) parts.push("dst-port " + r.dst_port);
    if (r.tcp_flags) parts.push("tcp-flags " + flagsToString(r.tcp_flags));
    if (r.fragment) parts.push("fragment");
    return { match: parts.join(", "), action: r.action === "rate_limit" ? "rate_limit" : r.action };
  }
  function mapFlowspec(list) { return (list || []).map(flowspecRule); }

  function mapSample(s) {
    if (!s) return null;
    var flows = (s.flows || []).map(function (f) {
      return {
        src: f.src, dst: f.dst, src_port: f.src_port, dst_port: f.dst_port,
        proto: f.proto, flags: flagsToString(f.tcp_flags), fragment: !!f.fragment,
        bytes: f.bytes, packets: f.packets, sampling_rate: f.sampling_rate
      };
    });
    return {
      flows: flows,
      top_sources: s.top_sources || [], top_src_ports: s.top_src_ports || [],
      top_dst_ports: s.top_dst_ports || [], protocols: s.protocols || [],
      total_packets: s.total_packets || 0
    };
  }

  /* real config.Group -> UI hostgroup vocabulary. */
  function mapGroup(g) {
    var baseline = g.baseline
      ? { enabled: true, factor: g.baseline.factor, warmup_seconds: g.baseline.warmup_seconds, floor: g.baseline.floor }
      : null;
    return {
      name: g.name,
      calc: g.calculation,
      thresholds: g.thresholds || {},
      mitigation: g.mitigation,
      ban_enabled: !!g.ban,
      escalation: g.escalation || [],
      baseline: baseline,
      next_hop: g.blackhole_next_hop || null,
      community: g.blackhole_communities || null,
      local_pref: g.blackhole_local_pref != null ? g.blackhole_local_pref : null,
      scrub_next_hop: g.scrub_next_hop || null
    };
  }

  /* real engine.HostStat -> UI host vocabulary (out_rates/out_baseline). */
  function mapHost(hs) {
    return {
      target: hs.target, group: hs.group,
      rates: hs.rates || {}, out_rates: hs.rates_out || {},
      baseline: hs.baseline || null, out_baseline: hs.baseline_out || null,
      in_attack: !!hs.in_attack, metric: hs.metric, direction: hs.direction
    };
  }

  function normalizeReason(reason) {
    if (!reason) return reason;
    if (reason.indexOf("whitelist") >= 0) return "whitelisted";
    if (reason.indexOf("outside") >= 0) return "outside_networks";
    if (reason.indexOf("max_active") >= 0 || reason.indexOf("cap") >= 0) return "cap";
    return reason;
  }
  function mapBan(b) {
    var nb = {};
    var k; for (k in b) nb[k] = b[k];
    nb.reason = normalizeReason(b.reason);
    nb.flowspec = b.flowspec ? mapFlowspec(b.flowspec) : null;
    /* real prefix is a full CIDR ("203.0.113.66/32"); the UI renders it next to
       the target, so reduce it to the "/NN" suffix to avoid showing the IP twice. */
    if (typeof nb.prefix === "string" && nb.prefix.indexOf("/") >= 0) nb.prefix = "/" + nb.prefix.split("/").pop();
    return nb;
  }

  /* The real Attack carries no escalation/escalation_step (those live on Ban).
     Reconstruct the ladder so the signature component works for the whole arc:
       - prefer the matching active Ban's escalation + step;
       - else use the owning group's configured ladder and derive the step from
         elapsed time since started_at (mirrors the engine's rung advancement). */
  function deriveEscalation(a, groups, bansRaw) {
    var ban = null, i;
    for (i = 0; i < bansRaw.length; i++) {
      if (bansRaw[i].target === a.target && bansRaw[i].state === "active") { ban = bansRaw[i]; break; }
    }
    if (ban && ban.escalation && ban.escalation.length) {
      return { escalation: ban.escalation, step: ban.escalation_step || 0, ban: ban };
    }
    var grp = null;
    for (i = 0; i < groups.length; i++) if (groups[i].name === a.group) { grp = groups[i]; break; }
    var esc = grp && grp.escalation && grp.escalation.length ? grp.escalation : null;
    if (!esc) return { escalation: [{ after_seconds: 0, action: a.method || "none" }], step: 0, ban: null };
    var endMs = a.ended_at ? new Date(a.ended_at).getTime() : Date.now();
    var elapsed = (endMs - new Date(a.started_at).getTime()) / 1000;
    var step = 0;
    for (i = 0; i < esc.length; i++) if (elapsed >= esc[i].after_seconds) step = i;
    return { escalation: esc, step: step, ban: null };
  }

  function mapAttack(a, groups, bansRaw) {
    var d = deriveEscalation(a, groups, bansRaw);
    var out = {
      scope: a.scope, target: a.target, group: a.group, direction: a.direction,
      metric: a.metric, rate: a.rate, threshold: a.threshold, rates: a.rates || {},
      active: !!a.active, ban_state: a.ban_state, method: a.method, route: a.route,
      flowspec: a.flowspec ? mapFlowspec(a.flowspec) : null,
      dry_run: !!a.dry_run, started_at: a.started_at, ended_at: a.ended_at,
      sample: mapSample(a.sample),
      classification: a.classification || { type: "mixed", confidence: 0 },
      escalation: d.escalation, escalation_step: d.step,
      /* recent table reads peak_rate; the API exposes the last measurement
         (rate), not a stored peak — surface it until /api/v1/traffic lands. */
      peak_rate: a.rate
    };
    /* For a live attack with a current ban, prefer the ban's current rung
       artifacts so the mitigation panel tracks escalation in real time. */
    if (d.ban) {
      out.method = d.ban.method || out.method;
      out.route = d.ban.route || out.route;
      if (d.ban.flowspec) out.flowspec = mapFlowspec(d.ban.flowspec);
      out.next_hop = d.ban.next_hop;
      out.community = d.ban.community;
      out.local_pref = d.ban.local_pref;
    }
    return out;
  }

  /* ============ refresh: fetch all four reads, map into cache ============ */
  function refresh() {
    return Promise.all([
      getJSON("/api/v1/status"),
      getJSON("/api/v1/attacks"),
      getJSON("/api/v1/hosts"),
      getJSON("/api/v1/bans")
    ]).then(function (r) {
      var status = r[0], attacks = r[1], hostsResp = r[2], bansResp = r[3];
      var groups = (status.hostgroups || []).map(mapGroup);
      var bansRaw = bansResp.bans || [];

      cache.groups = groups;
      cache.networks = status.networks || [];
      cache.status = {
        dry_run: !!status.dry_run,
        uptime_seconds: status.uptime_seconds || 0,
        active_attacks: status.active_attacks || 0,
        active_bans: status.active_bans || 0,
        hostgroups: groups,
        networks: cache.networks,
        thresholds: status.thresholds || null,
        role: status.role || "operator"
      };
      cache.attacks = {
        active: (attacks.active || []).map(function (a) { return mapAttack(a, groups, bansRaw); }),
        recent: (attacks.recent || []).map(function (a) { return mapAttack(a, groups, bansRaw); })
      };
      cache.hosts = (hostsResp.hosts || []).map(mapHost);
      cache.bansActive = bansRaw.filter(function (b) { return b.state === "active"; }).map(mapBan);
      cache.bansHistory = bansRaw.filter(function (b) { return b.state !== "active"; }).map(mapBan);
    });
  }

  /* ============ public API (mock-api shaped) ============ */
  w.API = {
    POLL_MS: POLL_MS,
    init: function () {},
    refresh: refresh,

    getStatus: function () { return cache.status; },
    getAttacks: function () { return cache.attacks; },
    getHosts: function () { return { hosts: cache.hosts }; },
    getBans: function () { return { active: cache.bansActive, history: rejections.concat(cache.bansHistory) }; },
    getHostgroups: function () { return cache.groups; },
    getNetworks: function () { return cache.networks; },
    /* historical traffic for one host (Traffic/Reports view). Resolves to
       {available:false} when the engine has no ClickHouse storage. */
    getTraffic: function (key, fromISO, toISO, step) {
      var qs = "key=" + encodeURIComponent(key);
      if (fromISO) qs += "&from=" + encodeURIComponent(fromISO);
      if (toISO) qs += "&to=" + encodeURIComponent(toISO);
      if (step) qs += "&step=" + step;
      return getJSON("/api/v1/traffic?" + qs)
        .then(function (r) { return { available: !!r.available, points: r.points || [] }; })
        .catch(function () { return { available: false, points: [] }; });
    },
    aggregate: function () {
      var inM = 0, outM = 0, inP = 0, outP = 0;
      cache.hosts.forEach(function (hHost) {
        inM += hHost.rates.mbps || 0; inP += hHost.rates.pps || 0;
        outM += hHost.out_rates.mbps || 0; outP += hHost.out_rates.pps || 0;
      });
      return { in_mbps: inM, out_mbps: outM, in_pps: inP, out_pps: outP };
    },

    ban: function (ip) {
      return request("/api/v1/ban", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: ip })
      }).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) {
          if (res.ok) return { ok: true, ban: mapBan(body) };
          if (res.status === 409) { var b = mapBan(body); rejections.unshift(b); return { ok: false, reason: b.reason }; }
          if (res.status === 403) return { ok: false, reason: "cross_tenant" };
          return { ok: false, reason: (body && body.error) || "error" };
        });
      });
    },
    unban: function (ip) {
      return request("/api/v1/unban", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: ip })
      }).then(function (res) { return { ok: res.ok }; });
    },
    reload: function () {
      return request("/api/v1/config/reload", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}"
      }).then(function (res) { return { ok: res.ok }; });
    }
  };
})(window);
