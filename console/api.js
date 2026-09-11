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
      hostgroups: [], networks: [], thresholds: null, role: "viewer",
      dataplane_dry_run: false, dataplane: null },
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
        /* refresh() fires four reads in parallel, so a first load gets four
           simultaneous 401s. Each w.prompt is synchronous and blocking, so the
           first 401 handler stores the token before the others run — they see
           it changed and retry silently instead of prompting again. */
        if (getToken() !== t) return request(path, opts, true);
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
        bytes: f.bytes, packets: f.packets, sampling_rate: f.sampling_rate,
        src_asn: f.src_asn || 0, src_org: f.src_org || "", src_country: f.src_country || ""
      };
    });
    return {
      flows: flows,
      top_sources: s.top_sources || [], top_src_ports: s.top_src_ports || [],
      top_dst_ports: s.top_dst_ports || [], protocols: s.protocols || [],
      top_asns: s.top_asns || [],
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
      /* measured in-kernel drops; null for every attack with no XDP rules.
         Passed through verbatim — the engine already shaped it. */
      dataplane: a.dataplane || null,
      dry_run: !!a.dry_run, started_at: a.started_at, ended_at: a.ended_at,
      sample: mapSample(a.sample),
      classification: a.classification || { type: "mixed", confidence: 0 },
      reason: a.reason || null,
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
      /* The ban's counters move every scrape; the attack record's were taken
         when it was detected. Prefer the live ones for a live attack. */
      if (d.ban.dataplane) out.dataplane = d.ban.dataplane;
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
        role: status.role || "operator",
        unscoped: !!status.unscoped,
        /* Settings view fields (admin-only ones are absent for scoped tokens) */
        version: status.version || "",
        /* update availability (opt-in update check; false/empty when disabled) */
        update_available: !!status.update_available,
        latest_version: status.latest_version || "",
        latest_is_security: !!status.latest_is_security,
        latest_url: status.latest_url || "",
        bgp: status.bgp || null,
        scrubbing: status.scrubbing || null,
        notify: status.notify || null,
        /* XDP data plane. The scalar is sent to EVERY role and defaults to
           false, so the dry-run banner logic never has to distinguish "no data
           plane" from "an older kapkan that does not send the field". The
           `dataplane` object is admin-only (it names interfaces) and is null for
           a scoped token — anything rendering it must handle that. */
        dataplane_dry_run: !!status.dataplane_dry_run,
        dataplane: status.dataplane || null,
        /* managed scrubbing nodes, COUNT only, sent to every role: it gates
           the Nodes nav item and the node column in bans. The inventory
           itself is a separate, admin-only fetch (getNodes). */
        nodes_total: status.nodes_total || 0,
        /* edge nodes, COUNT only, for every role: gates the Edge view (E4.5) */
        edge_nodes_total: status.edge_nodes_total || 0
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
    /* scrubbing-node inventory (Nodes view). Fetched on demand — app.js holds
       the freshness guard — never in the 3s refresh. A 403 (scoped token: the
       inventory is topology) is reported as forbidden, not as an error. */
    getNodes: function () {
      return request("/api/v1/dataplane/nodes").then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, total: 0, staleAfter: 15, nodes: [] };
        if (!res.ok) throw new Error("nodes -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, forbidden: false, total: r.nodes_total || 0,
            staleAfter: r.stale_after_seconds || 15, nodes: r.nodes || [] };
        });
      }).catch(function () { return { ok: false, forbidden: false, total: 0, staleAfter: 15, nodes: [] }; });
    },
    /* edge zones status (Edge view, E4.5): the alive edge nodes' last windows
       merged per zone, with the "who would be challenged" set. On demand like
       getNodes; a 403 (scoped token: node names are topology) is forbidden,
       not an error. */
    getEdgeZones: function () {
      return request("/api/v1/edge/zones/status").then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, nodesAlive: 0, nodesReporting: 0, zonesTruncated: 0, zones: [] };
        if (!res.ok) throw new Error("edge -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, forbidden: false, nodesAlive: r.nodes_alive || 0, nodesReporting: r.nodes_reporting || 0, zonesTruncated: r.zones_truncated || 0, zones: r.zones || [] };
        });
      }).catch(function () { return { ok: false, forbidden: false, nodesAlive: 0, nodesReporting: 0, zonesTruncated: 0, zones: [] }; });
    },
    /* edge-node inventory. Two readers, one fetch:
         - the Edge nodes view (E6.7) renders the whole document — each node's
           placement scope, the agent tokens bound to it and its last report;
         - the Edge view's HTTP/3 cell (E5.5) reads only terminator.h3 for the
           per-node detail the merged zone status cannot carry.
       Unscoped tokens only, like the scrub inventory: a 403 is reported as
       FORBIDDEN, not as an error, so the Edge nodes view can show the
       admin-only notice and the HTTP/3 tooltip can degrade to bare node names
       instead of the table claiming an empty fleet.
       unbound_agent_tokens is absent once every agent token is bound. */
    getEdgeNodes: function () {
      return request("/api/v1/edge/nodes").then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, total: 0, staleAfter: 15, nodes: [], unbound: [] };
        if (!res.ok) throw new Error("edge nodes -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, forbidden: false, total: r.nodes_total || 0,
            staleAfter: r.stale_after_seconds || 15, nodes: r.nodes || [],
            unbound: r.unbound_agent_tokens || [] };
        });
      }).catch(function () { return { ok: false, forbidden: false, total: 0, staleAfter: 15, nodes: [], unbound: [] }; });
    },
    /* ---- edge history (E6.6 reads; the Edge view's zone card) ----
       All three are on-demand reads with a freshness guard in app.js, never
       part of the 3s poll: they hit ClickHouse, and the windows they read are
       ten seconds long.

       Three answers are distinct and must stay so:
         available:false — storage is off. NOT an error and NOT an empty
           period: the engine never looked at the zone, so the view shows the
           same "enable storage" ghost the Traffic view uses.
         forbidden — 403. A tenant-scoped token on another tenant's zone, or
           on /edge/events at all (the events name nodes). The element is
           hidden rather than shown as an error: the answer is deliberately
           uninformative, so there is nothing to report.
         ok:false — a real failure (502, a dropped connection). Said out loud,
           because a zone WITH storage on and no answer is not a quiet zone.
       notFound is the fourth: a zone gone from the zones file (a lever kept
       its row). Nothing to read, and not a fault.
       absent is the fifth, on /edge/events only: a kapkan older than the
       endpoint itself. Also not a fault — see getEdgeEvents. */
    getEdgeHistory: function (zone, fromISO, toISO, step) {
      var qs = "zone=" + encodeURIComponent(zone) +
        "&from=" + encodeURIComponent(fromISO) + "&to=" + encodeURIComponent(toISO) + "&step=" + step;
      return request("/api/v1/edge/history?" + qs).then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, available: false, points: [] };
        if (res.status === 404) return { ok: false, notFound: true, available: false, points: [] };
        if (!res.ok) throw new Error("edge history -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, available: !!r.available, zone: r.zone || zone,
            /* the brain may raise or cap the step it was asked for — the
               response's own value is the one the buckets were built with */
            stepSeconds: r.step_seconds || step, points: r.points || [] };
        });
      }).catch(function () { return { ok: false, available: false, points: [] }; });
    },
    getEdgeHistorySources: function (zone, fromISO, toISO, state) {
      var qs = "zone=" + encodeURIComponent(zone) +
        "&from=" + encodeURIComponent(fromISO) + "&to=" + encodeURIComponent(toISO);
      if (state) qs += "&state=" + encodeURIComponent(state);
      return request("/api/v1/edge/history/sources?" + qs).then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, available: false, sources: [] };
        if (res.status === 404) return { ok: false, notFound: true, available: false, sources: [] };
        if (!res.ok) throw new Error("edge history sources -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, available: !!r.available, sources: r.sources || [] };
        });
      }).catch(function () { return { ok: false, available: false, sources: [] }; });
    },
    getEdgeEvents: function (fromISO, toISO) {
      var qs = "from=" + encodeURIComponent(fromISO) + "&to=" + encodeURIComponent(toISO);
      return request("/api/v1/edge/events?" + qs).then(function (res) {
        if (res.status === 403) return { ok: false, forbidden: true, available: false, events: [] };
        /* absent is the fifth answer, and only /events has it: a kapkan older
           than the endpoint has no route to refuse or to serve, so its 404 is
           "this kapkan has no fleet events", not a fault. The card is dropped
           the way a 403 drops it — a loud banner re-read every ten seconds
           would be the console shouting at a brain that is merely older. The
           zone reads cannot use the same rule: there a 404 is an answer about
           the ZONE (gone from the zones file), which the card does say. */
        if (res.status === 404) return { ok: false, absent: true, available: false, events: [] };
        if (!res.ok) throw new Error("edge events -> " + res.status);
        return res.json().then(function (r) {
          return { ok: true, available: !!r.available, events: r.events || [] };
        });
      }).catch(function () { return { ok: false, available: false, events: [] }; });
    },
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
