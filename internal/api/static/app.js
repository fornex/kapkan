"use strict";

// Kapkan dashboard. Plain JS, no framework. Every value that originates from
// observed traffic (addresses, ports, routes, group names) is rendered with
// textContent — never innerHTML — so attack-controlled data can never inject
// markup. The page CSP additionally blocks inline/foreign scripts.

const TOKEN_KEY = "kapkan_token";
let token = sessionStorage.getItem(TOKEN_KEY) || "";

// api fetches a JSON endpoint, attaching the bearer token when we have one.
// On 401 it prompts once for a token and retries.
async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  if (token) headers["Authorization"] = "Bearer " + token;
  const resp = await fetch(path, Object.assign({}, opts, { headers }));
  if (resp.status === 401) {
    const entered = window.prompt("API token required:");
    if (entered) {
      token = entered;
      sessionStorage.setItem(TOKEN_KEY, token);
      return api(path, opts); // retry once with the new token
    }
    throw new Error("unauthorized");
  }
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  return resp.json();
}

// el builds an element with text children and optional class — the single
// safe DOM constructor used everywhere below.
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined && text !== null) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
}

function fmt(n) {
  if (n === undefined || n === null) return "-";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return Math.round(n).toString();
}

function setRows(tableId, emptyId, rows) {
  const tbody = document.querySelector("#" + tableId + " tbody");
  tbody.replaceChildren(...rows);
  const empty = document.getElementById(emptyId);
  if (empty) empty.style.display = rows.length ? "none" : "";
}

function row(cells) {
  const tr = document.createElement("tr");
  for (const c of cells) {
    if (c instanceof HTMLElement && c.tagName === "TD") tr.appendChild(c);
    else { const td = el("td"); if (c instanceof HTMLElement) td.appendChild(c); else td.textContent = c == null ? "-" : String(c); tr.appendChild(td); }
  }
  return tr;
}

function topSources(sample) {
  if (!sample || !sample.top_sources || !sample.top_sources.length) return "-";
  return sample.top_sources.slice(0, 3).map((c) => c.key).join(", ");
}

function dirCell(direction) {
  const td = el("td", direction || "in");
  if (direction === "outgoing") td.className = "dir-out";
  return td;
}

function clsText(c) {
  if (!c) return "-";
  let s = c.type;
  if (c.src_port) s += " :" + c.src_port;
  return s;
}

function renderStatus(s) {
  const bar = document.getElementById("status-bar");
  const mode = el("span", s.dry_run ? "DRY-RUN" : "LIVE", "badge " + (s.dry_run ? "dry" : "live"));
  const wrap = (label, val) => { const c = el("span", null, "chip"); c.append(document.createTextNode(label + " "), el("b", val)); return c; };
  bar.replaceChildren(
    mode,
    wrap("attacks", s.active_attacks),
    wrap("bans", s.active_bans),
    wrap("uptime", Math.round(s.uptime_seconds) + "s"),
    wrap("networks", (s.networks || []).length)
  );
}

function renderActive(attacks) {
  const rows = (attacks || []).map((a) =>
    row([
      a.scope === "group" ? "group:" + a.group : a.target,
      a.scope,
      dirCell(a.direction),
      clsText(a.classification),
      a.metric,
      fmt(a.rate),
      fmt(a.threshold),
      topSources(a.sample),
      a.ban_state || "-",
    ])
  );
  setRows("active-attacks", "active-empty", rows);
  document.getElementById("active-count").textContent = rows.length ? "(" + rows.length + ")" : "";
}

function renderRecent(attacks) {
  const rows = (attacks || []).map((a) =>
    row([
      a.scope === "group" ? "group:" + a.group : a.target,
      dirCell(a.direction),
      clsText(a.classification),
      a.metric,
      fmt(a.rate),
      a.started_at ? new Date(a.started_at).toLocaleTimeString() : "-",
      a.ended_at ? new Date(a.ended_at).toLocaleTimeString() : "-",
    ])
  );
  setRows("recent-attacks", "recent-empty", rows);
}

function renderHosts(hosts) {
  const list = (hosts || []).slice().sort((a, b) => (b.rates?.pps || 0) - (a.rates?.pps || 0)).slice(0, 50);
  const rows = list.map((h) => {
    const inAttack = el("td", h.in_attack ? "yes" : "");
    if (h.in_attack) inAttack.className = "attacking";
    return row([
      h.target,
      h.group,
      fmt(h.rates?.pps),
      (h.rates?.mbps || 0).toFixed(1),
      fmt(h.rates?.flows_per_sec),
      h.baseline ? fmt(h.baseline.pps) : "-",
      inAttack,
    ]);
  });
  setRows("hosts", "hosts-empty", rows);
}

function renderBans(bans) {
  const active = (bans || []).filter((b) => b.state === "active");
  const rows = active.map((b) =>
    row([
      b.target,
      b.route,
      b.state,
      b.dry_run ? "dry-run" : "live",
      b.expires_at ? new Date(b.expires_at).toLocaleTimeString() : "-",
    ])
  );
  setRows("bans", "bans-empty", rows);
  document.getElementById("bans-count").textContent = rows.length ? "(" + rows.length + ")" : "";
}

async function refresh() {
  try {
    const [status, attacks, hosts, bans] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/attacks"),
      api("/api/v1/hosts"),
      api("/api/v1/bans"),
    ]);
    renderStatus(status);
    renderActive(attacks.active);
    renderRecent(attacks.recent);
    renderHosts(hosts.hosts);
    renderBans(bans.bans);
    document.getElementById("footer").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById("footer").textContent = "Error: " + e.message;
  }
}

async function post(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function wireForms() {
  document.getElementById("ban-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const action = ev.submitter && ev.submitter.dataset.action === "unban" ? "unban" : "ban";
    const ip = document.getElementById("ban-ip").value.trim();
    const result = document.getElementById("ban-result");
    if (!ip) { result.textContent = "enter an IP"; result.className = "result err"; return; }
    try {
      const b = await post("/api/v1/" + action, { ip });
      result.textContent = action + ": " + (b.state || "ok");
      result.className = "result " + (b.state === "rejected" ? "err" : "ok");
      refresh();
    } catch (e) {
      result.textContent = e.message;
      result.className = "result err";
    }
  });

  document.getElementById("reload-btn").addEventListener("click", async () => {
    try { await post("/api/v1/config/reload", {}); } catch (_) { /* surfaced on next refresh */ }
    refresh();
  });
}

function renderHostgroups(status) {
  const rows = (status.hostgroups || []).map((g) =>
    row([
      g.name,
      g.calculation,
      fmt(g.thresholds?.pps),
      fmt(g.thresholds?.mbps),
      fmt(g.thresholds?.flows_per_sec),
      g.ban ? "yes" : "no",
      g.baseline ? "x" + g.baseline.factor : "-",
    ])
  );
  setRows("hostgroups", null, rows);
}

async function refreshGroups() {
  try { renderHostgroups(await api("/api/v1/status")); } catch (_) { /* ignore */ }
}

wireForms();
refresh();
refreshGroups();
setInterval(refresh, 3000);
