// YAML emitter. Builds a commented Kapkan config from the wizard state, by hand
// (no YAML dependency) so we control formatting, comments and — crucially — the
// footgun-safe rules: dry_run is always written explicitly (and turning it off
// is a loud, opt-in choice), secrets are emitted as environment-variable NAMES
// never values, and empty optional fields/blocks are omitted so the engine
// applies its own defaults. Section order mirrors engine/deploy/config.example.yaml
// so generated files diff cleanly against the canonical example.

// Shared threshold matrix: the same key set backs `thresholds`,
// `thresholds_outgoing`, `carpet.thresholds` and per-hostgroup thresholds.
export const THRESHOLD_KEYS = [
  "pps",
  "mbps",
  "flows_per_sec",
  "tcp_pps",
  "tcp_mbps",
  "tcp_syn_pps",
  "tcp_syn_mbps",
  "udp_pps",
  "udp_mbps",
  "icmp_pps",
  "icmp_mbps",
  "frag_pps",
  "frag_mbps",
] as const;
export type ThresholdKey = (typeof THRESHOLD_KEYS)[number];
export type ThresholdSet = Record<ThresholdKey, string>; // "" = unset

export function emptyThresholds(): ThresholdSet {
  return Object.fromEntries(THRESHOLD_KEYS.map((k) => [k, ""])) as ThresholdSet;
}

export type Neighbor = { address: string; remote_asn: string; port: string };
export type BoundaryRow = { exporter: string; external_ifindexes: string; egress_sampling: boolean };
export type EscalationRow = { after_seconds: string; action: string };
export type ScrubNode = {
  name: string;
  next_hop: string;
  next_hop6: string;
  capacity_mbps: string;
  hostgroups: string; // comma-separated group names
};
export type RatelimitProfile = { name: string; pps: string; mbps: string };
export type StaticRule = {
  name: string;
  src: string;
  proto: string;
  src_port: string;
  dst_port: string;
  payload: string;
  action: string;
  profile: string;
};
export type ApiToken = { name: string; token_env: string; role: string; tenant: string; node: string };
export type Hostgroup = {
  name: string;
  networks: string; // comma-separated CIDRs
  calculation: string; // "" = per_host (default)
  ban: boolean;
  tenant: string;
  mitigation: string; // "" = inherit global
  thr: ThresholdSet; // all empty = inherit global thresholds
};

export type WizardState = {
  dry_run: boolean;
  // telemetry
  sflow: string;
  netflow: string;
  default_rate: string;
  boundary_debug: boolean;
  boundary: BoundaryRow[];
  flow_sources: string[];
  // networks & groups
  networks: string[];
  whitelist: string[];
  hostgroups: Hostgroup[];
  tenant: string;
  // detection
  thr: ThresholdSet;
  thrOut: ThresholdSet;
  baseline_on: boolean;
  baseline_factor: string;
  baseline_half_life: string;
  baseline_warmup: string;
  baseline_floor_pps: string;
  baseline_floor_mbps: string;
  baseline_floor_fps: string;
  carpet_on: boolean;
  carpet_v4: string;
  carpet_v6: string;
  carpet_min_hosts: string;
  carpet_mitigation: string; // "" = alert-only
  carpet_max_bans: string;
  carpetThr: ThresholdSet;
  samples_on: boolean;
  samples_buffer: string;
  samples_per_attack: string;
  // mitigation
  mitigation: string;
  flowspec_action: string; // "" = default (discard)
  flowspec_rate: string;
  flowspec_anchored: boolean;
  flowspec_minconc: string;
  escalation: EscalationRow[];
  scrub_next_hop: string;
  scrub_next_hop6: string;
  scrub_community: string;
  scrub_local_pref: string;
  scrub_nodes: ScrubNode[];
  scrub_selection: string; // "" = default (affinity)
  scrub_on_lost: string; // "" = default (withdraw)
  scrub_stale: string;
  dp_enabled: boolean;
  dp_interfaces: string; // comma-separated NIC names
  dp_xdp_mode: string; // "" = default (auto)
  dp_pin_path: string;
  dp_on_exit: string; // "" = default (keep)
  dp_drop_malformed: boolean;
  dp_allowlist: string[];
  dp_profiles: RatelimitProfile[];
  dp_rules: StaticRule[];
  dp_max_dynamic: string;
  dp_max_static: string;
  dp_max_sources: string;
  // bans
  ttl_seconds: string;
  unban_hysteresis_seconds: string;
  max_active_bans: string;
  ban_fallback: string; // "" = default (blackhole)
  ban_max_fraction: string;
  ban_max_per_window: string;
  ban_window_seconds: string;
  state_file: string;
  // bgp
  local_asn: string;
  router_id: string;
  next_hop: string;
  next_hop6: string;
  community: string;
  bgp_communities: string; // comma-separated, overrides `community`
  bgp_listen_port: string;
  bgp_local_pref: string;
  neighbors: Neighbor[];
  gr_enabled: boolean;
  gr_restart_seconds: string;
  gr_long_lived: boolean;
  gr_long_lived_stale: string;
  // notify
  tg_token_env: string;
  tg_chat_id: string;
  wh_url: string;
  slack_url: string;
  email_smtp: string;
  email_from: string;
  email_to: string; // comma-separated
  email_user_env: string;
  email_pass_env: string;
  email_tls: boolean;
  exec_command: string;
  exec_format: string; // "" = default (kapkan)
  exec_timeout: string;
  // storage / geoip
  ch_url: string;
  ch_database: string;
  ch_user_env: string;
  ch_pass_env: string;
  ch_ttl_days: string;
  ch_flush: string;
  ch_batch: string;
  ch_queue: string;
  ch_traffic: string;
  geo_enabled: boolean;
  geo_asn_db: string;
  geo_country_db: string;
  // api
  api_listen: string;
  api_dashboard: boolean;
  api_token_env: string;
  api_tokens: ApiToken[];
  // updates
  uc_enabled: boolean;
  uc_interval: string;
  uc_channel: string;
  uc_url: string;
  uc_notify: boolean;
};

export const initialState: WizardState = {
  dry_run: true,
  sflow: ":6343",
  netflow: ":2055",
  default_rate: "1000",
  boundary_debug: false,
  boundary: [],
  flow_sources: [],
  networks: ["203.0.113.0/24"],
  whitelist: [],
  hostgroups: [],
  tenant: "",
  thr: { ...emptyThresholds(), pps: "80000", mbps: "1000", flows_per_sec: "35000" },
  thrOut: emptyThresholds(),
  baseline_on: false,
  baseline_factor: "",
  baseline_half_life: "",
  baseline_warmup: "",
  baseline_floor_pps: "",
  baseline_floor_mbps: "",
  baseline_floor_fps: "",
  carpet_on: false,
  carpet_v4: "",
  carpet_v6: "",
  carpet_min_hosts: "",
  carpet_mitigation: "",
  carpet_max_bans: "",
  carpetThr: emptyThresholds(),
  samples_on: false,
  samples_buffer: "",
  samples_per_attack: "",
  mitigation: "blackhole",
  flowspec_action: "",
  flowspec_rate: "",
  flowspec_anchored: false,
  flowspec_minconc: "",
  escalation: [],
  scrub_next_hop: "",
  scrub_next_hop6: "",
  scrub_community: "",
  scrub_local_pref: "",
  scrub_nodes: [],
  scrub_selection: "",
  scrub_on_lost: "",
  scrub_stale: "",
  dp_enabled: false,
  dp_interfaces: "",
  dp_xdp_mode: "",
  dp_pin_path: "",
  dp_on_exit: "",
  dp_drop_malformed: false,
  dp_allowlist: [],
  dp_profiles: [],
  dp_rules: [],
  dp_max_dynamic: "",
  dp_max_static: "",
  dp_max_sources: "",
  ttl_seconds: "600",
  unban_hysteresis_seconds: "120",
  max_active_bans: "50",
  ban_fallback: "",
  ban_max_fraction: "",
  ban_max_per_window: "",
  ban_window_seconds: "",
  state_file: "",
  local_asn: "65001",
  router_id: "10.0.0.1",
  next_hop: "192.0.2.1",
  next_hop6: "",
  community: "65000:666",
  bgp_communities: "",
  bgp_listen_port: "",
  bgp_local_pref: "",
  neighbors: [{ address: "10.0.0.254", remote_asn: "65000", port: "" }],
  gr_enabled: true,
  gr_restart_seconds: "",
  gr_long_lived: false,
  gr_long_lived_stale: "",
  tg_token_env: "",
  tg_chat_id: "",
  wh_url: "",
  slack_url: "",
  email_smtp: "",
  email_from: "",
  email_to: "",
  email_user_env: "",
  email_pass_env: "",
  email_tls: false,
  exec_command: "",
  exec_format: "",
  exec_timeout: "",
  ch_url: "",
  ch_database: "",
  ch_user_env: "",
  ch_pass_env: "",
  ch_ttl_days: "",
  ch_flush: "",
  ch_batch: "",
  ch_queue: "",
  ch_traffic: "",
  geo_enabled: false,
  geo_asn_db: "",
  geo_country_db: "",
  api_listen: "127.0.0.1:8080",
  api_dashboard: true,
  api_token_env: "",
  api_tokens: [],
  uc_enabled: false,
  uc_interval: "",
  uc_channel: "stable",
  uc_url: "",
  uc_notify: false,
};

const q = (v: string) => `"${v.replace(/"/g, '\\"')}"`;
const num = (v: string) => v.trim();

// Inline comment helper: pads the code to a fixed column so comments line up, and keeps
// every generated line short enough to read in the builder's side pane (and in a diff).
const COMMENT_COL = 30;
const c = (code: string, comment: string) =>
  code.length >= COMMENT_COL ? `${code}  # ${comment}` : `${code.padEnd(COMMENT_COL)}# ${comment}`;
const csv = (v: string) => v.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

// Threshold sub-block at `indent`; returns [] when every key is empty.
function thresholdLines(t: ThresholdSet, indent: string): string[] {
  const out: string[] = [];
  for (const k of THRESHOLD_KEYS) {
    const v = t[k].trim();
    if (v !== "" && v !== "0") out.push(`${indent}${k}: ${v}`);
  }
  return out;
}

function anySet(t: ThresholdSet): boolean {
  return THRESHOLD_KEYS.some((k) => t[k].trim() !== "" && t[k].trim() !== "0");
}

export function emitConfig(s: WizardState): string {
  const L: string[] = [];
  L.push("# Kapkan config — generated by the kapkan.io builder.");
  L.push("# Check first:  kapkan -check-config config.yaml");
  L.push("");

  if (s.dry_run) {
    L.push(c(`dry_run: true`, "simulated, never announced"));
  } else {
    L.push(c(`dry_run: false`, "LIVE: announcements go out"));
  }
  L.push("");

  L.push("listen:");
  if (s.sflow.trim()) L.push(`  sflow: ${q(s.sflow)}`);
  if (s.netflow.trim()) L.push(c(`  netflow: ${q(s.netflow)}`, "NetFlow v5/v9 + IPFIX"));
  L.push("");

  L.push("sampling:");
  L.push(c(`  default_rate: ${num(s.default_rate)}`, "when the exporter omits it"));
  if (s.boundary_debug) L.push(c(`  boundary_debug: true`, "calibration only"));
  if (s.boundary.some((b) => b.exporter.trim())) {
    L.push(c(`  boundary:`, "boundary counting"));
    for (const b of s.boundary) {
      if (!b.exporter.trim()) continue;
      L.push(`    - exporter: ${q(b.exporter.trim())}`);
      const idx = csv(b.external_ifindexes);
      if (idx.length) L.push(`      external_ifindexes: [${idx.join(", ")}]`);
      if (b.egress_sampling) L.push(c(`      egress_sampling: true`, "calibrate before setting"));
    }
  }
  L.push("");

  if (s.flow_sources.some((f) => f.trim())) {
    L.push(c(`flow_sources:`, "trusted exporters"));
    for (const f of s.flow_sources) if (f.trim()) L.push(`  - ${q(f.trim())}`);
    L.push("");
  }

  L.push(c(`networks:`, "detection scope"));
  for (const n of s.networks) if (n.trim()) L.push(`  - ${q(n.trim())}`);
  L.push("");

  if (s.whitelist.some((w) => w.trim())) {
    L.push(c(`protected_whitelist:`, "never banned"));
    for (const w of s.whitelist) if (w.trim()) L.push(`  - ${q(w.trim())}`);
    L.push("");
  }

  L.push(c(`thresholds:`, "per host, unsampled units"));
  L.push(...thresholdLines(s.thr, "  "));
  L.push("");

  if (anySet(s.thrOut)) {
    L.push(c(`thresholds_outgoing:`, "traffic leaving your hosts"));
    L.push(...thresholdLines(s.thrOut, "  "));
    L.push("");
  }

  if (s.baseline_on) {
    L.push(c(`baseline:`, "learned thresholds"));
    L.push("  enabled: true");
    if (num(s.baseline_factor)) L.push(`  factor: ${num(s.baseline_factor)}`);
    if (num(s.baseline_half_life)) L.push(`  half_life_seconds: ${num(s.baseline_half_life)}`);
    if (num(s.baseline_warmup)) L.push(`  warmup_seconds: ${num(s.baseline_warmup)}`);
    if (num(s.baseline_floor_pps) || num(s.baseline_floor_mbps) || num(s.baseline_floor_fps)) {
      L.push("  floor:");
      if (num(s.baseline_floor_pps)) L.push(`    pps: ${num(s.baseline_floor_pps)}`);
      if (num(s.baseline_floor_mbps)) L.push(`    mbps: ${num(s.baseline_floor_mbps)}`);
      if (num(s.baseline_floor_fps)) L.push(`    flows_per_sec: ${num(s.baseline_floor_fps)}`);
    }
    L.push("");
  }

  if (s.carpet_on) {
    L.push(c(`carpet:`, "subnet-spread attacks"));
    if (num(s.carpet_v4)) L.push(`  aggregation_prefix_v4: ${num(s.carpet_v4)}`);
    if (num(s.carpet_v6)) L.push(`  aggregation_prefix_v6: ${num(s.carpet_v6)}`);
    if (num(s.carpet_min_hosts)) L.push(`  min_hosts: ${num(s.carpet_min_hosts)}`);
    if (anySet(s.carpetThr)) {
      L.push(c(`  thresholds:`, "aggregate over the prefix"));
      L.push(...thresholdLines(s.carpetThr, "    "));
    }
    if (s.carpet_mitigation) L.push(`  mitigation: ${s.carpet_mitigation}`);
    else L.push("  # mitigation:                    # empty = alert-only");
    if (num(s.carpet_max_bans)) L.push(`  max_active_prefix_bans: ${num(s.carpet_max_bans)}`);
    L.push("");
  }

  if (s.samples_on) {
    L.push(c(`samples:`, "buffered attack samples"));
    L.push("  enabled: true");
    if (num(s.samples_buffer)) L.push(`  buffer_flows: ${num(s.samples_buffer)}`);
    if (num(s.samples_per_attack)) L.push(`  flows_per_attack: ${num(s.samples_per_attack)}`);
    L.push("");
  }

  const groups = s.hostgroups.filter((g) => g.name.trim());
  if (groups.length) {
    L.push(c(`hostgroups:`, "per-group policy"));
    for (const g of groups) {
      L.push(`  - name: ${g.name.trim()}`);
      const nets = csv(g.networks);
      if (nets.length) {
        L.push("    networks:");
        for (const n of nets) L.push(`      - ${q(n)}`);
      }
      if (g.calculation && g.calculation !== "per_host") L.push(`    calculation: ${g.calculation}`);
      if (!g.ban) L.push(c(`    ban: false`, "detect, never mitigate"));
      if (g.mitigation) L.push(`    mitigation: ${g.mitigation}`);
      if (anySet(g.thr)) {
        L.push(c(`    thresholds:`, "omit to inherit global"));
        L.push(...thresholdLines(g.thr, "      "));
      }
      if (g.tenant.trim()) L.push(`    tenant: ${q(g.tenant.trim())}`);
    }
    L.push("");
  }

  if (s.tenant.trim()) {
    L.push(c(`tenant: ${q(s.tenant.trim())}`, "global fallback group"));
    L.push("");
  }

  if (s.mitigation && s.mitigation !== "blackhole") {
    L.push(`mitigation: ${s.mitigation}`);
    L.push("");
  }

  const flowspecSet =
    s.flowspec_action || num(s.flowspec_rate) || s.flowspec_anchored || num(s.flowspec_minconc);
  if (flowspecSet) {
    L.push("flowspec:");
    if (s.flowspec_action) L.push(`  action: ${s.flowspec_action}`);
    if (num(s.flowspec_rate)) L.push(c(`  rate_mbps: ${num(s.flowspec_rate)}`, "required for rate_limit"));
    if (s.flowspec_anchored) L.push(c(`  source_anchored: true`, "drop dominant sources"));
    if (num(s.flowspec_minconc)) L.push(`  min_source_concentration: ${num(s.flowspec_minconc)}`);
    L.push("");
  }

  const rungs = s.escalation.filter((e) => e.action);
  if (rungs.length) {
    L.push(c(`escalation:`, "supersedes mitigation"));
    for (const e of rungs) {
      L.push(`  - {after_seconds: ${num(e.after_seconds) || "0"}, action: ${e.action}}`);
    }
    L.push("");
  }

  const scrubSet =
    s.scrub_next_hop.trim() || s.scrub_next_hop6.trim() || s.scrub_community.trim() ||
    num(s.scrub_local_pref) || s.scrub_nodes.some((n) => n.name.trim()) ||
    s.scrub_selection || s.scrub_on_lost || num(s.scrub_stale);
  if (scrubSet) {
    L.push(c(`scrubbing:`, "required for divert"));
    if (s.scrub_next_hop.trim()) L.push(c(`  next_hop: ${q(s.scrub_next_hop.trim())}`, "scrubbing center (v4)"));
    if (s.scrub_next_hop6.trim()) L.push(`  next_hop6: ${q(s.scrub_next_hop6.trim())}`);
    if (s.scrub_community.trim()) L.push(`  community: ${q(s.scrub_community.trim())}`);
    if (num(s.scrub_local_pref)) L.push(c(`  local_pref: ${num(s.scrub_local_pref)}`, "divert route wins"));
    const nodes = s.scrub_nodes.filter((n) => n.name.trim());
    if (nodes.length) {
      L.push(c(`  nodes:`, "managed scrub nodes"));
      for (const n of nodes) {
        L.push(`    - name: ${n.name.trim()}`);
        if (n.next_hop.trim()) L.push(`      next_hop: ${q(n.next_hop.trim())}`);
        if (n.next_hop6.trim()) L.push(`      next_hop6: ${q(n.next_hop6.trim())}`);
        if (num(n.capacity_mbps)) L.push(`      capacity_mbps: ${num(n.capacity_mbps)}`);
        const hgs = csv(n.hostgroups);
        if (hgs.length) L.push(`      hostgroups: [${hgs.join(", ")}]`);
      }
    }
    if (s.scrub_selection) L.push(`  node_selection: ${s.scrub_selection}`);
    if (s.scrub_on_lost) L.push(`  on_all_nodes_lost: ${s.scrub_on_lost}`);
    if (num(s.scrub_stale)) L.push(`  stale_after_seconds: ${num(s.scrub_stale)}`);
    L.push("");
  }

  const dpSet =
    s.dp_enabled || csv(s.dp_interfaces).length || s.dp_xdp_mode || s.dp_pin_path.trim() ||
    s.dp_on_exit || s.dp_drop_malformed || s.dp_allowlist.some((a) => a.trim()) ||
    s.dp_profiles.some((p) => p.name.trim()) || s.dp_rules.some((r) => r.name.trim()) ||
    num(s.dp_max_dynamic) || num(s.dp_max_static) || num(s.dp_max_sources);
  if (dpSet) {
    L.push(c(`dataplane:`, "in-kernel XDP drops"));
    if (s.dp_enabled) L.push("  enabled: true");
    const ifs = csv(s.dp_interfaces);
    if (ifs.length) L.push(c(`  interfaces: [${ifs.join(", ")}]`, "restart required"));
    if (s.dp_xdp_mode) L.push(`  xdp_mode: ${s.dp_xdp_mode}`);
    if (s.dp_pin_path.trim()) L.push(`  pin_path: ${s.dp_pin_path.trim()}`);
    if (s.dp_on_exit) L.push(`  on_exit: ${s.dp_on_exit}`);
    if (s.dp_drop_malformed) L.push(c(`  drop_malformed: true`, "drop unparseable frames"));
    if (s.dp_allowlist.some((a) => a.trim())) {
      L.push(c(`  allowlist:`, "sources that always pass"));
      for (const a of s.dp_allowlist) if (a.trim()) L.push(`    - ${q(a.trim())}`);
    }
    const profiles = s.dp_profiles.filter((p) => p.name.trim());
    if (profiles.length) {
      L.push(c(`  ratelimit_profiles:`, "named ceilings"));
      for (const p of profiles) {
        const parts = [`name: ${p.name.trim()}`];
        if (num(p.pps)) parts.push(`pps: ${num(p.pps)}`);
        if (num(p.mbps)) parts.push(`mbps: ${num(p.mbps)}`);
        L.push(`    - {${parts.join(", ")}}`);
      }
    }
    const rules = s.dp_rules.filter((r) => r.name.trim());
    if (rules.length) {
      L.push(c(`  static_rules:`, "always-on rules"));
      for (const r of rules) {
        L.push(`    - name: ${r.name.trim()}`);
        const m: string[] = [];
        if (r.src.trim()) m.push(`src: ${q(r.src.trim())}`);
        if (r.proto) m.push(`proto: ${r.proto}`);
        if (num(r.src_port)) m.push(`src_port: ${num(r.src_port)}`);
        if (num(r.dst_port)) m.push(`dst_port: ${num(r.dst_port)}`);
        if (r.payload) m.push(`payload: ${r.payload}`);
        if (m.length) L.push(`      match: {${m.join(", ")}}`);
        if (r.action) L.push(`      action: ${r.action}`);
        if (r.profile.trim()) L.push(`      profile: ${r.profile.trim()}`);
      }
    }
    if (num(s.dp_max_dynamic) || num(s.dp_max_static) || num(s.dp_max_sources)) {
      L.push("  limits:");
      if (num(s.dp_max_dynamic)) L.push(c(`    max_dynamic_rules: ${num(s.dp_max_dynamic)}`, ">= max_active_bans * 8"));
      if (num(s.dp_max_static)) L.push(`    max_static_rules: ${num(s.dp_max_static)}`);
      if (num(s.dp_max_sources)) L.push(`    max_ratelimit_sources: ${num(s.dp_max_sources)}`);
    }
    L.push("");
  }

  L.push("ban:");
  L.push(c(`  ttl_seconds: ${num(s.ttl_seconds)}`, "auto-withdraw after this"));
  L.push(c(`  unban_hysteresis_seconds: ${num(s.unban_hysteresis_seconds)}`, "anti-flap before unban"));
  L.push(`  max_active_bans: ${num(s.max_active_bans)}`);
  if (s.ban_fallback) L.push(c(`  fallback: ${s.ban_fallback}`, "when the peer rejects"));
  if (num(s.ban_max_fraction)) L.push(c(`  max_banned_fraction: ${num(s.ban_max_fraction)}`, "blast-radius guard"));
  if (num(s.ban_max_per_window)) L.push(c(`  max_bans_per_window: ${num(s.ban_max_per_window)}`, "storm guard"));
  if (num(s.ban_window_seconds)) L.push(`  ban_window_seconds: ${num(s.ban_window_seconds)}`);
  if (s.state_file.trim()) {
    L.push(c(`  state_file: ${q(s.state_file.trim())}`, "survives a restart"));
  }
  L.push("");

  L.push("bgp:");
  L.push(`  local_asn: ${num(s.local_asn)}`);
  L.push(c(`  router_id: ${q(s.router_id)}`, "IPv4 dotted-quad"));
  L.push(c(`  next_hop: ${q(s.next_hop)}`, "blackhole next-hop"));
  if (s.next_hop6.trim()) L.push(`  next_hop6: ${q(s.next_hop6.trim())}`);
  const comms = csv(s.bgp_communities);
  if (comms.length) {
    L.push(c(`  communities: [${comms.map(q).join(", ")}]`, "overrides community"));
  } else {
    L.push(c(`  community: ${q(s.community)}`, "RTBH community"));
  }
  if (num(s.bgp_listen_port)) L.push(`  listen_port: ${num(s.bgp_listen_port)}`);
  if (num(s.bgp_local_pref)) L.push(c(`  local_pref: ${num(s.bgp_local_pref)}`, "on blackholes (iBGP)"));
  L.push("  neighbors:");
  for (const n of s.neighbors) {
    if (!n.address.trim()) continue;
    L.push(`    - address: ${q(n.address.trim())}`);
    L.push(`      remote_asn: ${num(n.remote_asn)}`);
    if (num(n.port)) L.push(`      port: ${num(n.port)}`);
  }
  // graceful_restart: on by default — emit only the knobs the operator changed.
  const gr: string[] = [];
  if (!s.gr_enabled) gr.push(c(`    enabled: false`, "opt out of Graceful Restart"));
  if (s.gr_restart_seconds.trim() && num(s.gr_restart_seconds) !== "0") gr.push(`    restart_seconds: ${num(s.gr_restart_seconds)}`);
  if (s.gr_long_lived) gr.push("    long_lived: true");
  if (s.gr_long_lived_stale.trim() && num(s.gr_long_lived_stale) !== "0") gr.push(`    long_lived_stale_seconds: ${num(s.gr_long_lived_stale)}`);
  if (gr.length) {
    L.push("  graceful_restart:");
    for (const g of gr) L.push(g);
  }
  L.push("");

  const notifyLines: string[] = [];
  if (s.tg_token_env.trim()) {
    notifyLines.push("  telegram:");
    notifyLines.push(c(`    token_env: ${q(s.tg_token_env.trim())}`, "env var name, not token"));
    if (s.tg_chat_id.trim()) notifyLines.push(`    chat_id: ${q(s.tg_chat_id.trim())}`);
  }
  if (s.wh_url.trim()) {
    notifyLines.push("  webhook:");
    notifyLines.push(c(`    url: ${q(s.wh_url.trim())}`, "JSON POST per attack"));
  }
  if (s.slack_url.trim()) {
    notifyLines.push("  slack:");
    notifyLines.push(`    webhook_url: ${q(s.slack_url.trim())}`);
  }
  if (s.email_smtp.trim()) {
    notifyLines.push(c(`  email:`, "credentials from env vars"));
    notifyLines.push(`    smtp_host: ${q(s.email_smtp.trim())}`);
    if (s.email_from.trim()) notifyLines.push(`    from: ${q(s.email_from.trim())}`);
    const to = csv(s.email_to);
    if (to.length) notifyLines.push(`    to: [${to.map(q).join(", ")}]`);
    if (s.email_user_env.trim()) notifyLines.push(`    username_env: ${q(s.email_user_env.trim())}`);
    if (s.email_pass_env.trim()) notifyLines.push(`    password_env: ${q(s.email_pass_env.trim())}`);
    if (s.email_tls) notifyLines.push("    require_tls: true");
  }
  if (s.exec_command.trim()) {
    notifyLines.push(c(`  exec:`, "hook per attack event"));
    notifyLines.push(`    command: ${q(s.exec_command.trim())}`);
    if (s.exec_format) notifyLines.push(c(`    format: ${s.exec_format}`, "FastNetMon-compatible"));
    if (num(s.exec_timeout)) notifyLines.push(`    timeout_seconds: ${num(s.exec_timeout)}`);
  }
  if (notifyLines.length) {
    L.push("notify:");
    L.push(...notifyLines);
    L.push("");
  }

  if (s.ch_url.trim()) {
    L.push(c(`storage:`, "ClickHouse history"));
    L.push("  clickhouse:");
    L.push(`    url: ${q(s.ch_url.trim())}`);
    if (s.ch_database.trim()) L.push(`    database: ${q(s.ch_database.trim())}`);
    if (s.ch_user_env.trim()) L.push(`    username_env: ${q(s.ch_user_env.trim())}`);
    if (s.ch_pass_env.trim()) L.push(`    password_env: ${q(s.ch_pass_env.trim())}`);
    if (num(s.ch_ttl_days)) L.push(`    ttl_days: ${num(s.ch_ttl_days)}`);
    if (num(s.ch_flush)) L.push(`    flush_interval_seconds: ${num(s.ch_flush)}`);
    if (num(s.ch_batch)) L.push(`    batch_size: ${num(s.ch_batch)}`);
    if (num(s.ch_queue)) L.push(`    queue_size: ${num(s.ch_queue)}`);
    if (num(s.ch_traffic)) L.push(`    traffic_interval_seconds: ${num(s.ch_traffic)}`);
    L.push("");
  }

  if (s.geo_enabled) {
    L.push(c(`geoip:`, "MaxMind attribution"));
    L.push("  enabled: true");
    if (s.geo_asn_db.trim()) L.push(`  asn_database: ${q(s.geo_asn_db.trim())}`);
    if (s.geo_country_db.trim()) L.push(`  country_database: ${q(s.geo_country_db.trim())}`);
    L.push("");
  }

  L.push("api:");
  L.push(c(`  listen: ${q(s.api_listen)}`, "localhost needs no auth"));
  if (!s.api_dashboard) L.push(c(`  dashboard: false`, "JSON API only"));
  const tokens = s.api_tokens.filter((tk) => tk.name.trim() && tk.token_env.trim());
  if (tokens.length) {
    L.push(c(`  tokens:`, "viewer / operator / agent"));
    for (const tk of tokens) {
      const parts = [`name: ${tk.name.trim()}`, `token_env: ${q(tk.token_env.trim())}`];
      if (tk.role) parts.push(`role: ${tk.role}`);
      if (tk.tenant.trim()) parts.push(`tenant: ${q(tk.tenant.trim())}`);
      if (tk.node.trim()) parts.push(`node: ${q(tk.node.trim())}`);
      L.push(`    - {${parts.join(", ")}}`);
    }
  } else if (s.api_token_env.trim()) {
    L.push(c(`  token_env: ${q(s.api_token_env.trim())}`, "required off localhost"));
  } else {
    L.push("  # token_env: \"KAPKAN_API_TOKEN\"  # required off localhost");
  }

  if (s.uc_enabled) {
    L.push("");
    L.push(c(`update_check:`, "opt-in version check"));
    L.push("  enabled: true");
    if (s.uc_interval.trim() && num(s.uc_interval) !== "0") L.push(`  interval_seconds: ${num(s.uc_interval)}`);
    if (s.uc_channel && s.uc_channel !== "stable") L.push(`  channel: ${s.uc_channel}`);
    if (s.uc_url.trim()) L.push(`  url: ${q(s.uc_url.trim())}`);
    if (s.uc_notify) L.push(c(`  notify: true`, "via notify channels"));
  }

  return L.join("\n") + "\n";
}
