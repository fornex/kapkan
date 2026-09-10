// Import of an existing kapkan config.yaml into the builder. The parsed
// document (js-yaml `load`, done lazily by the caller) is mapped onto a fresh
// WizardState; anything the form cannot represent is reported by the caller
// via a leaf-path diff (imported leaves minus re-emitted leaves), so nothing
// is ever dropped silently.

import {
  emptyThresholds,
  initialState,
  THRESHOLD_KEYS,
  type ThresholdSet,
  type WizardState,
} from "./emit";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);

function get(doc: unknown, path: string): unknown {
  let cur: unknown = doc;
  for (const seg of path.split(".")) {
    if (!isObj(cur)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

const str = (v: unknown): string =>
  v === undefined || v === null ? "" : typeof v === "object" ? "" : String(v);
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(str).filter(Boolean) : [];
const csvOf = (v: unknown): string => strList(v).join(", ");
const boolOr = (v: unknown, dflt: boolean): boolean => (typeof v === "boolean" ? v : dflt);

function readThr(v: unknown): ThresholdSet {
  const out = emptyThresholds();
  if (isObj(v)) {
    for (const k of THRESHOLD_KEYS) {
      const raw = v[k];
      if (raw !== undefined && raw !== null && typeof raw !== "object") out[k] = String(raw);
    }
  }
  return out;
}

// A state where every example/default value is blanked, so the imported file
// alone determines the output. Engine-required fields the file lacks will
// surface through the always-on engine verdict.
function blankState(): WizardState {
  return {
    ...JSON.parse(JSON.stringify(initialState)),
    sflow: "",
    netflow: "",
    default_rate: "",
    networks: [],
    whitelist: [],
    neighbors: [],
    thr: emptyThresholds(),
    ttl_seconds: "",
    unban_hysteresis_seconds: "",
    max_active_bans: "",
    local_asn: "",
    router_id: "",
    next_hop: "",
    community: "",
    api_listen: "",
  };
}

export function docToState(doc: unknown): WizardState {
  const s = blankState();
  if (!isObj(doc)) return s;

  s.dry_run = get(doc, "dry_run") !== false;

  s.sflow = str(get(doc, "listen.sflow"));
  s.netflow = str(get(doc, "listen.netflow"));
  s.default_rate = str(get(doc, "sampling.default_rate"));
  s.boundary_debug = boolOr(get(doc, "sampling.boundary_debug"), false);
  const boundary = get(doc, "sampling.boundary");
  if (Array.isArray(boundary)) {
    s.boundary = boundary.filter(isObj).map((b) => ({
      exporter: str(b.exporter),
      external_ifindexes: csvOf(b.external_ifindexes),
      egress_sampling: boolOr(b.egress_sampling, false),
    }));
  }
  s.flow_sources = strList(get(doc, "flow_sources"));

  s.networks = strList(get(doc, "networks"));
  s.whitelist = strList(get(doc, "protected_whitelist"));
  const groups = get(doc, "hostgroups");
  if (Array.isArray(groups)) {
    s.hostgroups = groups.filter(isObj).map((g) => ({
      name: str(g.name),
      networks: csvOf(g.networks),
      calculation: str(g.calculation),
      ban: boolOr(g.ban, true),
      tenant: str(g.tenant),
      mitigation: str(g.mitigation),
      thr: readThr(g.thresholds),
    }));
  }
  s.tenant = str(get(doc, "tenant"));

  s.thr = readThr(get(doc, "thresholds"));
  s.thrOut = readThr(get(doc, "thresholds_outgoing"));

  const baseline = get(doc, "baseline");
  if (isObj(baseline)) {
    s.baseline_on = boolOr(baseline.enabled, true);
    s.baseline_factor = str(baseline.factor);
    s.baseline_half_life = str(baseline.half_life_seconds);
    s.baseline_warmup = str(baseline.warmup_seconds);
    s.baseline_floor_pps = str(get(baseline, "floor.pps"));
    s.baseline_floor_mbps = str(get(baseline, "floor.mbps"));
    s.baseline_floor_fps = str(get(baseline, "floor.flows_per_sec"));
  }

  const carpet = get(doc, "carpet");
  if (isObj(carpet)) {
    s.carpet_on = true;
    s.carpet_v4 = str(carpet.aggregation_prefix_v4);
    s.carpet_v6 = str(carpet.aggregation_prefix_v6);
    s.carpet_min_hosts = str(carpet.min_hosts);
    s.carpet_mitigation = str(carpet.mitigation);
    s.carpet_max_bans = str(carpet.max_active_prefix_bans);
    s.carpetThr = readThr(carpet.thresholds);
  }

  const samples = get(doc, "samples");
  if (isObj(samples)) {
    s.samples_on = boolOr(samples.enabled, true);
    s.samples_buffer = str(samples.buffer_flows);
    s.samples_per_attack = str(samples.flows_per_attack);
  }

  s.mitigation = str(get(doc, "mitigation")) || "blackhole";
  const flowspec = get(doc, "flowspec");
  if (isObj(flowspec)) {
    s.flowspec_action = str(flowspec.action);
    s.flowspec_rate = str(flowspec.rate_mbps);
    s.flowspec_anchored = boolOr(flowspec.source_anchored, false);
    s.flowspec_minconc = str(flowspec.min_source_concentration);
  }
  const escalation = get(doc, "escalation");
  if (Array.isArray(escalation)) {
    s.escalation = escalation.filter(isObj).map((e) => ({
      after_seconds: str(e.after_seconds),
      action: str(e.action),
    }));
  }
  const scrubbing = get(doc, "scrubbing");
  if (isObj(scrubbing)) {
    s.scrub_next_hop = str(scrubbing.next_hop);
    s.scrub_next_hop6 = str(scrubbing.next_hop6);
    s.scrub_community = str(scrubbing.community);
    s.scrub_local_pref = str(scrubbing.local_pref);
    s.scrub_selection = str(scrubbing.node_selection);
    s.scrub_on_lost = str(scrubbing.on_all_nodes_lost);
    s.scrub_stale = str(scrubbing.stale_after_seconds);
    if (Array.isArray(scrubbing.nodes)) {
      s.scrub_nodes = scrubbing.nodes.filter(isObj).map((n) => ({
        name: str(n.name),
        next_hop: str(n.next_hop),
        next_hop6: str(n.next_hop6),
        capacity_mbps: str(n.capacity_mbps),
        hostgroups: csvOf(n.hostgroups),
      }));
    }
  }
  const dp = get(doc, "dataplane");
  if (isObj(dp)) {
    s.dp_enabled = boolOr(dp.enabled, false);
    s.dp_interfaces = csvOf(dp.interfaces);
    s.dp_xdp_mode = str(dp.xdp_mode);
    s.dp_pin_path = str(dp.pin_path);
    s.dp_on_exit = str(dp.on_exit);
    s.dp_drop_malformed = boolOr(dp.drop_malformed, false);
    s.dp_allowlist = strList(dp.allowlist);
    if (Array.isArray(dp.ratelimit_profiles)) {
      s.dp_profiles = dp.ratelimit_profiles.filter(isObj).map((p) => ({
        name: str(p.name),
        pps: str(p.pps),
        mbps: str(p.mbps),
      }));
    }
    if (Array.isArray(dp.static_rules)) {
      s.dp_rules = dp.static_rules.filter(isObj).map((r) => ({
        name: str(r.name),
        src: str(get(r, "match.src")),
        proto: str(get(r, "match.proto")),
        src_port: str(get(r, "match.src_port")),
        dst_port: str(get(r, "match.dst_port")),
        payload: str(get(r, "match.payload")),
        action: str(r.action),
        profile: str(r.profile),
      }));
    }
    s.dp_max_dynamic = str(get(dp, "limits.max_dynamic_rules"));
    s.dp_max_static = str(get(dp, "limits.max_static_rules"));
    s.dp_max_sources = str(get(dp, "limits.max_ratelimit_sources"));
  }

  s.ttl_seconds = str(get(doc, "ban.ttl_seconds"));
  s.unban_hysteresis_seconds = str(get(doc, "ban.unban_hysteresis_seconds"));
  s.max_active_bans = str(get(doc, "ban.max_active_bans"));
  s.ban_fallback = str(get(doc, "ban.fallback"));
  s.ban_max_fraction = str(get(doc, "ban.max_banned_fraction"));
  s.ban_max_per_window = str(get(doc, "ban.max_bans_per_window"));
  s.ban_window_seconds = str(get(doc, "ban.ban_window_seconds"));
  s.state_file = str(get(doc, "ban.state_file"));

  s.local_asn = str(get(doc, "bgp.local_asn"));
  s.router_id = str(get(doc, "bgp.router_id"));
  s.next_hop = str(get(doc, "bgp.next_hop"));
  s.next_hop6 = str(get(doc, "bgp.next_hop6"));
  s.community = str(get(doc, "bgp.community"));
  s.bgp_communities = csvOf(get(doc, "bgp.communities"));
  s.bgp_listen_port = str(get(doc, "bgp.listen_port"));
  s.bgp_local_pref = str(get(doc, "bgp.local_pref"));
  const neighbors = get(doc, "bgp.neighbors");
  if (Array.isArray(neighbors)) {
    s.neighbors = neighbors.filter(isObj).map((n) => ({
      address: str(n.address),
      remote_asn: str(n.remote_asn),
      port: str(n.port),
    }));
  }
  const gr = get(doc, "bgp.graceful_restart");
  if (isObj(gr)) {
    s.gr_enabled = boolOr(gr.enabled, true);
    s.gr_restart_seconds = str(gr.restart_seconds);
    s.gr_long_lived = boolOr(gr.long_lived, false);
    s.gr_long_lived_stale = str(gr.long_lived_stale_seconds);
  }

  s.tg_token_env = str(get(doc, "notify.telegram.token_env"));
  s.tg_chat_id = str(get(doc, "notify.telegram.chat_id"));
  s.wh_url = str(get(doc, "notify.webhook.url"));
  s.slack_url = str(get(doc, "notify.slack.webhook_url"));
  s.email_smtp = str(get(doc, "notify.email.smtp_host"));
  s.email_from = str(get(doc, "notify.email.from"));
  s.email_to = csvOf(get(doc, "notify.email.to"));
  s.email_user_env = str(get(doc, "notify.email.username_env"));
  s.email_pass_env = str(get(doc, "notify.email.password_env"));
  s.email_tls = boolOr(get(doc, "notify.email.require_tls"), false);
  s.exec_command = str(get(doc, "notify.exec.command"));
  s.exec_format = str(get(doc, "notify.exec.format"));
  s.exec_timeout = str(get(doc, "notify.exec.timeout_seconds"));

  s.ch_url = str(get(doc, "storage.clickhouse.url"));
  s.ch_database = str(get(doc, "storage.clickhouse.database"));
  s.ch_user_env = str(get(doc, "storage.clickhouse.username_env"));
  s.ch_pass_env = str(get(doc, "storage.clickhouse.password_env"));
  s.ch_ttl_days = str(get(doc, "storage.clickhouse.ttl_days"));
  s.ch_flush = str(get(doc, "storage.clickhouse.flush_interval_seconds"));
  s.ch_batch = str(get(doc, "storage.clickhouse.batch_size"));
  s.ch_queue = str(get(doc, "storage.clickhouse.queue_size"));
  s.ch_traffic = str(get(doc, "storage.clickhouse.traffic_interval_seconds"));

  const geo = get(doc, "geoip");
  if (isObj(geo)) {
    s.geo_enabled = boolOr(geo.enabled, true);
    s.geo_asn_db = str(geo.asn_database);
    s.geo_country_db = str(geo.country_database);
  }

  s.api_listen = str(get(doc, "api.listen"));
  s.api_dashboard = get(doc, "api.dashboard") !== false;
  s.api_token_env = str(get(doc, "api.token_env"));
  const tokens = get(doc, "api.tokens");
  if (Array.isArray(tokens)) {
    s.api_tokens = tokens.filter(isObj).map((tk) => ({
      name: str(tk.name),
      token_env: str(tk.token_env),
      role: str(tk.role),
      tenant: str(tk.tenant),
      node: str(tk.node),
    }));
  }

  const uc = get(doc, "update_check");
  if (isObj(uc)) {
    s.uc_enabled = boolOr(uc.enabled, false);
    s.uc_interval = str(uc.interval_seconds);
    s.uc_channel = str(uc.channel) || "stable";
    s.uc_url = str(uc.url);
    s.uc_notify = boolOr(uc.notify, false);
  }

  return s;
}

// Index-insensitive leaf paths of a parsed YAML document: array items collapse
// to "[]" so reordering never reads as loss. Used by the caller to compute
// which imported keys the regenerated file no longer carries.
export function leafPaths(v: unknown, prefix = ""): string[] {
  if (v === null || v === undefined) return prefix ? [prefix] : [];
  if (Array.isArray(v)) {
    if (v.length === 0) return prefix ? [prefix] : [];
    return v.flatMap((item) =>
      typeof item === "object" && item !== null ? leafPaths(item, `${prefix}[]`) : prefix ? [prefix] : [],
    );
  }
  if (typeof v === "object") {
    const entries = Object.entries(v as Obj);
    if (entries.length === 0) return prefix ? [prefix] : [];
    return entries.flatMap(([k, val]) => leafPaths(val, prefix ? `${prefix}.${k}` : k));
  }
  return prefix ? [prefix] : [];
}
