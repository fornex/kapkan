"use client";

// Config builder v2: one sectioned page instead of a stepper. The generated
// YAML is always on screen (sticky right pane) with just-changed lines
// highlighted, and the wasm engine verdict is a permanent strip — not a
// last-step reveal. Sections follow the operator pipeline (telemetry →
// networks → detection → mitigation → bans → notify → api); each field shows
// a human label with the raw YAML key beside it, and rarely-needed fields sit
// in one collapsed "Advanced" group per section.
//
// Coverage: every top-level subsystem of the engine config is editable here.
// Per-hostgroup DEEP overrides (group-level bgp/baseline/flowspec/scrubbing/
// escalation/outgoing thresholds) are deliberately YAML-only — the group card
// covers the core (name, networks, calculation, ban, tenant, mitigation,
// thresholds); the engine accepts hand-added keys the form does not render.

import { useEffect, useMemo, useRef, useState } from "react";
import type { Locale } from "@/lib/i18n";
import {
  wizardChrome,
  wizardHelp,
  wizardLabels,
  type SectionId,
  type WizardChrome,
} from "@/lib/wizard/strings";
import {
  emitConfig,
  emptyThresholds,
  initialState,
  THRESHOLD_KEYS,
  type ThresholdKey,
  type ThresholdSet,
  type WizardState,
} from "@/lib/wizard/emit";
import { fieldMeta, fieldNode } from "@/lib/wizard/schema";
import { validateNumber, validateString } from "@/lib/wizard/validate";
import { loadEngineValidator, type EngineResult, type EngineValidator } from "@/lib/wizard/wasm";
import {
  applyDiff,
  buildDiff,
  clearLocal,
  decodeShare,
  encodeDiff,
  loadLocal,
  saveLocal,
  type StateDiff,
} from "@/lib/wizard/share";
import { docToState, leafPaths } from "@/lib/wizard/import";

const inputCls =
  "w-full min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm outline-none transition-colors focus:border-accent";
const cellCls =
  "w-full min-w-0 rounded-md border bg-background px-2 py-1.5 font-mono text-xs outline-none transition-colors focus:border-accent";
const miniBtnCls =
  "rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted";

// ---------------------------------------------------------------------------
// Field registry: one declaration drives both rendering and per-section error
// status. Order inside a section is render order; `advanced` fields collapse
// into the section's Advanced group; `showIf` gates fields behind a toggle.

type FieldKind =
  | "text"
  | "number"
  | "bool"
  | "select"
  | "list"
  | "csv"
  | "matrix"
  | "neighbors"
  | "method"
  | "boundary"
  | "escalation"
  | "hostgroups"
  | "scrubnodes"
  | "rlprofiles"
  | "staticrules"
  | "apitokens";

type SubheadKey = keyof WizardChrome["subheads"];

type FieldDef = {
  kind: FieldKind;
  key?: keyof WizardState;
  path: string;
  matrix?: "thr" | "thrOut" | "carpetThr";
  itemPath?: string; // csv: schema path used to validate each token
  required?: boolean;
  mono?: boolean;
  advanced?: boolean;
  subhead?: SubheadKey; // rendered before this field
  emptyOption?: boolean; // select: allow "" = engine default
  numericCsv?: boolean; // csv: tokens must be integers
  showIf?: (s: WizardState) => boolean;
};

const SECTION_IDS: SectionId[] = [
  "telemetry",
  "networks",
  "detection",
  "mitigation",
  "bans",
  "notify",
  "api",
];

const FIELDS: Record<SectionId, FieldDef[]> = {
  telemetry: [
    { kind: "text", key: "sflow", path: "listen.sflow", mono: true },
    { kind: "text", key: "netflow", path: "listen.netflow", mono: true },
    { kind: "number", key: "default_rate", path: "sampling.default_rate", required: true },
    { kind: "bool", key: "boundary_debug", path: "sampling.boundary_debug", advanced: true },
    { kind: "boundary", key: "boundary", path: "sampling.boundary", advanced: true },
    { kind: "list", key: "flow_sources", path: "flow_sources", advanced: true },
  ],
  networks: [
    { kind: "list", key: "networks", path: "networks" },
    { kind: "list", key: "whitelist", path: "protected_whitelist" },
    { kind: "hostgroups", key: "hostgroups", path: "hostgroups" },
    { kind: "text", key: "tenant", path: "tenant", advanced: true },
  ],
  detection: [
    { kind: "matrix", matrix: "thr", path: "thresholds", required: true },
    { kind: "matrix", matrix: "thrOut", path: "thresholds_outgoing", advanced: true },
    { kind: "bool", key: "baseline_on", path: "baseline.enabled", advanced: true, subhead: "baseline" },
    { kind: "number", key: "baseline_factor", path: "baseline.factor", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "number", key: "baseline_half_life", path: "baseline.half_life_seconds", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "number", key: "baseline_warmup", path: "baseline.warmup_seconds", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "number", key: "baseline_floor_pps", path: "baseline.floor.pps", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "number", key: "baseline_floor_mbps", path: "baseline.floor.mbps", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "number", key: "baseline_floor_fps", path: "baseline.floor.flows_per_sec", advanced: true, showIf: (s) => s.baseline_on },
    { kind: "bool", key: "carpet_on", path: "carpet", advanced: true, subhead: "carpet" },
    { kind: "number", key: "carpet_v4", path: "carpet.aggregation_prefix_v4", advanced: true, showIf: (s) => s.carpet_on },
    { kind: "number", key: "carpet_v6", path: "carpet.aggregation_prefix_v6", advanced: true, showIf: (s) => s.carpet_on },
    { kind: "number", key: "carpet_min_hosts", path: "carpet.min_hosts", advanced: true, showIf: (s) => s.carpet_on },
    { kind: "matrix", matrix: "carpetThr", path: "carpet.thresholds", advanced: true, showIf: (s) => s.carpet_on },
    { kind: "select", key: "carpet_mitigation", path: "carpet.mitigation", advanced: true, emptyOption: true, showIf: (s) => s.carpet_on },
    { kind: "number", key: "carpet_max_bans", path: "carpet.max_active_prefix_bans", advanced: true, showIf: (s) => s.carpet_on },
    { kind: "bool", key: "samples_on", path: "samples", advanced: true, subhead: "samples" },
    { kind: "number", key: "samples_buffer", path: "samples.buffer_flows", advanced: true, showIf: (s) => s.samples_on },
    { kind: "number", key: "samples_per_attack", path: "samples.flows_per_attack", advanced: true, showIf: (s) => s.samples_on },
  ],
  mitigation: [
    { kind: "method", key: "mitigation", path: "mitigation", subhead: "method" },
    // (method-specific groups are rendered between `method` and the BGP core —
    // see METHOD_FIELDS below)
    { kind: "number", key: "local_asn", path: "bgp.local_asn", required: true, subhead: "bgp" },
    { kind: "text", key: "router_id", path: "bgp.router_id", required: true, mono: true },
    { kind: "text", key: "next_hop", path: "bgp.next_hop", required: true, mono: true },
    { kind: "text", key: "next_hop6", path: "bgp.next_hop6", mono: true },
    { kind: "text", key: "community", path: "bgp.community", required: true, mono: true },
    { kind: "neighbors", key: "neighbors", path: "bgp.neighbors" },
    { kind: "csv", key: "bgp_communities", path: "bgp.communities", itemPath: "bgp.communities", mono: true, advanced: true },
    { kind: "number", key: "bgp_listen_port", path: "bgp.listen_port", advanced: true },
    { kind: "number", key: "bgp_local_pref", path: "bgp.local_pref", advanced: true },
    { kind: "bool", key: "gr_enabled", path: "bgp.graceful_restart.enabled", advanced: true },
    { kind: "number", key: "gr_restart_seconds", path: "bgp.graceful_restart.restart_seconds", advanced: true },
    { kind: "bool", key: "gr_long_lived", path: "bgp.graceful_restart.long_lived", advanced: true },
    { kind: "number", key: "gr_long_lived_stale", path: "bgp.graceful_restart.long_lived_stale_seconds", advanced: true },
    { kind: "escalation", key: "escalation", path: "escalation", advanced: true, subhead: "escalation" },
  ],
  bans: [
    { kind: "number", key: "ttl_seconds", path: "ban.ttl_seconds", required: true },
    { kind: "number", key: "unban_hysteresis_seconds", path: "ban.unban_hysteresis_seconds", required: true },
    { kind: "number", key: "max_active_bans", path: "ban.max_active_bans", required: true },
    { kind: "select", key: "ban_fallback", path: "ban.fallback", advanced: true, emptyOption: true },
    { kind: "number", key: "ban_max_fraction", path: "ban.max_banned_fraction", advanced: true },
    { kind: "number", key: "ban_max_per_window", path: "ban.max_bans_per_window", advanced: true },
    { kind: "number", key: "ban_window_seconds", path: "ban.ban_window_seconds", advanced: true },
    { kind: "text", key: "state_file", path: "ban.state_file", mono: true, advanced: true },
  ],
  notify: [
    { kind: "text", key: "tg_token_env", path: "notify.telegram.token_env", mono: true, subhead: "telegram" },
    { kind: "text", key: "tg_chat_id", path: "notify.telegram.chat_id", mono: true },
    { kind: "text", key: "wh_url", path: "notify.webhook.url", mono: true },
    { kind: "text", key: "slack_url", path: "notify.slack.webhook_url", mono: true },
    { kind: "text", key: "email_smtp", path: "notify.email.smtp_host", mono: true, advanced: true, subhead: "email" },
    { kind: "text", key: "email_from", path: "notify.email.from", advanced: true },
    { kind: "csv", key: "email_to", path: "notify.email.to", advanced: true },
    { kind: "text", key: "email_user_env", path: "notify.email.username_env", mono: true, advanced: true },
    { kind: "text", key: "email_pass_env", path: "notify.email.password_env", mono: true, advanced: true },
    { kind: "bool", key: "email_tls", path: "notify.email.require_tls", advanced: true },
    { kind: "text", key: "exec_command", path: "notify.exec.command", mono: true, advanced: true, subhead: "exec" },
    { kind: "select", key: "exec_format", path: "notify.exec.format", advanced: true, emptyOption: true },
    { kind: "number", key: "exec_timeout", path: "notify.exec.timeout_seconds", advanced: true },
    { kind: "bool", key: "uc_enabled", path: "update_check.enabled", advanced: true, subhead: "updates" },
    { kind: "number", key: "uc_interval", path: "update_check.interval_seconds", advanced: true, showIf: (s) => s.uc_enabled },
    { kind: "select", key: "uc_channel", path: "update_check.channel", advanced: true, showIf: (s) => s.uc_enabled },
    { kind: "text", key: "uc_url", path: "update_check.url", mono: true, advanced: true, showIf: (s) => s.uc_enabled },
    { kind: "bool", key: "uc_notify", path: "update_check.notify", advanced: true, showIf: (s) => s.uc_enabled },
  ],
  api: [
    { kind: "text", key: "api_listen", path: "api.listen", required: true, mono: true },
    { kind: "bool", key: "api_dashboard", path: "api.dashboard" },
    { kind: "text", key: "api_token_env", path: "api.token_env", mono: true },
    { kind: "apitokens", key: "api_tokens", path: "api.tokens" },
    { kind: "text", key: "ch_url", path: "storage.clickhouse.url", mono: true, advanced: true, subhead: "storage" },
    { kind: "text", key: "ch_database", path: "storage.clickhouse.database", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "text", key: "ch_user_env", path: "storage.clickhouse.username_env", mono: true, advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "text", key: "ch_pass_env", path: "storage.clickhouse.password_env", mono: true, advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "number", key: "ch_ttl_days", path: "storage.clickhouse.ttl_days", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "number", key: "ch_flush", path: "storage.clickhouse.flush_interval_seconds", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "number", key: "ch_batch", path: "storage.clickhouse.batch_size", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "number", key: "ch_queue", path: "storage.clickhouse.queue_size", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "number", key: "ch_traffic", path: "storage.clickhouse.traffic_interval_seconds", advanced: true, showIf: (s) => s.ch_url.trim() !== "" },
    { kind: "bool", key: "geo_enabled", path: "geoip.enabled", advanced: true, subhead: "geoip" },
    { kind: "text", key: "geo_asn_db", path: "geoip.asn_database", mono: true, advanced: true, showIf: (s) => s.geo_enabled },
    { kind: "text", key: "geo_country_db", path: "geoip.country_database", mono: true, advanced: true, showIf: (s) => s.geo_enabled },
  ],
};

// Method-specific groups, rendered as auto-opening panels right under the
// method selector. Their errors count toward the mitigation section.
const METHOD_FIELDS: Record<"flowspec" | "scrubbing" | "dataplane", FieldDef[]> = {
  flowspec: [
    { kind: "select", key: "flowspec_action", path: "flowspec.action", emptyOption: true },
    { kind: "number", key: "flowspec_rate", path: "flowspec.rate_mbps" },
    { kind: "bool", key: "flowspec_anchored", path: "flowspec.source_anchored" },
    { kind: "number", key: "flowspec_minconc", path: "flowspec.min_source_concentration" },
  ],
  scrubbing: [
    { kind: "text", key: "scrub_next_hop", path: "scrubbing.next_hop", mono: true },
    { kind: "text", key: "scrub_next_hop6", path: "scrubbing.next_hop6", mono: true },
    { kind: "text", key: "scrub_community", path: "scrubbing.community", mono: true },
    { kind: "number", key: "scrub_local_pref", path: "scrubbing.local_pref" },
    { kind: "scrubnodes", key: "scrub_nodes", path: "scrubbing.nodes" },
    { kind: "select", key: "scrub_selection", path: "scrubbing.node_selection", emptyOption: true },
    { kind: "select", key: "scrub_on_lost", path: "scrubbing.on_all_nodes_lost", emptyOption: true },
    { kind: "number", key: "scrub_stale", path: "scrubbing.stale_after_seconds" },
  ],
  dataplane: [
    { kind: "bool", key: "dp_enabled", path: "dataplane.enabled" },
    { kind: "csv", key: "dp_interfaces", path: "dataplane.interfaces", mono: true },
    { kind: "select", key: "dp_xdp_mode", path: "dataplane.xdp_mode", emptyOption: true },
    { kind: "text", key: "dp_pin_path", path: "dataplane.pin_path", mono: true },
    { kind: "select", key: "dp_on_exit", path: "dataplane.on_exit", emptyOption: true },
    { kind: "bool", key: "dp_drop_malformed", path: "dataplane.drop_malformed" },
    { kind: "list", key: "dp_allowlist", path: "dataplane.allowlist" },
    { kind: "rlprofiles", key: "dp_profiles", path: "dataplane.ratelimit_profiles" },
    { kind: "staticrules", key: "dp_rules", path: "dataplane.static_rules" },
    { kind: "number", key: "dp_max_dynamic", path: "dataplane.limits.max_dynamic_rules" },
    { kind: "number", key: "dp_max_static", path: "dataplane.limits.max_static_rules" },
    { kind: "number", key: "dp_max_sources", path: "dataplane.limits.max_ratelimit_sources" },
  ],
};

// Best-effort map from an engine error's leading YAML path to the section that
// owns it, so the red verdict strip can jump to the right place.
const ERROR_SECTION: Array<[RegExp, SectionId]> = [
  [/^(listen|sampling|flow_sources)/, "telemetry"],
  [/^(networks|protected_whitelist|hostgroups|tenant)/, "networks"],
  [/^(thresholds|baseline|carpet|samples)/, "detection"],
  [/^(bgp|mitigation|flowspec|scrubbing|dataplane|escalation)/, "mitigation"],
  [/^ban\b|^ban[.:]/, "bans"],
  [/^(notify|update_check)/, "notify"],
  [/^(api|storage|geoip)/, "api"],
];

function guessErrorSection(err: string | undefined): SectionId | null {
  if (!err) return null;
  const head = err.trim();
  for (const [re, sec] of ERROR_SECTION) if (re.test(head)) return sec;
  return null;
}

const splitCsv = (v: string) => v.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

// Split a generated line into [code, comment]. Quote-aware on purpose: a "#" in
// a webhook URL fragment (notify.webhook.url, notify.slack.webhook_url) is data,
// and a naive indexOf("#") rendered half the URL as a grey comment.
function splitComment(ln: string): [string, string] {
  let inQuote = false;
  for (let i = 0; i < ln.length; i++) {
    const ch = ln[i];
    if (inQuote && ch === "\\") {
      i++;
      continue;
    }
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (ch === "#" && !inQuote && (i === 0 || /\s/.test(ln[i - 1]))) {
      return [ln.slice(0, i), ln.slice(i)];
    }
  }
  return [ln, ""];
}

// Applicability-named presets, stored as diffs over initialState (which IS the
// recommended hosting-edge baseline). Every preset must pass the engine check.
const PRESETS: Array<{ id: "edge" | "single" | "carrier"; diff: StateDiff }> = [
  { id: "edge", diff: {} },
  {
    id: "single",
    diff: {
      thr: { ...emptyThresholds(), pps: "20000", mbps: "500", flows_per_sec: "10000", udp_pps: "10000" },
      ttl_seconds: "300",
      max_active_bans: "10",
    },
  },
  {
    id: "carrier",
    diff: {
      thr: { ...emptyThresholds(), pps: "200000", mbps: "5000", flows_per_sec: "80000" },
      carpet_on: true,
      carpet_min_hosts: "10",
      carpetThr: { ...emptyThresholds(), pps: "2000000", mbps: "20000" },
      samples_on: true,
    },
  },
];

// Flat def list with owning section/panel — drives search and the modified count.
type SearchEntry = { f: FieldDef; section: SectionId; group?: "flowspec" | "scrubbing" | "dataplane" };
const ALL_DEFS: SearchEntry[] = [
  ...SECTION_IDS.flatMap((id) => FIELDS[id].map((f) => ({ f, section: id }))),
  ...(Object.keys(METHOD_FIELDS) as Array<keyof typeof METHOD_FIELDS>).flatMap((g) =>
    METHOD_FIELDS[g].map((f) => ({ f, section: "mitigation" as SectionId, group: g })),
  ),
];

// Module-level on purpose: defining this inside ConfigBuilder would give it a
// new component identity every render, remounting the subtree and dropping
// input focus on each keystroke.
// One field row. Label + YAML key on the left, control on the right — the
// settings-page shape, so a column of rows scans vertically instead of ragging.
// The description is NOT printed by default: 50 always-on help paragraphs were
// what made the page unreadable. It appears on demand (per field, or globally
// via the toolbar switch); errors always show.
function FieldShell({
  f,
  label,
  help,
  gloss,
  error,
  modified,
  onReset,
  resetTitle,
  showHelp,
  helpLabel,
  wide,
  children,
}: {
  f: FieldDef;
  label: string;
  help?: string;
  gloss?: string | null;
  error: string | null;
  modified?: boolean;
  onReset?: () => void;
  resetTitle?: string;
  showHelp?: boolean;
  helpLabel?: string;
  wide?: boolean; // matrices and row editors take the full width instead of the right half
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const helpVisible = !!help && (showHelp || open);
  return (
    <div
      className={`group/field relative py-3 pl-3 ${
        modified ? "before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-full before:bg-accent" : ""
      }`}
    >
      {/* container query, not a viewport one: the row splits into label/control
          columns based on how wide the SECTION actually is, so a narrow form
          column keeps the stacked layout instead of squeezing */}
      <div
        className={
          wide
            ? "space-y-2"
            : "gap-x-6 gap-y-2 @[34rem]/sec:grid @[34rem]/sec:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] @[34rem]/sec:items-start"
        }
      >
        <div className={wide ? "" : "min-w-0 @[34rem]/sec:pt-1.5"}>
          <div className="flex items-baseline gap-2">
            <label htmlFor={`f-${f.path}`} className="text-[13px] font-medium leading-snug">
              {label}
            </label>
            {help && !showHelp && (
              <button
                type="button"
                title={helpLabel}
                aria-label={helpLabel}
                aria-expanded={open}
                onClick={() => setOpen((v) => !v)}
                className={`shrink-0 rounded-full border border-border px-1.5 text-[10px] leading-4 transition-opacity ${
                  open ? "text-foreground" : "text-muted-foreground opacity-0 group-hover/field:opacity-100 focus-visible:opacity-100"
                }`}
              >
                ?
              </button>
            )}
            {modified && onReset && (
              <button
                type="button"
                title={resetTitle}
                aria-label={resetTitle}
                onClick={onReset}
                className="shrink-0 text-[11px] leading-4 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover/field:opacity-100 focus-visible:opacity-100"
              >
                ↺
              </button>
            )}
          </div>
          <code className="mt-0.5 block font-mono text-[11px] leading-4 text-muted-foreground/70">
            {f.path}
          </code>
        </div>
        <div className={wide ? "" : "min-w-0 flex-1"}>
          {children}
          {(error || gloss) && (
            <div className="mt-1 flex items-baseline justify-between gap-3">
              {error ? <p className="text-xs text-red-500">{error}</p> : <span />}
              {gloss && !error && (
                <span className="ml-auto shrink-0 text-[11px] font-medium text-muted-foreground">{gloss}</span>
              )}
            </div>
          )}
        </div>
      </div>
      {helpVisible && (
        <p className="mt-2 max-w-[68ch] text-xs leading-relaxed text-muted-foreground">{help}</p>
      )}
    </div>
  );
}

export function ConfigBuilder({ lang }: { lang: Locale }) {
  const t = wizardChrome[lang];
  const vmsg = t.validation;
  const labelOf = (path: string): string =>
    wizardLabels[lang]?.[path] ?? wizardLabels.en[path] ?? path;
  const helpOf = (path?: string): string | undefined =>
    path ? (wizardHelp[lang]?.[path] ?? fieldMeta(path).description) : undefined;

  const [s, setS] = useState<WizardState>(initialState);
  const [copied, setCopied] = useState(false);
  const [active, setActive] = useState<SectionId>("telemetry");
  // per-method-group manual open override; null = follow the active method
  const [groupOpen, setGroupOpen] = useState<Record<string, boolean | null>>({
    flowspec: null,
    scrubbing: null,
    dataplane: null,
  });
  // stage-3 service layer.
  // The pressed state of the @modified chip; what the form actually filters by
  // is the derived `filterModified` below — a filter with nothing left to show
  // must not stay in force.
  const [filterModifiedOn, setFilterModifiedOn] = useState(false);
  // Deterministic initial values — a static export hydrates with these, then a
  // mount effect applies what the operator chose last time.
  const [showHelp, setShowHelp] = useState(false);
  const [dockOpen, setDockOpen] = useState(true);
  const [presetsOpen, setPresetsOpen] = useState(false);
  // The YAML pane has exactly ONE mount at a time — a CSS-hidden second copy
  // would duplicate every id inside it (including #yaml-pane).
  const [wideLayout, setWideLayout] = useState(false);
  const [protoOpen, setProtoOpen] = useState<Record<string, boolean>>({});
  const [searchQ, setSearchQ] = useState("");
  const [searchFocus, setSearchFocus] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importDiag, setImportDiag] = useState<{ lost: string[]; error?: string } | null>(null);
  const [shared, setShared] = useState(false);
  const [flashPath, setFlashPath] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const restoredRef = useRef(false);
  const blurTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // View preferences live outside the config state on purpose: they must never
  // reach buildDiff / the share hash / the saved diff.
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1440px)");
    let stored: string | null = null;
    try {
      // one-time hydration of view prefs; deterministic defaults render first
      // eslint-disable-next-line react-hooks/set-state-in-effect
      if (localStorage.getItem("kapkan.cfg.help") === "1") setShowHelp(true);
      stored = localStorage.getItem("kapkan.cfg.dock");
    } catch {
      /* storage blocked — defaults are fine */
    }
    // Where there is room the file stays open beside the form; where there is
    // not, it collapses to the status strip (which still carries the verdict)
    // so the form owns the screen. An explicit choice always wins.
    setDockOpen(stored === null ? mq.matches : stored === "1");
    const sync = () => setWideLayout(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);

  function toggleHelp() {
    setShowHelp((v) => {
      try {
        localStorage.setItem("kapkan.cfg.help", v ? "0" : "1");
      } catch {
        /* ignore */
      }
      return !v;
    });
  }

  function toggleDock(next: boolean) {
    setDockOpen(next);
    try {
      localStorage.setItem("kapkan.cfg.dock", next ? "1" : "0");
    } catch {
      /* ignore */
    }
  }

  // Restore once: a share link wins over the local autosave.
  useEffect(() => {
    try {
      const m = window.location.hash.match(/^#s=(.+)$/);
      const diff = m ? decodeShare(m[1]) : loadLocal();
      if (diff && Object.keys(diff).length > 0) {
        // One-time mount restore of saved/shared work.
        setS(applyDiff(diff));
      }
    } finally {
      restoredRef.current = true;
    }
  }, []);

  // Autosave + keep the URL shareable: both store the diff vs defaults.
  useEffect(() => {
    if (!restoredRef.current) return;
    const id = setTimeout(() => {
      const diff = buildDiff(s);
      saveLocal(diff);
      const hash = Object.keys(diff).length > 0 ? "#s=" + encodeDiff(diff) : "";
      window.history.replaceState(null, "", window.location.pathname + window.location.search + hash);
    }, 500);
    return () => clearTimeout(id);
  }, [s]);

  const yaml = useMemo(() => emitConfig(s), [s]);
  const yamlLines = useMemo(() => yaml.split("\n"), [yaml]);

  // --- just-changed line highlighting: compare against the previous emit as a
  // multiset, so unchanged-but-shifted lines don't flash.
  const prevLinesRef = useRef<string[] | null>(null);
  const [hotLines, setHotLines] = useState<Set<number>>(() => new Set());
  useEffect(() => {
    const prev = prevLinesRef.current;
    prevLinesRef.current = yamlLines;
    if (!prev) return;
    const pool = new Map<string, number>();
    for (const l of prev) pool.set(l, (pool.get(l) ?? 0) + 1);
    const fresh = new Set<number>();
    yamlLines.forEach((l, i) => {
      const n = pool.get(l) ?? 0;
      if (n > 0) pool.set(l, n - 1);
      else fresh.add(i);
    });
    if (fresh.size === 0) return;
    // Intentional one-frame visual pulse: flag the just-changed lines, then fade.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHotLines(fresh);
    const id = setTimeout(() => setHotLines(new Set()), 1400);
    return () => clearTimeout(id);
  }, [yamlLines]);

  // --- engine-exact validation via the wasm build of the real Parse+validate.
  const validatorRef = useRef<EngineValidator | null>(null);
  const [engineReady, setEngineReady] = useState<boolean | null>(null);
  const [engineResult, setEngineResult] = useState<EngineResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadEngineValidator().then((fn) => {
      if (cancelled) return;
      validatorRef.current = fn;
      setEngineReady(!!fn);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const fn = validatorRef.current;
    if (!fn) return;
    const id = setTimeout(() => {
      try {
        setEngineResult(fn(yaml));
      } catch {
        setEngineResult(null);
      }
    }, 350);
    return () => clearTimeout(id);
  }, [yaml, engineReady]);

  // --- scrollspy for the section rail.
  useEffect(() => {
    const obs = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id.slice(4) as SectionId);
      },
      // matches the two-row sticky bar (97px); the bar's height is invariant —
      // the live-mode warning reuses row 1 instead of adding a third row
      { rootMargin: "-104px 0px -55% 0px", threshold: 0 },
    );
    for (const id of SECTION_IDS) {
      const el = document.getElementById(`sec-${id}`);
      if (el) obs.observe(el);
    }
    return () => obs.disconnect();
  }, []);

  function set<K extends keyof WizardState>(k: K, v: WizardState[K]) {
    setS((p) => ({ ...p, [k]: v }));
    // An edit made while the chip is pressed but the filter has nothing to show
    // (it dropped itself) forgets the press — otherwise this very edit would
    // snap the form back into the filtered view around the field just touched.
    if (filterModifiedOn && !filterModified) setFilterModifiedOn(false);
  }

  function scrollToSection(id: SectionId) {
    setActive(id);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document
      .getElementById(`sec-${id}`)
      ?.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }

  function copy() {
    navigator.clipboard?.writeText(yaml).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  function download() {
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "config.yaml";
    a.click();
    URL.revokeObjectURL(url);
  }

  // Which mitigation methods the config actually uses (method, escalation
  // rungs, hostgroup overrides, carpet) — drives the auto-open method panels.
  const usesAction = (a: string) =>
    s.mitigation === a ||
    s.escalation.some((e) => e.action === a) ||
    s.hostgroups.some((g) => g.mitigation === a) ||
    s.carpet_mitigation === a;
  const methodAuto: Record<"flowspec" | "scrubbing" | "dataplane", boolean> = {
    flowspec: usesAction("flowspec"),
    scrubbing: usesAction("divert"),
    dataplane: usesAction("dataplane") || s.dp_enabled,
  };

  // --- per-field validation, shared by the renderers and the section dots.
  function matrixError(f: FieldDef): string | null {
    const val = s[f.matrix!] as ThresholdSet;
    for (const k of THRESHOLD_KEYS) {
      const raw = val[k].trim();
      if (f.required && f.matrix === "thr" && (k === "pps" || k === "mbps" || k === "flows_per_sec")) {
        if (raw === "") return vmsg.required;
      }
      if (raw === "") continue;
      const err = validateNumber(`${f.path}.${k}`, Number(raw), vmsg);
      if (err) return err;
    }
    return null;
  }

  function fieldError(f: FieldDef): string | null {
    if (f.showIf && !f.showIf(s)) return null;
    switch (f.kind) {
      case "text": {
        const v = s[f.key!] as string;
        if (v.trim() === "") return f.required ? vmsg.required : null;
        return validateString(f.path, v, vmsg);
      }
      case "number": {
        const v = s[f.key!] as string;
        if (v.trim() === "") return f.required ? vmsg.required : null;
        return validateNumber(f.path, Number(v), vmsg);
      }
      case "list": {
        for (const item of s[f.key!] as string[]) {
          if (!item.trim()) continue;
          const err = validateString(f.path, item, vmsg);
          if (err) return err;
        }
        return null;
      }
      case "csv": {
        for (const token of splitCsv(s[f.key!] as string)) {
          if (f.numericCsv) {
            if (!/^\d+$/.test(token)) return vmsg.notNumber;
            continue;
          }
          const err = f.itemPath ? validateString(f.itemPath, token, vmsg) : null;
          if (err) return err;
        }
        return null;
      }
      case "matrix":
        return matrixError(f);
      case "neighbors": {
        for (const n of s.neighbors) {
          if (n.address.trim()) {
            const err = validateString("bgp.neighbors.address", n.address, vmsg);
            if (err) return err;
          }
          if (n.remote_asn.trim()) {
            const err = validateNumber("bgp.neighbors.remote_asn", Number(n.remote_asn), vmsg);
            if (err) return err;
          }
          if (n.port.trim()) {
            const err = validateNumber("bgp.neighbors.port", Number(n.port), vmsg);
            if (err) return err;
          }
        }
        return null;
      }
      case "boundary": {
        for (const b of s.boundary) {
          if (b.exporter.trim()) {
            const err = validateString("sampling.boundary.exporter", b.exporter, vmsg);
            if (err) return err;
          }
          for (const token of splitCsv(b.external_ifindexes)) {
            if (!/^\d+$/.test(token)) return vmsg.notNumber;
          }
        }
        return null;
      }
      case "escalation": {
        for (const e of s.escalation) {
          if (e.after_seconds.trim()) {
            const err = validateNumber("escalation.after_seconds", Number(e.after_seconds), vmsg);
            if (err) return err;
          }
          if (e.action) {
            const err = validateString("escalation.action", e.action, vmsg);
            if (err) return err;
          }
        }
        return null;
      }
      case "hostgroups": {
        for (const g of s.hostgroups) {
          if (g.name.trim()) {
            const err = validateString("hostgroups.name", g.name, vmsg);
            if (err) return err;
          }
          for (const net of splitCsv(g.networks)) {
            const err = validateString("hostgroups.networks", net, vmsg);
            if (err) return err;
          }
          for (const k of THRESHOLD_KEYS) {
            const raw = g.thr[k].trim();
            if (raw === "") continue;
            const err = validateNumber(`hostgroups.thresholds.${k}`, Number(raw), vmsg);
            if (err) return err;
          }
        }
        return null;
      }
      case "scrubnodes": {
        for (const n of s.scrub_nodes) {
          if (n.next_hop.trim()) {
            const err = validateString("scrubbing.nodes.next_hop", n.next_hop, vmsg);
            if (err) return err;
          }
          if (n.next_hop6.trim()) {
            const err = validateString("scrubbing.nodes.next_hop6", n.next_hop6, vmsg);
            if (err) return err;
          }
          if (n.capacity_mbps.trim()) {
            const err = validateNumber("scrubbing.nodes.capacity_mbps", Number(n.capacity_mbps), vmsg);
            if (err) return err;
          }
        }
        return null;
      }
      case "rlprofiles": {
        for (const p of s.dp_profiles) {
          if (p.name.trim()) {
            const err = validateString("dataplane.ratelimit_profiles.name", p.name, vmsg);
            if (err) return err;
          }
          for (const [path, v] of [
            ["dataplane.ratelimit_profiles.pps", p.pps],
            ["dataplane.ratelimit_profiles.mbps", p.mbps],
          ] as const) {
            if (v.trim()) {
              const err = validateNumber(path, Number(v), vmsg);
              if (err) return err;
            }
          }
        }
        return null;
      }
      case "staticrules": {
        for (const r of s.dp_rules) {
          if (r.name.trim()) {
            const err = validateString("dataplane.static_rules.name", r.name, vmsg);
            if (err) return err;
          }
          if (r.src.trim()) {
            const err = validateString("dataplane.static_rules.match.src", r.src, vmsg);
            if (err) return err;
          }
          if (r.proto) {
            const err = validateString("dataplane.static_rules.match.proto", r.proto, vmsg);
            if (err) return err;
          }
          if (r.payload) {
            const err = validateString("dataplane.static_rules.match.payload", r.payload, vmsg);
            if (err) return err;
          }
          for (const [path, v] of [
            ["dataplane.static_rules.match.src_port", r.src_port],
            ["dataplane.static_rules.match.dst_port", r.dst_port],
          ] as const) {
            if (v.trim()) {
              const err = validateNumber(path, Number(v), vmsg);
              if (err) return err;
            }
          }
        }
        return null;
      }
      case "apitokens": {
        for (const tk of s.api_tokens) {
          if (tk.name.trim()) {
            const err = validateString("api.tokens.name", tk.name, vmsg);
            if (err) return err;
          }
          if (tk.role) {
            const err = validateString("api.tokens.role", tk.role, vmsg);
            if (err) return err;
          }
        }
        return null;
      }
      default:
        return null;
    }
  }

  const sectionErrors = useMemo(() => {
    const out = {} as Record<SectionId, number>;
    for (const id of SECTION_IDS) {
      out[id] = FIELDS[id].reduce((n, f) => n + (fieldError(f) ? 1 : 0), 0);
    }
    for (const defs of Object.values(METHOD_FIELDS)) {
      out.mitigation += defs.reduce((n, f) => n + (fieldError(f) ? 1 : 0), 0);
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s, vmsg]);
  const totalErrors = SECTION_IDS.reduce((n, id) => n + sectionErrors[id], 0);
  const firstErrorSection = SECTION_IDS.find((id) => sectionErrors[id] > 0) ?? null;

  // --- modified-vs-default tracking (the VS Code @modified pattern) ---
  const fieldSlice = (st: WizardState, f: FieldDef): unknown =>
    f.matrix ? st[f.matrix] : f.key ? st[f.key] : undefined;
  const fieldModified = (f: FieldDef): boolean =>
    JSON.stringify(fieldSlice(s, f)) !== JSON.stringify(fieldSlice(initialState, f));
  // A field whose showIf gate is shut has no row to filter down to, so it is not
  // a deviation the operator can see or act on — it must not be counted as one.
  const fieldShown = (f: FieldDef): boolean => !f.showIf || f.showIf(s);
  const fieldDeviates = (f: FieldDef): boolean => fieldModified(f) && fieldShown(f);
  function resetField(f: FieldDef) {
    if (f.matrix) set(f.matrix, JSON.parse(JSON.stringify(initialState[f.matrix])));
    else if (f.key) set(f.key, JSON.parse(JSON.stringify(initialState[f.key])) as WizardState[keyof WizardState]);
  }
  // Every deviation, hidden ones included: this is what Reset/preset would wipe,
  // so it is what their confirmations must count.
  const modifiedCount = ALL_DEFS.reduce((n, e) => n + (fieldModified(e.f) ? 1 : 0), 0);
  // per-section deviation count for the rail (must come after fieldDeviates —
  // a useMemo body runs during render, so an earlier call would hit its TDZ)
  const sectionModified = useMemo(() => {
    const out = {} as Record<SectionId, number>;
    for (const id of SECTION_IDS) {
      out[id] = FIELDS[id].reduce((n, f) => n + (fieldDeviates(f) ? 1 : 0), 0);
    }
    for (const defs of Object.values(METHOD_FIELDS)) {
      out.mitigation += defs.reduce((n, f) => n + (fieldDeviates(f) ? 1 : 0), 0);
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s]);
  // What the @modified view would actually list. The chip offers itself only
  // while this is non-zero, and the filter is only in force while the chip is
  // there to switch it off: resetting the last edit from inside the filtered
  // view used to leave every section filtered away with the chip already gone —
  // an empty page no click could undo, only a reload.
  const shownModified = SECTION_IDS.reduce((n, id) => n + sectionModified[id], 0);
  const filterModified = filterModifiedOn && shownModified > 0;

  function applyPreset(diff: StateDiff) {
    if (modifiedCount > 0 && !window.confirm(t.presets.confirm)) return;
    setS(applyDiff(diff));
    setImportDiag(null);
  }

  function resetAll() {
    if (modifiedCount > 0 && !window.confirm(t.reset.confirm)) return;
    clearLocal();
    setS(JSON.parse(JSON.stringify(initialState)));
    setImportDiag(null);
    setFilterModifiedOn(false);
  }

  function shareLink() {
    const diff = buildDiff(s);
    const hash = Object.keys(diff).length > 0 ? "#s=" + encodeDiff(diff) : "";
    const url = window.location.origin + window.location.pathname + window.location.search + hash;
    navigator.clipboard?.writeText(url).then(() => {
      setShared(true);
      setTimeout(() => setShared(false), 1500);
    });
  }

  async function doImport() {
    try {
      const { load } = await import("js-yaml");
      const doc = load(importText);
      if (!doc || typeof doc !== "object") throw new Error("not a YAML mapping");
      const next = docToState(doc);
      const emitted = load(emitConfig(next));
      const emittedLeaves = new Set(leafPaths(emitted));
      const lost = [...new Set(leafPaths(doc).filter((p) => !emittedLeaves.has(p)))];
      setS(next);
      setImportDiag({ lost });
      setFilterModifiedOn(false);
    } catch (e) {
      setImportDiag({ lost: [], error: e instanceof Error ? e.message : String(e) });
    }
  }

  function copyCmd(cmd: string) {
    navigator.clipboard?.writeText(cmd).then(() => {
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 1500);
    });
  }

  // Search across labels, YAML keys and help text; jump opens whatever hides
  // the field (advanced <details>, a method panel) and flashes it.
  const searchResults = (() => {
    const q = searchQ.trim().toLowerCase();
    if (!q || !searchFocus) return [];
    return ALL_DEFS.map((entry) => {
      const label = labelOf(entry.f.path).toLowerCase();
      const path = entry.f.path.toLowerCase();
      const help = (helpOf(entry.f.path) ?? "").toLowerCase();
      const score = label.startsWith(q) ? 0 : label.includes(q) ? 1 : path.includes(q) ? 2 : help.includes(q) ? 3 : -1;
      return { entry, score };
    })
      .filter((x) => x.score >= 0)
      .sort((a, b) => a.score - b.score)
      .slice(0, 12)
      .map((x) => x.entry);
  })();

  function jumpToField(entry: SearchEntry) {
    setSearchQ("");
    setSearchFocus(false);
    if (entry.group) setGroupOpen((p) => ({ ...p, [entry.group as string]: true }));
    // a jump to a field the @modified view does not list has to leave that view
    if (!filterModified || !fieldDeviates(entry.f)) setFilterModifiedOn(false);
    setFlashPath(entry.f.path);
    setTimeout(() => {
      const el = document.getElementById(`fw-${entry.f.path}`);
      let d = el?.closest("details");
      while (d) {
        d.open = true;
        d = d.parentElement?.closest("details") ?? null;
      }
      const target = el ?? document.getElementById(`sec-${entry.section}`);
      const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      target?.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
    }, 60);
    setTimeout(() => setFlashPath(null), 1800);
  }

  // Human gloss for *_seconds fields: "600" → "≈ 10 min".
  function secondsGloss(f: FieldDef): string | null {
    if (f.kind !== "number" || !f.path.endsWith("_seconds")) return null;
    const n = Number((s[f.key!] as string).trim());
    if (!Number.isFinite(n) || n < 120) return null;
    if (n >= 5400) return t.hours.replace("{v}", (Math.round((n / 3600) * 10) / 10).toString());
    return t.minutes.replace("{v}", Math.round(n / 60).toString());
  }

  // ------------------------------------------------------------------ fields

  // An empty box says nothing; an empty box showing the value the engine would
  // use says what leaving it empty MEANS. Booleans have a switch, and the three
  // overlay defaults that are literally "" still deserve the em dash.
  function placeholderFor(f: FieldDef): string {
    const d = fieldMeta(f.path).defaultWhenAbsent;
    if (d === undefined || typeof d === "boolean") return "—";
    return String(d) || "—";
  }

  const WIDE_KINDS: FieldKind[] = [
    "matrix",
    "list",
    "neighbors",
    "boundary",
    "escalation",
    "hostgroups",
    "scrubnodes",
    "rlprofiles",
    "staticrules",
    "apitokens",
    "method",
  ];

  const shellProps = (f: FieldDef) => {
    const modified = fieldModified(f);
    return {
      f,
      label: labelOf(f.path),
      help: helpOf(f.path),
      gloss: secondsGloss(f),
      modified,
      onReset: modified ? () => resetField(f) : undefined,
      resetTitle: t.reset.btn,
      showHelp,
      helpLabel: t.helpOne,
      wide: WIDE_KINDS.includes(f.kind),
    };
  };

  function renderText(f: FieldDef) {
    const value = s[f.key!] as string;
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <input
          id={`f-${f.path}`}
          className={`${inputCls} ${f.mono ? "max-w-[22rem] font-mono" : "max-w-[26rem]"}`}
          value={value}
          placeholder={placeholderFor(f)}
          spellCheck={false}
          onChange={(e) => set(f.key!, e.target.value as WizardState[typeof f.key & keyof WizardState])}
        />
      </FieldShell>
    );
  }

  function renderNumber(f: FieldDef) {
    const value = s[f.key!] as string;
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <input
          id={`f-${f.path}`}
          className={`${inputCls} max-w-[11rem] font-mono`}
          inputMode="numeric"
          value={value}
          placeholder={placeholderFor(f)}
          spellCheck={false}
          onChange={(e) => set(f.key!, e.target.value as WizardState[typeof f.key & keyof WizardState])}
        />
      </FieldShell>
    );
  }

  function renderCsv(f: FieldDef) {
    const value = s[f.key!] as string;
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <input
          id={`f-${f.path}`}
          className={`${inputCls} max-w-[30rem]${f.mono ? " font-mono" : ""}`}
          value={value}
          spellCheck={false}
          placeholder="a, b, c"
          onChange={(e) => set(f.key!, e.target.value as WizardState[typeof f.key & keyof WizardState])}
        />
      </FieldShell>
    );
  }

  function renderBool(f: FieldDef) {
    // A boolean is its own control: render it as a switch row (label left,
    // switch right) so it lines up with the value column of every other row.
    const on = s[f.key!] as boolean;
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={null}>
        <div className="flex @[34rem]/sec:justify-start">
          <button
            type="button"
            role="switch"
            aria-checked={on}
            aria-labelledby={undefined}
            aria-label={labelOf(f.path)}
            onClick={() => set(f.key!, !on as WizardState[typeof f.key & keyof WizardState])}
            className={`relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors ${
              on ? "border-accent bg-accent" : "border-border bg-muted"
            }`}
          >
            <span
              aria-hidden
              className={`absolute top-0.5 h-3.5 w-3.5 rounded-full bg-background transition-[left] ${
                on ? "left-[18px]" : "left-0.5"
              }`}
            />
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderSelect(f: FieldDef) {
    const opts = fieldNode(f.path)?.enum ?? [];
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <select
          id={`f-${f.path}`}
          className={`${inputCls} max-w-[16rem]`}
          value={s[f.key!] as string}
          onChange={(e) => set(f.key!, e.target.value as WizardState[typeof f.key & keyof WizardState])}
        >
          {f.emptyOption && <option value="">—</option>}
          {opts.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </FieldShell>
    );
  }

  function renderList(f: FieldDef) {
    const values = s[f.key!] as string[];
    const key = f.key as "networks" | "whitelist" | "flow_sources" | "dp_allowlist";
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={null}>
        <div className="space-y-2">
          {values.length === 0 && (
            <p className="max-w-[26rem] rounded-md border border-dashed border-border px-3 py-1.5 text-xs text-muted-foreground">
              {t.emptyList}
            </p>
          )}
          {values.map((v, i) => {
            const err = v.trim() ? validateString(f.path, v, vmsg) : null;
            return (
              <div key={i}>
                <div className="flex gap-2">
                  <input
                    className={`${inputCls} max-w-[26rem] font-mono`}
                    value={v}
                    spellCheck={false}
                    onChange={(e) => {
                      const next = values.slice();
                      next[i] = e.target.value;
                      set(key, next);
                    }}
                  />
                  <button
                    type="button"
                    aria-label="remove"
                    className="shrink-0 rounded-md border border-border px-3 text-muted-foreground hover:bg-muted"
                    onClick={() => set(key, values.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </div>
                {err && <p className="mt-1 text-xs text-red-500">{err}</p>}
              </div>
            );
          })}
          <button type="button" className={miniBtnCls} onClick={() => set(key, [...values, ""])}>
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderMatrix(f: FieldDef) {
    const mkey = f.matrix!;
    const val = s[mkey] as ThresholdSet;
    const upd = (k: ThresholdKey, v: string) =>
      set(mkey, { ...val, [k]: v } as WizardState[typeof mkey]);
    const rows: Array<{ label: string; pps: ThresholdKey; mbps: ThresholdKey }> = [
      { label: t.thr.total, pps: "pps", mbps: "mbps" },
      { label: t.thr.tcp, pps: "tcp_pps", mbps: "tcp_mbps" },
      { label: t.thr.tcpSyn, pps: "tcp_syn_pps", mbps: "tcp_syn_mbps" },
      { label: t.thr.udp, pps: "udp_pps", mbps: "udp_mbps" },
      { label: t.thr.icmp, pps: "icmp_pps", mbps: "icmp_mbps" },
      { label: t.thr.frag, pps: "frag_pps", mbps: "frag_mbps" },
    ];
    const err = matrixError(f);
    const cell = (k: ThresholdKey) => {
      const raw = val[k].trim();
      const bad =
        (raw !== "" && validateNumber(`${f.path}.${k}`, Number(raw), vmsg) !== null) ||
        (f.required && f.matrix === "thr" && raw === "" &&
          (k === "pps" || k === "mbps" || k === "flows_per_sec"));
      return (
        <input
          aria-label={`${f.path}.${k}`}
          className={`${cellCls} ${bad ? "border-red-500" : "border-border"}`}
          inputMode="numeric"
          placeholder={t.thrOff}
          value={val[k]}
          spellCheck={false}
          onChange={(e) => upd(k, e.target.value)}
        />
      );
    };
    // Only the "any traffic" limits are shown up front. Ten mostly-empty
    // per-protocol boxes are what made this read as a broken spreadsheet, so
    // they live behind a disclosure that opens itself when any of them is set.
    const protoRows = rows.slice(1);
    const protoSet = protoRows.some((r) => val[r.pps].trim() !== "" || val[r.mbps].trim() !== "");
    const headers = (
      <>
        <span />
        <span className="pl-1 font-mono text-[11px] text-muted-foreground">pps</span>
        <span className="pl-1 font-mono text-[11px] text-muted-foreground">mbps</span>
      </>
    );
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={err}>
        <div className="grid max-w-[30rem] grid-cols-[minmax(88px,1fr)_7rem_7rem] items-center gap-x-2 gap-y-1.5">
          {headers}
          <span className="text-xs text-muted-foreground">{rows[0].label}</span>
          {cell(rows[0].pps)}
          {cell(rows[0].mbps)}
          <span className="text-xs text-muted-foreground">{t.thr.flows}</span>
          {cell("flows_per_sec")}
          <span />
        </div>
        {/* uncontrolled-with-an-override: `open={protoSet}` alone re-asserted
            itself on every render, so the operator could not close the group */}
        <details
          className="group/proto mt-2"
          open={protoOpen[f.path] ?? protoSet}
          onToggle={(e) =>
            setProtoOpen((p) => ({ ...p, [f.path]: (e.currentTarget as HTMLDetailsElement).open }))
          }
        >
          <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
            <span aria-hidden className="text-[9px] transition-transform group-open/proto:rotate-90">
              ▶
            </span>
            {t.thr.perProto}
          </summary>
          <div className="mt-2 grid max-w-[30rem] grid-cols-[minmax(88px,1fr)_7rem_7rem] items-center gap-x-2 gap-y-1.5">
            {headers}
            {protoRows.map((r) => (
              <div key={r.pps} className="contents">
                <span className="text-xs text-muted-foreground">{r.label}</span>
                {cell(r.pps)}
                {cell(r.mbps)}
              </div>
            ))}
          </div>
        </details>
        {!err && <p className="mt-2 text-[11px] text-muted-foreground/80">{t.thr.hint}</p>}
      </FieldShell>
    );
  }

  // Small building blocks for the repeatable-row editors.
  // Every repeatable row gets a header naming WHICH row it is (its index in the
  // YAML plus whatever identifies it), so a list of five stops being five
  // identical boxes of inputs.
  function rowShell(
    children: React.ReactNode,
    onRemove: () => void,
    key: number,
    meta?: { basePath: string; title?: string },
  ) {
    return (
      <div key={key} className="overflow-hidden rounded-lg border border-border bg-background/40">
        {meta && (
          <div className="flex items-center gap-2 border-b border-border/70 bg-muted px-3 py-1.5">
            <code className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground/70">
              {`${meta.basePath}[${key}]`}
            </code>
            <span className="min-w-0 flex-1 truncate text-[12px] font-medium">
              {meta.title?.trim() ? (
                meta.title
              ) : (
                <span className="font-normal text-muted-foreground/60">{t.rowUntitled}</span>
              )}
            </span>
            <button
              type="button"
              aria-label={t.removeRow}
              title={t.removeRow}
              className="shrink-0 rounded p-1 text-[13px] leading-none text-muted-foreground/60 hover:bg-red-500/10 hover:text-red-500"
              onClick={onRemove}
            >
              ×
            </button>
          </div>
        )}
        <div className="flex flex-wrap items-end gap-2 px-3 py-2.5">{children}</div>
      </div>
    );
  }

  // Cells inside repeatable rows carry a caption instead of relying on a
  // placeholder that vanishes the moment you type — a row of seven anonymous
  // boxes was unreadable once filled.
  function rowInput(opts: {
    value: string;
    placeholder: string;
    onChange: (v: string) => void;
    width?: string;
    numeric?: boolean;
    error?: string | null;
  }) {
    return (
      <label className={`flex min-w-0 flex-col gap-0.5 ${opts.width ?? "w-32"}`}>
        <span className="truncate font-mono text-[10px] leading-3 text-muted-foreground/80">
          {opts.placeholder}
        </span>
        <input
          className={`${cellCls} ${opts.error ? "border-red-500" : "border-border"}`}
          value={opts.value}
          spellCheck={false}
          inputMode={opts.numeric ? "numeric" : undefined}
          onChange={(e) => opts.onChange(e.target.value)}
        />
      </label>
    );
  }

  function rowSelect(opts: {
    value: string;
    path: string;
    onChange: (v: string) => void;
    width?: string;
    emptyLabel?: string;
  }) {
    const enumOpts = fieldNode(opts.path)?.enum ?? [];
    const caption = opts.path.split(".").pop() ?? opts.path;
    return (
      <label className={`flex min-w-0 flex-col gap-0.5 ${opts.width ?? "w-28"}`}>
        <span className="truncate font-mono text-[10px] leading-3 text-muted-foreground/80">
          {caption}
        </span>
        <select
          className={`${cellCls} border-border`}
          value={opts.value}
          aria-label={opts.path}
          onChange={(e) => opts.onChange(e.target.value)}
        >
          <option value="">{opts.emptyLabel ?? "—"}</option>
          {enumOpts.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </label>
    );
  }

  function renderNeighbors(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.neighbors)[number]>) => {
      const next = s.neighbors.slice();
      next[i] = { ...next[i], ...patch };
      set("neighbors", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.neighbors.map((n, i) =>
            rowShell(
              <>
                {rowInput({ value: n.address, placeholder: "address", width: "w-44 grow", onChange: (v) => updRow(i, { address: v }) })}
                {rowInput({ value: n.remote_asn, placeholder: "remote_asn", numeric: true, width: "w-28", onChange: (v) => updRow(i, { remote_asn: v }) })}
                {rowInput({ value: n.port, placeholder: "port", numeric: true, width: "w-20", onChange: (v) => updRow(i, { port: v }) })}
              </>,
              () => set("neighbors", s.neighbors.filter((_, j) => j !== i)),
              i,
              { basePath: "bgp.neighbors", title: n.address },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() => set("neighbors", [...s.neighbors, { address: "", remote_asn: "", port: "" }])}
          >
            {t.addNeighbor}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderBoundary(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.boundary)[number]>) => {
      const next = s.boundary.slice();
      next[i] = { ...next[i], ...patch };
      set("boundary", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.boundary.map((b, i) =>
            rowShell(
              <>
                {rowInput({ value: b.exporter, placeholder: "exporter", width: "w-40 grow", onChange: (v) => updRow(i, { exporter: v }) })}
                {rowInput({ value: b.external_ifindexes, placeholder: "external_ifindexes", width: "w-44", onChange: (v) => updRow(i, { external_ifindexes: v }) })}
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-[var(--accent)]"
                    checked={b.egress_sampling}
                    onChange={(e) => updRow(i, { egress_sampling: e.target.checked })}
                  />
                  egress_sampling
                </label>
              </>,
              () => set("boundary", s.boundary.filter((_, j) => j !== i)),
              i,
              { basePath: "sampling.boundary", title: b.exporter },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("boundary", [...s.boundary, { exporter: "", external_ifindexes: "", egress_sampling: false }])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderEscalation(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.escalation)[number]>) => {
      const next = s.escalation.slice();
      next[i] = { ...next[i], ...patch };
      set("escalation", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.escalation.map((e, i) =>
            rowShell(
              <>
                {rowInput({ value: e.after_seconds, placeholder: "after_seconds", numeric: true, width: "w-32", onChange: (v) => updRow(i, { after_seconds: v }) })}
                {rowSelect({ value: e.action, path: "escalation.action", width: "w-36", onChange: (v) => updRow(i, { action: v }) })}
              </>,
              () => set("escalation", s.escalation.filter((_, j) => j !== i)),
              i,
              { basePath: "escalation", title: e.action ? `+${e.after_seconds || 0}s → ${e.action}` : "" },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("escalation", [
                ...s.escalation,
                { after_seconds: s.escalation.length === 0 ? "0" : "", action: "" },
              ])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderHostgroups(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.hostgroups)[number]>) => {
      const next = s.hostgroups.slice();
      next[i] = { ...next[i], ...patch };
      set("hostgroups", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-3">
          {s.hostgroups.map((g, i) => (
            <div key={i} className="space-y-2 rounded-md border border-border p-3">
              <div className="flex flex-wrap items-start gap-2">
                {rowInput({ value: g.name, placeholder: "name", width: "w-36", onChange: (v) => updRow(i, { name: v }) })}
                {rowInput({ value: g.networks, placeholder: "networks (CIDR, CIDR…)", width: "w-56 grow", onChange: (v) => updRow(i, { networks: v }) })}
                {rowSelect({ value: g.calculation, path: "hostgroups.calculation", width: "w-28", onChange: (v) => updRow(i, { calculation: v }) })}
                {rowSelect({ value: g.mitigation, path: "hostgroups.mitigation", width: "w-32", onChange: (v) => updRow(i, { mitigation: v }) })}
                {rowInput({ value: g.tenant, placeholder: "tenant", width: "w-28", onChange: (v) => updRow(i, { tenant: v }) })}
                <label className="flex items-center gap-2 py-1.5 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-[var(--accent)]"
                    checked={g.ban}
                    onChange={(e) => updRow(i, { ban: e.target.checked })}
                  />
                  ban
                </label>
                <button
                  type="button"
                  aria-label="remove"
                  className="ml-auto shrink-0 rounded-md border border-border px-3 py-1.5 text-muted-foreground hover:bg-muted"
                  onClick={() => set("hostgroups", s.hostgroups.filter((_, j) => j !== i))}
                >
                  ×
                </button>
              </div>
              <details>
                <summary className="cursor-pointer list-none text-xs text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                  ▸ {labelOf("thresholds")}
                </summary>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {THRESHOLD_KEYS.map((k) => (
                    <input
                      key={k}
                      aria-label={`hostgroups.thresholds.${k}`}
                      className={`${cellCls} border-border`}
                      inputMode="numeric"
                      placeholder={k}
                      value={g.thr[k]}
                      spellCheck={false}
                      onChange={(e) => updRow(i, { thr: { ...g.thr, [k]: e.target.value } })}
                    />
                  ))}
                </div>
              </details>
            </div>
          ))}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("hostgroups", [
                ...s.hostgroups,
                { name: "", networks: "", calculation: "", ban: true, tenant: "", mitigation: "", thr: emptyThresholds() },
              ])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderScrubNodes(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.scrub_nodes)[number]>) => {
      const next = s.scrub_nodes.slice();
      next[i] = { ...next[i], ...patch };
      set("scrub_nodes", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.scrub_nodes.map((n, i) =>
            rowShell(
              <>
                {rowInput({ value: n.name, placeholder: "name", width: "w-28", onChange: (v) => updRow(i, { name: v }) })}
                {rowInput({ value: n.next_hop, placeholder: "next_hop", width: "w-32", onChange: (v) => updRow(i, { next_hop: v }) })}
                {rowInput({ value: n.next_hop6, placeholder: "next_hop6", width: "w-32", onChange: (v) => updRow(i, { next_hop6: v }) })}
                {rowInput({ value: n.capacity_mbps, placeholder: "capacity_mbps", numeric: true, width: "w-32", onChange: (v) => updRow(i, { capacity_mbps: v }) })}
                {rowInput({ value: n.hostgroups, placeholder: "hostgroups", width: "w-36", onChange: (v) => updRow(i, { hostgroups: v }) })}
              </>,
              () => set("scrub_nodes", s.scrub_nodes.filter((_, j) => j !== i)),
              i,
              { basePath: "scrubbing.nodes", title: n.name },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("scrub_nodes", [
                ...s.scrub_nodes,
                { name: "", next_hop: "", next_hop6: "", capacity_mbps: "", hostgroups: "" },
              ])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderRlProfiles(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.dp_profiles)[number]>) => {
      const next = s.dp_profiles.slice();
      next[i] = { ...next[i], ...patch };
      set("dp_profiles", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.dp_profiles.map((p, i) =>
            rowShell(
              <>
                {rowInput({ value: p.name, placeholder: "name", width: "w-36", onChange: (v) => updRow(i, { name: v }) })}
                {rowInput({ value: p.pps, placeholder: "pps", numeric: true, width: "w-28", onChange: (v) => updRow(i, { pps: v }) })}
                {rowInput({ value: p.mbps, placeholder: "mbps", numeric: true, width: "w-28", onChange: (v) => updRow(i, { mbps: v }) })}
              </>,
              () => set("dp_profiles", s.dp_profiles.filter((_, j) => j !== i)),
              i,
              { basePath: "dataplane.ratelimit_profiles", title: p.name },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() => set("dp_profiles", [...s.dp_profiles, { name: "", pps: "", mbps: "" }])}
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderStaticRules(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.dp_rules)[number]>) => {
      const next = s.dp_rules.slice();
      next[i] = { ...next[i], ...patch };
      set("dp_rules", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.dp_rules.map((r, i) =>
            rowShell(
              <>
                {rowInput({ value: r.name, placeholder: "name", width: "w-32", onChange: (v) => updRow(i, { name: v }) })}
                {rowInput({ value: r.src, placeholder: "match.src", width: "w-36", onChange: (v) => updRow(i, { src: v }) })}
                {rowSelect({ value: r.proto, path: "dataplane.static_rules.match.proto", width: "w-24", onChange: (v) => updRow(i, { proto: v }) })}
                {rowInput({ value: r.src_port, placeholder: "src_port", numeric: true, width: "w-24", onChange: (v) => updRow(i, { src_port: v }) })}
                {rowInput({ value: r.dst_port, placeholder: "dst_port", numeric: true, width: "w-24", onChange: (v) => updRow(i, { dst_port: v }) })}
                {rowSelect({ value: r.payload, path: "dataplane.static_rules.match.payload", width: "w-36", onChange: (v) => updRow(i, { payload: v }) })}
                {rowSelect({ value: r.action, path: "dataplane.static_rules.action", width: "w-28", onChange: (v) => updRow(i, { action: v }) })}
                {rowInput({ value: r.profile, placeholder: "profile", width: "w-28", onChange: (v) => updRow(i, { profile: v }) })}
              </>,
              () => set("dp_rules", s.dp_rules.filter((_, j) => j !== i)),
              i,
              { basePath: "dataplane.static_rules", title: r.name },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("dp_rules", [
                ...s.dp_rules,
                { name: "", src: "", proto: "", src_port: "", dst_port: "", payload: "", action: "", profile: "" },
              ])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderApiTokens(f: FieldDef) {
    const updRow = (i: number, patch: Partial<(typeof s.api_tokens)[number]>) => {
      const next = s.api_tokens.slice();
      next[i] = { ...next[i], ...patch };
      set("api_tokens", next);
    };
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={fieldError(f)}>
        <div className="space-y-2">
          {s.api_tokens.map((tk, i) =>
            rowShell(
              <>
                {rowInput({ value: tk.name, placeholder: "name", width: "w-32", onChange: (v) => updRow(i, { name: v }) })}
                {rowInput({ value: tk.token_env, placeholder: "token_env", width: "w-44 grow", onChange: (v) => updRow(i, { token_env: v }) })}
                {rowSelect({ value: tk.role, path: "api.tokens.role", width: "w-28", onChange: (v) => updRow(i, { role: v }) })}
                {rowInput({ value: tk.tenant, placeholder: "tenant", width: "w-28", onChange: (v) => updRow(i, { tenant: v }) })}
              </>,
              () => set("api_tokens", s.api_tokens.filter((_, j) => j !== i)),
              i,
              { basePath: "api.tokens", title: tk.name },
            ),
          )}
          <button
            type="button"
            className={miniBtnCls}
            onClick={() =>
              set("api_tokens", [...s.api_tokens, { name: "", token_env: "", role: "", tenant: "" }])
            }
          >
            {t.addItem}
          </button>
        </div>
      </FieldShell>
    );
  }

  function renderMethod(f: FieldDef) {
    const opts = fieldNode("mitigation")?.enum ?? ["blackhole", "flowspec", "divert", "dataplane"];
    return (
      <FieldShell key={f.path} {...shellProps(f)} error={null}>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {opts.map((o) => (
            <button
              key={o}
              type="button"
              aria-pressed={s.mitigation === o}
              onClick={() => {
                set("mitigation", o);
                setGroupOpen({ flowspec: null, scrubbing: null, dataplane: null });
              }}
              className={`rounded-md border px-3 py-2 text-sm font-medium capitalize transition-colors ${
                s.mitigation === o
                  ? "border-accent bg-accent/10 text-foreground"
                  : "border-border text-muted-foreground hover:bg-muted"
              }`}
            >
              {o}
            </button>
          ))}
        </div>
      </FieldShell>
    );
  }

  function renderField(f: FieldDef): React.ReactNode {
    if (f.showIf && !f.showIf(s)) return null;
    switch (f.kind) {
      case "text":
        return renderText(f);
      case "number":
        return renderNumber(f);
      case "bool":
        return renderBool(f);
      case "select":
        return renderSelect(f);
      case "list":
        return renderList(f);
      case "csv":
        return renderCsv(f);
      case "matrix":
        return renderMatrix(f);
      case "neighbors":
        return renderNeighbors(f);
      case "method":
        return renderMethod(f);
      case "boundary":
        return renderBoundary(f);
      case "escalation":
        return renderEscalation(f);
      case "hostgroups":
        return renderHostgroups(f);
      case "scrubnodes":
        return renderScrubNodes(f);
      case "rlprofiles":
        return renderRlProfiles(f);
      case "staticrules":
        return renderStaticRules(f);
      case "apitokens":
        return renderApiTokens(f);
    }
  }

  function renderFieldList(defs: FieldDef[]) {
    return defs.map((f) => {
      if (filterModified && !fieldModified(f)) return null;
      const node = renderField(f);
      if (node === null) return null;
      return (
        <div
          key={f.path}
          id={`fw-${f.path}`}
          className={
            flashPath === f.path
              ? "rounded-md ring-2 ring-accent ring-offset-2 ring-offset-surface"
              : undefined
          }
        >
          {f.subhead && !filterModified && (
            // group divider: a labelled hairline, so it never competes with the
            // section card's own header strip
            <div className="flex items-center gap-3 pb-1 pt-4">
              <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                {t.subheads[f.subhead]}
              </h3>
              <span aria-hidden className="h-px flex-1 bg-border/70" />
            </div>
          )}
          {node}
        </div>
      );
    });
  }

  function renderMethodGroup(id: "flowspec" | "scrubbing" | "dataplane") {
    const auto = methodAuto[id];
    const open = groupOpen[id] ?? auto;
    const errs = METHOD_FIELDS[id].reduce((n, f) => n + (fieldError(f) ? 1 : 0), 0);
    return (
      <div key={id} className={`rounded-md border ${auto ? "border-accent/50" : "border-border"}`}>
        <button
          type="button"
          aria-expanded={open}
          className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-medium"
          onClick={() => setGroupOpen((p) => ({ ...p, [id]: !open }))}
        >
          <span aria-hidden className={`text-[10px] transition-transform ${open ? "rotate-90" : ""}`}>
            ▶
          </span>
          {t.subheads[id]}
          {auto && <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-accent" />}
          {errs > 0 && <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-red-500" />}
        </button>
        {open && <div className="space-y-5 border-t border-border p-4">{renderFieldList(METHOD_FIELDS[id])}</div>}
      </div>
    );
  }

  function renderSection(id: SectionId) {
    const defs = FIELDS[id];
    // @modified filter: flat list of just the changed fields, section hidden
    // entirely when it holds none.
    if (filterModified) {
      const mod = defs.filter(fieldDeviates);
      const methodMod =
        id === "mitigation"
          ? (Object.keys(METHOD_FIELDS) as Array<keyof typeof METHOD_FIELDS>).flatMap((g) =>
              METHOD_FIELDS[g].filter(fieldDeviates),
            )
          : [];
      if (mod.length + methodMod.length === 0) return null;
      return (
        <section key={id} id={`sec-${id}`} aria-labelledby={`sec-${id}-h`} className="@container/sec scroll-mt-[6.5rem]">
          {sectionCard(id, <div className="divide-y divide-border/60">{renderFieldList([...mod, ...methodMod])}</div>)}
        </section>
      );
    }
    const basic = defs.filter((f) => !f.advanced);
    const advanced = defs.filter((f) => f.advanced);
    const hint = t.advHints[id];
    return (
      <section key={id} id={`sec-${id}`} aria-labelledby={`sec-${id}-h`} className="@container/sec scroll-mt-[6.5rem]">
        {sectionCard(
          id,
          <>
            <div className="divide-y divide-border/60">
              {id === "mitigation" ? (
                <>
                  {renderFieldList([defs[0]])}
                  <div className="space-y-2 py-3">
                    {renderMethodGroup("flowspec")}
                    {renderMethodGroup("scrubbing")}
                    {renderMethodGroup("dataplane")}
                  </div>
                  {renderFieldList(basic.slice(1))}
                </>
              ) : (
                renderFieldList(basic)
              )}
            </div>
            {advanced.length > 0 && (
              <details className="group -mx-5 -mb-4 mt-1 border-t border-border">
                <summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-3 text-[13px] font-medium text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                  <span aria-hidden className="text-[9px] transition-transform group-open:rotate-90">
                    ▶
                  </span>
                  {t.advanced}
                  {hint && (
                    <span className="truncate font-normal text-muted-foreground/70">— {hint}</span>
                  )}
                </summary>
                <div className="divide-y divide-border/60 border-t border-border/60 px-5 pb-1">
                  {renderFieldList(advanced)}
                </div>
              </details>
            )}
          </>,
        )}
      </section>
    );
  }

  // Section card: a real header strip (title + status) over the body, echoing the
  // engine console's card head/body — the floating uppercase mini-label above an
  // unheaded box was one of the things that read as noise.
  function sectionCard(id: SectionId, body: React.ReactNode) {
    const errs = sectionErrors[id];
    return (
      <div className="overflow-hidden rounded-xl border border-border bg-surface">
        <div className="flex items-center gap-3 border-b border-border bg-muted px-5 py-2.5">
          <h2 id={`sec-${id}-h`} className="text-[13px] font-semibold tracking-tight">
            {t.sections[id]}
          </h2>
          {errs > 0 && (
            <span className="rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-500">
              {t.sectionErrs.replace("{n}", String(errs))}
            </span>
          )}
        </div>
        <div className="px-5 pb-4 pt-1">{body}</div>
      </div>
    );
  }

  // ------------------------------------------------------------- YAML pane

  // Line-level tint: keys accented, comments muted. The alignment padding the
  // emitter writes is dropped here — in a 26rem pane it is the difference
  // between a line that fits and a line that looks chopped off.
  function renderYamlLine(ln: string) {
    if (ln === "") return " ";
    const [rawCode, comment] = splitComment(ln);
    const code = rawCode.replace(/\s+$/, "");
    const m = code.match(/^(\s*(?:- )?)([A-Za-z0-9_]+)(:)(.*)$/);
    return (
      <>
        {m ? (
          <>
            {m[1]}
            <span className="text-accent">{m[2]}</span>
            {m[3]}
            {m[4]}
          </>
        ) : (
          code
        )}
        {comment && <span className="text-muted-foreground/60">{(code ? "  " : "") + comment}</span>}
      </>
    );
  }

  const verdict = (() => {
    if (engineReady === false)
      return { tone: "muted" as const, text: t.engineOff, section: null };
    if (engineReady === null || !engineResult)
      return { tone: "muted" as const, text: t.engineChecking, section: null };
    if (engineResult.ok)
      return {
        tone: "ok" as const,
        text: t.accepts,
        summary: engineResult.summary,
        section: null,
      };
    return {
      tone: "err" as const,
      text: engineResult.error ?? "",
      section: guessErrorSection(engineResult.error),
    };
  })();

  // The verdict sits ABOVE the code: it is a statement about the file below it.
  const verdictStrip = (
    <div
      className={`border-b px-3 py-2 text-[12px] ${
        verdict.tone === "ok"
          ? "border-emerald-500/30 bg-emerald-500/10"
          : verdict.tone === "err"
            ? "border-red-500/30 bg-red-500/10"
            : "border-border"
      }`}
      role="status"
      aria-live="polite"
    >
      {verdict.tone === "ok" ? (
        verdict.summary ? (
          <details>
            <summary className="cursor-pointer font-medium text-emerald-600 dark:text-emerald-400">
              ✓ {verdict.text}{" "}
              <span className="font-normal text-muted-foreground">· {t.engineSummary}</span>
            </summary>
            <pre className="mt-2 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-muted-foreground">
              {verdict.summary}
            </pre>
          </details>
        ) : (
          <p className="font-medium text-emerald-600 dark:text-emerald-400">✓ {verdict.text}</p>
        )
      ) : verdict.tone === "err" ? (
        verdict.section ? (
          <button
            type="button"
            onClick={() => scrollToSection(verdict.section as SectionId)}
            className="w-full text-left font-medium text-red-500 hover:underline"
          >
            ✗ {verdict.text}
          </button>
        ) : (
          <p className="font-medium text-red-500">✗ {verdict.text}</p>
        )
      ) : (
        <p className="text-muted-foreground">{verdict.text}</p>
      )}
    </div>
  );

  const yamlPane = (
    <div id="yaml-pane" className="scroll-mt-[6.5rem]">
      <div className="overflow-hidden rounded-xl border border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border bg-muted px-3 py-2">
          <span className="font-mono text-[12px] font-semibold text-muted-foreground">{t.output}</span>
          <button
            type="button"
            onClick={copy}
            className="ml-auto h-7 rounded-md border border-border px-2.5 text-[12px] font-medium hover:bg-muted"
          >
            {copied ? t.copied : t.copy}
          </button>
          <button
            type="button"
            onClick={download}
            className="h-7 rounded-md bg-accent px-2.5 text-[12px] font-medium text-accent-foreground hover:opacity-90"
          >
            {t.download}
          </button>
          {wideLayout && (
            <button
              type="button"
              onClick={() => toggleDock(false)}
              title={t.yamlHide}
              aria-label={t.yamlHide}
              className="grid h-7 w-7 place-items-center rounded-md text-muted-foreground hover:bg-muted"
            >
              »
            </button>
          )}
        </div>
        {verdictStrip}
        <pre className="max-h-[50vh] overflow-auto px-3 py-3 font-mono text-[12px] leading-[1.6] min-[1440px]:max-h-[calc(100vh-18rem)]">
          {yamlLines.map((ln, i) => (
            <span
              key={i}
              className={`-mx-1 block whitespace-pre-wrap break-words rounded-sm px-1 pl-[calc(0.25rem+2ch)] [text-indent:-2ch] transition-colors duration-700 ${
                hotLines.has(i) ? "bg-accent/20 duration-0" : ""
              }`}
            >
              {renderYamlLine(ln)}
            </span>
          ))}
        </pre>

      {/* deploy runbook: needed after the file is written, so it starts folded —
          and it lives in the same card, so the pane is one object, not a stack */}
      <details className="group/rb border-t border-border">
        <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-[12px] font-medium text-muted-foreground hover:bg-muted/40 hover:text-foreground [&::-webkit-details-marker]:hidden">
          <span aria-hidden className="text-[9px] transition-transform group-open/rb:rotate-90">
            ▶
          </span>
          {t.runbook.title}
        </summary>
        <ol className="space-y-3 border-t border-border px-3 py-3">
          {[
            { text: t.runbook.save, cmd: "sudo install -m 0644 config.yaml /etc/kapkan/config.yaml" },
            { text: t.runbook.check, cmd: "kapkan -check-config /etc/kapkan/config.yaml" },
            ...(methodAuto.dataplane
              ? [
                  {
                    text: t.runbook.dataplane,
                    cmd: "sudo install -D -m 0644 /usr/share/kapkan/kapkan-dataplane.conf /etc/systemd/system/kapkan.service.d/10-dataplane.conf && sudo systemctl daemon-reload",
                  },
                ]
              : []),
            {
              text: t.runbook.apply,
              cmd: methodAuto.dataplane ? "sudo systemctl restart kapkan" : "sudo systemctl reload kapkan",
            },
            s.dry_run
              ? { text: t.runbook.watch, cmd: "journalctl -u kapkan -f" }
              : { text: t.runbook.live, cmd: undefined },
          ].map((step, i) => (
            <li key={i} className="text-xs">
              <p className={step.cmd ? "text-muted-foreground" : "font-medium text-red-500"}>
                {i + 1}. {step.text}
              </p>
              {step.cmd && (
                <div className="mt-1 flex items-center gap-2">
                  <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-muted px-2 py-1 font-mono text-[11px]">
                    {step.cmd}
                  </code>
                  <button
                    type="button"
                    onClick={() => copyCmd(step.cmd as string)}
                    className="shrink-0 rounded-md border border-border px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-muted"
                  >
                    {copiedCmd === step.cmd ? t.copied : t.copy}
                  </button>
                </div>
              )}
            </li>
          ))}
        </ol>
      </details>
      </div>
    </div>
  );

  // ------------------------------------------------------------------ shell

  const dot = (id: SectionId) => (
    <span
      aria-hidden
      className={`h-1.5 w-1.5 shrink-0 rounded-full ${
        sectionErrors[id] > 0 ? "bg-red-500" : "bg-emerald-500/70"
      }`}
    />
  );

  return (
    <div
      className={
        wideLayout ? "" : dockOpen ? "pb-[calc(45vh+3rem)]" : "pb-14"
      }
    >
      {/* Mode + tools. Two rows of a FIXED height at lg+: every sticky offset and
          the scrollspy rootMargin encode this bar's 97px, so the live-mode warning
          reuses row 1's descriptive slot instead of adding a third row. */}
      <div
        className={`z-30 -mx-6 border-b bg-background/90 px-6 backdrop-blur lg:sticky lg:top-0 lg:-mx-8 lg:px-8 ${
          s.dry_run ? "border-border" : "border-b-2 border-red-500/60"
        }`}
      >
        <div className="flex min-h-12 flex-wrap items-center gap-x-3 gap-y-2 py-2 lg:h-12 lg:py-0">
          <span
            className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${
              s.dry_run
                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                : "bg-red-500/10 text-red-500"
            }`}
          >
            <span
              aria-hidden
              className={`h-2 w-2 rounded-full ${s.dry_run ? "bg-emerald-500" : "bg-red-500"}`}
            />
            {s.dry_run ? t.modeWatch : t.modeLive}
          </span>

          <button
            type="button"
            role="switch"
            aria-checked={!s.dry_run}
            aria-label={t.modeLive}
            onClick={() => set("dry_run", !s.dry_run)}
            className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${
              s.dry_run ? "bg-muted" : "bg-red-500"
            }`}
          >
            <span
              aria-hidden
              className={`absolute top-0.5 h-5 w-5 rounded-full bg-background shadow transition-[left] ${
                s.dry_run ? "left-0.5" : "left-[22px]"
              } border border-border`}
            />
          </button>

          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
            dry_run: {String(s.dry_run)}
          </code>

          <span
            className={`hidden min-w-0 flex-1 truncate text-xs md:inline ${
              s.dry_run ? "text-muted-foreground" : "font-medium text-red-500"
            }`}
          >
            {s.dry_run ? t.modeWatchDesc : t.liveWarning}
          </span>

          {totalErrors > 0 && firstErrorSection && (
            <button
              type="button"
              onClick={() => scrollToSection(firstErrorSection)}
              className="ml-auto rounded-full bg-red-500/10 px-3 py-1 text-xs font-medium text-red-500 hover:bg-red-500/20"
            >
              {t.fieldErrors.replace("{n}", String(totalErrors))}
            </button>
          )}
        </div>

        {/* Toolbar in three zones: find · view · source. Eight identical pills in
            one row is what made this read as a browser extension bar. */}
        <div className="flex min-h-12 flex-wrap items-center gap-x-3 gap-y-2 border-t border-border/60 py-2 lg:h-12 lg:py-0">
          <div className="relative w-full max-w-[20rem] flex-1">
            <input
              value={searchQ}
              placeholder={t.search.placeholder}
              spellCheck={false}
              onChange={(e) => setSearchQ(e.target.value)}
              onFocus={() => {
                if (blurTimer.current) clearTimeout(blurTimer.current);
                setSearchFocus(true);
              }}
              onBlur={() => {
                blurTimer.current = setTimeout(() => setSearchFocus(false), 150);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && searchResults[0]) jumpToField(searchResults[0]);
                if (e.key === "Escape") {
                  setSearchQ("");
                  (e.target as HTMLInputElement).blur();
                }
              }}
              className="h-8 w-full rounded-md border border-border bg-background pl-8 pr-2.5 text-[13px] outline-none transition-colors focus:border-accent focus:ring-2 focus:ring-accent/20"
            />
            <svg
              aria-hidden
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/70"
            >
              <circle cx="11" cy="11" r="7" />
              <path d="m20 20-3.5-3.5" />
            </svg>
            {searchFocus && searchQ.trim() !== "" && (
              <div className="absolute z-40 mt-1 max-h-72 w-full min-w-[260px] overflow-auto rounded-md border border-border bg-surface shadow-lg">
                {searchResults.length === 0 ? (
                  <p className="px-3 py-2 text-xs text-muted-foreground">{t.search.empty}</p>
                ) : (
                  searchResults.map((r) => (
                    <button
                      key={r.f.path}
                      type="button"
                      onMouseDown={(e) => {
                        e.preventDefault();
                        jumpToField(r);
                      }}
                      className="flex w-full items-baseline justify-between gap-3 px-3 py-1.5 text-left text-sm hover:bg-muted"
                    >
                      <span className="truncate">{labelOf(r.f.path)}</span>
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                        {t.sections[r.section]} · {r.f.path}
                      </span>
                    </button>
                  ))
                )}
              </div>
            )}
          </div>

          {/* zone B — view toggles look like toggles, not like more buttons */}
          <button
            type="button"
            role="switch"
            aria-checked={showHelp}
            onClick={toggleHelp}
            className="flex shrink-0 items-center gap-2 text-[12px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <span
              aria-hidden
              className={`relative h-4 w-7 rounded-full border transition-colors ${
                showHelp ? "border-accent bg-accent" : "border-border bg-muted"
              }`}
            >
              <span
                className={`absolute top-0.5 h-2.5 w-2.5 rounded-full bg-background transition-[left] ${
                  showHelp ? "left-[14px]" : "left-0.5"
                }`}
              />
            </span>
            {t.helpToggle}
          </button>
          {shownModified > 0 && (
            <button
              type="button"
              aria-pressed={filterModified}
              onClick={() => setFilterModifiedOn(!filterModified)}
              className={`h-8 shrink-0 rounded-md border px-2.5 text-[12px] transition-colors ${
                filterModified
                  ? "border-accent bg-accent/10 text-foreground"
                  : "border-border text-muted-foreground hover:bg-muted"
              }`}
            >
              {t.modifiedChip.replace("{n}", String(shownModified))}
            </button>
          )}
          {/* zone C — source of the config: a preset menu (its descriptions are
              visible here instead of hiding in a title) then the file actions */}
          <div className="relative ml-auto shrink-0">
            <button
              type="button"
              aria-haspopup="menu"
              aria-expanded={presetsOpen}
              onClick={() => setPresetsOpen((v) => !v)}
              onBlur={() => setTimeout(() => setPresetsOpen(false), 150)}
              className="h-8 rounded-md border border-border px-3 text-[12px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              {t.presetLabel} ▾
            </button>
            {presetsOpen && (
              <div
                role="menu"
                className="absolute right-0 z-40 mt-1 w-72 rounded-lg border border-border bg-surface p-1 shadow-lg"
              >
                {PRESETS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    role="menuitem"
                    onMouseDown={(e) => {
                      e.preventDefault();
                      setPresetsOpen(false);
                      applyPreset(p.diff);
                    }}
                    className="block w-full rounded-md px-3 py-2 text-left transition-colors hover:bg-muted"
                  >
                    <span className="block text-sm font-medium">{t.presets[p.id].name}</span>
                    <span className="mt-0.5 block text-xs text-muted-foreground">
                      {t.presets[p.id].desc}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <span aria-hidden className="hidden h-5 w-px bg-border md:block" />

          {/* file actions: quieter than the view toggles above */}
          <div className="flex shrink-0 items-center gap-3 text-[12px]">
            <button
              type="button"
              onClick={() => {
                setImportOpen((v) => !v);
                setImportDiag(null);
              }}
              className="text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t.importer.btn}
            </button>
            <button
              type="button"
              onClick={shareLink}
              className="text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {shared ? t.share.copied : t.share.btn}
            </button>
            <button
              type="button"
              onClick={resetAll}
              className="text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t.reset.btn}
            </button>
          </div>
        </div>
      </div>

      {importOpen && (
        <div className="mt-4 rounded-lg border border-border bg-surface p-4">
          <p className="text-xs text-muted-foreground">{t.importer.hint}</p>
          <textarea
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            spellCheck={false}
            rows={8}
            placeholder={"dry_run: true\nnetworks:\n  - \"203.0.113.0/24\"\n…"}
            className="mt-2 w-full rounded-md border border-border bg-background p-3 font-mono text-xs outline-none transition-colors focus:border-accent"
          />
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={doImport}
              className="rounded-md bg-accent px-3 py-1 text-xs font-medium text-accent-foreground hover:opacity-90"
            >
              {t.importer.apply}
            </button>
            <button
              type="button"
              onClick={() => {
                setImportOpen(false);
                setImportDiag(null);
              }}
              className="rounded-md border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-muted"
            >
              {t.importer.cancel}
            </button>
          </div>
          {importDiag?.error && (
            <p className="mt-2 text-xs text-red-500">{t.importer.bad.replace("{err}", importDiag.error)}</p>
          )}
          {importDiag && !importDiag.error && (
            <div className="mt-2 text-xs">
              <p className="font-medium text-emerald-600 dark:text-emerald-400">{t.importer.ok}</p>
              {importDiag.lost.length > 0 && (
                <>
                  <p className="mt-1 font-medium text-amber-600 dark:text-amber-400">{t.importer.lost}</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {importDiag.lost.map((p) => (
                      <code key={p} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                        {p}
                      </code>
                    ))}
                  </div>
                  <p className="mt-1 text-muted-foreground">{t.importer.lostNote}</p>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* Three regimes. The old 200/1fr/540 split inside a 1280px container left the
          form 428px — and it stayed 428px however wide the monitor got. Below 1440
          the YAML lives in a bottom dock so the form owns the width; from 1440 it
          takes a third column that the operator can collapse to a strip. */}
      {/* All three regimes use the same variant FORM (min-[…]) on purpose: mixing
          `lg:` with an arbitrary min-width makes the named breakpoint win at
          1440+ regardless of order, and the YAML column silently wraps away. */}
      <div
        className={`mt-6 min-[1024px]:grid min-[1024px]:grid-cols-[13rem_minmax(0,1fr)] min-[1024px]:items-start min-[1024px]:gap-8 ${
          dockOpen
            ? "min-[1440px]:grid-cols-[13rem_minmax(0,1fr)_26rem] min-[1600px]:grid-cols-[13rem_minmax(0,1fr)_30rem]"
            : "min-[1440px]:grid-cols-[13rem_minmax(0,1fr)_2.5rem]"
        }`}
      >
        {/* section rail */}
        <nav aria-label={t.nav} className="min-[1024px]:sticky min-[1024px]:top-[6.5rem] min-[1024px]:self-start">
          {/* mobile: horizontal chips */}
          <div className="-mx-6 flex gap-2 overflow-x-auto px-6 pb-3 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden lg:hidden">
            {SECTION_IDS.map((id) => (
              <button
                key={id}
                type="button"
                onClick={() => scrollToSection(id)}
                className={`flex shrink-0 items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${
                  active === id
                    ? "border-accent text-foreground"
                    : "border-border text-muted-foreground"
                }`}
              >
                {t.sections[id]}
                {dot(id)}
              </button>
            ))}
          </div>
          {/* desktop: vertical list on a spine. No green dots — absence of red
              is the signal; a column of seven ticks is decoration. */}
          <ul className="hidden border-l border-border lg:block">
            {SECTION_IDS.map((id) => (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => scrollToSection(id)}
                  aria-current={active === id ? "true" : undefined}
                  className={`-ml-px flex w-full items-center gap-2 border-l-2 py-2 pl-3 pr-2 text-left text-[13px] transition-colors ${
                    active === id
                      ? "rounded-r-md border-accent bg-accent/5 font-medium text-foreground"
                      : "border-transparent text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                  }`}
                >
                  <span className="min-w-0 flex-1 truncate">{t.sections[id]}</span>
                  {sectionErrors[id] > 0 ? (
                    <span aria-hidden className="h-1.5 w-1.5 shrink-0 rounded-full bg-red-500" />
                  ) : sectionModified[id] > 0 ? (
                    <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground/70">
                      {sectionModified[id]}
                    </span>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* form column */}
        <div className="min-w-0 space-y-6">{SECTION_IDS.map(renderSection)}</div>

        {/* YAML column — only from 1440px; below that it lives in the dock */}
        {wideLayout && dockOpen ? (
          <aside className="min-w-0 min-[1440px]:sticky min-[1440px]:top-[6.5rem] min-[1440px]:self-start">
            {yamlPane}
          </aside>
        ) : wideLayout ? (
          <aside className="min-[1440px]:sticky min-[1440px]:top-[6.5rem] min-[1440px]:self-start">
            <button
              type="button"
              onClick={() => toggleDock(true)}
              title={t.yamlShow}
              aria-label={t.yamlShow}
              className="flex h-48 w-10 flex-col items-center justify-between rounded-xl border border-border bg-surface py-3 text-muted-foreground transition-colors hover:text-foreground"
            >
              <span aria-hidden className="text-xs">
                «
              </span>
              <span className="rotate-180 font-mono text-[11px] tracking-wide [writing-mode:vertical-rl]">
                config.yaml
              </span>
              <span
                aria-hidden
                className={`h-2 w-2 rounded-full ${
                  verdict.tone === "ok"
                    ? "bg-emerald-500"
                    : verdict.tone === "err"
                      ? "bg-red-500"
                      : "bg-border"
                }`}
              />
            </button>
          </aside>
        ) : null}
      </div>

      {/* Below 1440 the YAML is a bottom dock whose collapsed state IS the status
          bar — one status surface instead of a stack of strips. */}
      {!wideLayout && (
      <div className="fixed inset-x-0 bottom-0 z-40 border-t border-border bg-background/95 shadow-[0_-6px_16px_-8px_rgba(0,0,0,0.35)] backdrop-blur">
        <button
          type="button"
          aria-expanded={dockOpen}
          aria-controls="yaml-dock-body"
          onClick={() => toggleDock(!dockOpen)}
          className="flex h-11 w-full items-center gap-2.5 px-4 text-left transition-colors hover:bg-muted/40"
        >
          <span
            aria-hidden
            className={`h-2 w-2 shrink-0 rounded-full ${
              verdict.tone === "ok"
                ? "bg-emerald-500"
                : verdict.tone === "err"
                  ? "bg-red-500"
                  : "bg-muted-foreground/50"
            }`}
          />
          <span
            className={`min-w-0 flex-1 truncate text-[12px] font-medium ${
              verdict.tone === "ok"
                ? "text-emerald-600 dark:text-emerald-400"
                : verdict.tone === "err"
                  ? "text-red-500"
                  : "text-muted-foreground"
            }`}
          >
            {verdict.text}
          </span>
          <code className="hidden shrink-0 font-mono text-[11px] text-muted-foreground sm:inline">
            config.yaml
          </code>
          {/* Reads as a button but stays a span — the whole bar is already the <button>. */}
          <span className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12px] font-medium">
            <span
              aria-hidden
              className={`text-[9px] transition-transform ${dockOpen ? "" : "rotate-180"}`}
            >
              ▾
            </span>
            {dockOpen ? t.yamlHide : t.yamlJump}
          </span>
        </button>
        {dockOpen && (
          <div id="yaml-dock-body" className="max-h-[45vh] overflow-auto border-t border-border px-4 py-3">
            {yamlPane}
          </div>
        )}
      </div>
      )}
    </div>
  );
}
