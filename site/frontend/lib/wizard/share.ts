// Persistence + share-by-URL for the config builder. Both are stored as a
// DIFF against initialState (not the full state): saves stay tiny, share URLs
// stay short, and fields added in later versions simply keep their defaults
// when an old diff is applied. Secrets are structurally absent — the state
// only ever holds environment-variable NAMES.

import {
  emptyThresholds,
  initialState,
  type ThresholdSet,
  type WizardState,
} from "./emit";

export type StateDiff = Partial<Record<keyof WizardState, unknown>>;

const STORAGE_KEY = "kapkan-config-builder";
const VERSION = 3; // bump when the state shape changes incompatibly

// Row templates: imported/saved row objects are normalized over these so a
// missing or mistyped cell can never crash a renderer.
const ROW_TEMPLATES: Partial<Record<keyof WizardState, Record<string, unknown>>> = {
  neighbors: { address: "", remote_asn: "", port: "" },
  boundary: { exporter: "", external_ifindexes: "", egress_sampling: false },
  escalation: { after_seconds: "", action: "" },
  hostgroups: {
    name: "",
    networks: "",
    calculation: "",
    ban: true,
    tenant: "",
    mitigation: "",
    thr: emptyThresholds(),
  },
  scrub_nodes: { name: "", next_hop: "", next_hop6: "", capacity_mbps: "", hostgroups: "" },
  dp_profiles: { name: "", pps: "", mbps: "" },
  dp_rules: { name: "", src: "", proto: "", src_port: "", dst_port: "", payload: "", action: "", profile: "" },
  api_tokens: { name: "", token_env: "", role: "", tenant: "", node: "" },
};

export function buildDiff(s: WizardState): StateDiff {
  const diff: StateDiff = {};
  for (const k of Object.keys(initialState) as Array<keyof WizardState>) {
    if (JSON.stringify(s[k]) !== JSON.stringify(initialState[k])) diff[k] = s[k];
  }
  return diff;
}

function sanitizeThr(v: unknown): ThresholdSet {
  const out = emptyThresholds();
  if (v && typeof v === "object") {
    for (const k of Object.keys(out) as Array<keyof ThresholdSet>) {
      const raw = (v as Record<string, unknown>)[k];
      if (typeof raw === "string") out[k] = raw;
      else if (typeof raw === "number") out[k] = String(raw);
    }
  }
  return out;
}

function sanitizeRow(tpl: Record<string, unknown>, v: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = { ...tpl, ...(tpl.thr ? { thr: emptyThresholds() } : {}) };
  if (!v || typeof v !== "object") return out;
  const row = v as Record<string, unknown>;
  for (const key of Object.keys(tpl)) {
    const t = tpl[key];
    const raw = row[key];
    if (key === "thr") out.thr = sanitizeThr(raw);
    else if (typeof t === "string" && typeof raw === "string") out[key] = raw;
    else if (typeof t === "string" && typeof raw === "number") out[key] = String(raw);
    else if (typeof t === "boolean" && typeof raw === "boolean") out[key] = raw;
  }
  return out;
}

// applyDiff builds a full, type-safe state from initialState + a diff of
// unknown provenance (URL, storage, preset). Anything mistyped is dropped.
export function applyDiff(diff: StateDiff): WizardState {
  const out: WizardState = JSON.parse(JSON.stringify(initialState));
  for (const k of Object.keys(initialState) as Array<keyof WizardState>) {
    if (!(k in diff)) continue;
    const v = diff[k];
    const init = initialState[k];
    if (typeof init === "string" && typeof v === "string") {
      (out as Record<string, unknown>)[k] = v;
    } else if (typeof init === "boolean" && typeof v === "boolean") {
      (out as Record<string, unknown>)[k] = v;
    } else if (Array.isArray(init) && Array.isArray(v)) {
      const tpl = ROW_TEMPLATES[k];
      (out as Record<string, unknown>)[k] = tpl
        ? v.map((item) => sanitizeRow(tpl, item))
        : v.filter((x): x is string => typeof x === "string");
    } else if (init && typeof init === "object" && !Array.isArray(init)) {
      (out as Record<string, unknown>)[k] = sanitizeThr(v);
    }
  }
  return out;
}

// --- base64url encoding of a diff (for #s= share links) ---

export function encodeDiff(diff: StateDiff): string {
  const json = JSON.stringify(diff);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeShare(encoded: string): StateDiff | null {
  try {
    const b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return parsed && typeof parsed === "object" ? (parsed as StateDiff) : null;
  } catch {
    return null;
  }
}

// --- localStorage autosave ---

export function saveLocal(diff: StateDiff): void {
  try {
    if (Object.keys(diff).length === 0) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, JSON.stringify({ v: VERSION, d: diff }));
  } catch {
    /* storage full/blocked — autosave is best-effort */
  }
}

export function loadLocal(): StateDiff | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.v !== VERSION || typeof parsed.d !== "object") return null;
    return parsed.d as StateDiff;
  } catch {
    return null;
  }
}

export function clearLocal(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}
