// Client-side field validation. Rules are pulled from the engine-generated
// schema (enum / minimum / maximum / pattern) wherever the engine expresses
// them declaratively, and from the overlay's `format` hint for the fields the
// engine validates imperatively with net/netip (IP / CIDR / host:port /
// community), which therefore carry no regex in the schema. Messages are
// localized — the caller passes its locale's WizardValidation strings. This
// catches the common mistakes inline; cross-field rules (CIDR overlap, prefix
// containment, monotonic ladders) are deferred to the wasm engine validator and
// to `kapkan -check-config`.

import { fieldNode, fieldMeta } from "./schema";
import type { WizardValidation } from "./strings";

function isIPv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIPv6(s: string): boolean {
  if (!s.includes(":")) return false;
  if ((s.match(/::/g) ?? []).length > 1) return false;
  const body = s.split("%")[0]; // strip zone id
  return /^[0-9a-fA-F:]+$/.test(body) && body.split(":").every((g) => g === "" || /^[0-9a-fA-F]{1,4}$/.test(g));
}

function isIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

function isCIDR(s: string): boolean {
  const slash = s.lastIndexOf("/");
  if (slash < 0) return false;
  const addr = s.slice(0, slash);
  const bits = Number(s.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0) return false;
  if (isIPv4(addr)) return bits <= 32;
  if (isIPv6(addr)) return bits <= 128;
  return false;
}

function isHostPort(s: string): boolean {
  const colon = s.lastIndexOf(":");
  if (colon < 0) return false;
  const port = Number(s.slice(colon + 1));
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isCommunity(s: string): boolean {
  const m = s.match(/^(\d{1,5}):(\d{1,5})$/);
  if (!m) return false;
  return Number(m[1]) <= 65535 && Number(m[2]) <= 65535;
}

function formatOK(format: string, v: string): boolean {
  switch (format) {
    case "ipv4":
      return isIPv4(v);
    case "ipv6":
      return isIPv6(v);
    case "ip":
      return isIP(v);
    case "cidr":
      return isCIDR(v);
    case "hostport":
      return isHostPort(v);
    case "community":
      return isCommunity(v);
    case "url":
      return /^https?:\/\/.+/.test(v);
    default:
      return true; // path and unknown formats are validated server-side
  }
}

// validateString returns a localized error for a string value at `path`, or null
// if it is acceptable. Empty strings are treated as "unset" and pass; callers
// enforce required-ness separately.
export function validateString(path: string, value: string, v: WizardValidation): string | null {
  const s = value.trim();
  if (s === "") return null;

  const node = fieldNode(path);
  if (node?.enum && !node.enum.includes(s)) {
    return v.enum.replace("{allowed}", node.enum.join(", "));
  }
  if (node?.pattern && !new RegExp(node.pattern).test(s)) {
    return v.identifier;
  }
  const fmt = fieldMeta(path).format;
  if (fmt && !formatOK(fmt, s)) {
    return v.formats[fmt] ?? v.identifier;
  }
  return null;
}

// validateNumber checks the schema's numeric bounds for `path`.
export function validateNumber(path: string, value: number, v: WizardValidation): string | null {
  if (Number.isNaN(value)) return v.notNumber;
  const node = fieldNode(path);
  if (node?.minimum !== undefined && value < node.minimum) {
    return v.min.replace("{min}", String(node.minimum));
  }
  if (node?.maximum !== undefined && value > node.maximum) {
    return v.max.replace("{max}", String(node.maximum));
  }
  return null;
}
