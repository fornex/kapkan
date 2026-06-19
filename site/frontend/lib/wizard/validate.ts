// Client-side field validation. Rules are pulled from the engine-generated
// schema (enum / minimum / maximum / pattern) wherever the engine expresses
// them declaratively, and from the overlay's `format` hint for the fields the
// engine validates imperatively with net/netip (IP / CIDR / host:port /
// community), which therefore carry no regex in the schema. This catches the
// common mistakes inline; cross-field rules (CIDR overlap, prefix containment,
// monotonic ladders) are deferred to `kapkan -check-config`, by design.

import { fieldNode, fieldMeta } from "./schema";

function isIPv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIPv6(s: string): boolean {
  if (!s.includes(":")) return false;
  // Permissive: hex groups separated by ":", at most one "::". Good enough for
  // inline feedback; the engine's netip parse is authoritative.
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

const formatLabel: Record<string, string> = {
  ipv4: "an IPv4 address (e.g. 192.0.2.1)",
  ipv6: "an IPv6 address (e.g. 2001:db8::1)",
  ip: "an IP address",
  cidr: "a CIDR prefix (e.g. 203.0.113.0/24)",
  hostport: "host:port (e.g. :6343 or 127.0.0.1:8080)",
  community: "a BGP community ASN:value (e.g. 65000:666)",
  url: "an http(s) URL",
};

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

// validateString returns an error message for a string value at `path`, or null
// if it is acceptable. Empty strings are treated as "unset" and pass (the emit
// layer omits empties); callers enforce required-ness separately.
export function validateString(path: string, value: string): string | null {
  const v = value.trim();
  if (v === "") return null;

  const node = fieldNode(path);
  if (node?.enum && !node.enum.includes(v)) {
    return `must be one of: ${node.enum.join(", ")}`;
  }
  if (node?.pattern && !new RegExp(node.pattern).test(v)) {
    // The only patterns the engine ships are identifier-style (env var names,
    // db/group names); a generic message reads better than the raw regex.
    return `invalid value (allowed: letters, digits, "_", "-", "." per the engine rule)`;
  }
  const fmt = fieldMeta(path).format;
  if (fmt && !formatOK(fmt, v)) {
    return `must be ${formatLabel[fmt] ?? fmt}`;
  }
  return null;
}

// validateNumber checks the schema's numeric bounds for `path`.
export function validateNumber(path: string, value: number): string | null {
  if (Number.isNaN(value)) return "must be a number";
  const node = fieldNode(path);
  if (node?.minimum !== undefined && value < node.minimum) return `must be ≥ ${node.minimum}`;
  if (node?.maximum !== undefined && value > node.maximum) return `must be ≤ ${node.maximum}`;
  return null;
}
