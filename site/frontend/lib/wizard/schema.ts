// Wizard data layer. Reads the engine-generated config schema and the
// hand-maintained overlay (both copied into content/docs from the monorepo
// docs/ by copy-docs.mjs at predev/prebuild). The schema is the source of truth
// for field types, enums, numeric bounds and regex patterns; the overlay adds
// tiers, help, value-format hints and behavioural flags. Keeping validation
// rules sourced from the schema is what keeps the wizard from drifting away
// from the engine — the engine's own `kapkan -check-config` is the final word.

import schemaJson from "@/content/docs/config-schema.json";
import overlayJson from "@/content/docs/config-schema-overlay.json";

export type SchemaNode = {
  type?: string;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  pattern?: string;
  properties?: Record<string, SchemaNode>;
  items?: SchemaNode;
  "x-optional"?: boolean;
};

export type OverlayField = {
  tier?: "basic" | "advanced";
  description?: string;
  format?: string; // ipv4 | ipv6 | ip | cidr | hostport | community | url | path
  secret?: boolean;
  defaultWhenAbsent?: unknown;
  reloadImmutable?: boolean;
  serverVerified?: boolean;
  crossField?: string;
};

const schema = schemaJson as unknown as SchemaNode;
const overlay = (overlayJson as { fields?: Record<string, OverlayField> }).fields ?? {};

// fieldNode walks the schema along a dotted path, transparently descending
// through array `items`, and returns the leaf node (the element node for a
// list path, which is what per-entry validation needs).
export function fieldNode(path: string): SchemaNode | undefined {
  let cur: SchemaNode | undefined = schema;
  for (const seg of path.split(".")) {
    const props: SchemaNode["properties"] = cur?.properties;
    if (!props || !props[seg]) return undefined;
    cur = props[seg];
    if (cur.items) cur = cur.items;
  }
  return cur;
}

export function fieldMeta(path: string): OverlayField {
  return overlay[path] ?? {};
}
