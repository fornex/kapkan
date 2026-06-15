// Site-wide constants. Kept in one place so branding/links are easy to swap
// when the landing-page design handoff lands.
export const site = {
  name: "Kapkan",
  tagline: "Free, open-source DDoS detection & RTBH mitigation",
  // Derived from the Go module path (github.com/kapkan-io/kapkan). Update if
  // the canonical repo URL differs.
  repo: "https://github.com/kapkan-io/kapkan",
} as const;
