// Site-wide constants. Kept in one place so branding/links are easy to swap
// when the landing-page design handoff lands.
export const site = {
  name: "Kapkan",
  tagline: "Free, open-source DDoS detection & RTBH mitigation",
  // Public GitHub repository. The Go module path is github.com/kapkan-io/kapkan
  // (see go.mod), but the repo is published under fornex/kapkan — keep this in
  // sync with the actual repository URL.
  repo: "https://github.com/fornex/kapkan",
} as const;
