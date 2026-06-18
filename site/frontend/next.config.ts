import type { NextConfig } from "next";
import createMDX from "@next/mdx";

const nextConfig: NextConfig = {
  // Ship a fully static site: `next build` emits `out/` with one HTML file per
  // route. No Node runtime needed — nginx serves the files directly.
  output: "export",
  // Emit `route/index.html` (not `route.html`) so the host's default
  // `try_files $uri $uri/ =404` resolves clean URLs without extra rewrites.
  trailingSlash: true,
  // Let .md / .mdx files act as pages alongside the usual extensions.
  pageExtensions: ["ts", "tsx", "js", "jsx", "md", "mdx"],
};

// Plugins are passed by string name so they keep working under Turbopack
// (Next 16's default), which cannot receive JS function references.
const withMDX = createMDX({
  options: {
    remarkPlugins: ["remark-gfm"],
    rehypePlugins: ["rehype-slug"],
  },
});

export default withMDX(nextConfig);
