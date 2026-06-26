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
// (Next 16's default), which cannot receive JS function references. Options
// must be JSON-serializable for the same reason — no functions, so the
// autolink `content` is given as a literal hast node, not a builder fn.
const withMDX = createMDX({
  options: {
    remarkPlugins: ["remark-gfm"],
    rehypePlugins: [
      // Adds an `id` to every heading (slugified from its text).
      "rehype-slug",
      // Appends a copyable "#" link to each heading so readers can grab a
      // deep link to any section. Runs after rehype-slug — it links to the
      // id that plugin produced. The "#" is hidden until the heading is
      // hovered/focused (styled via `.heading-anchor` in globals.css).
      [
        "rehype-autolink-headings",
        {
          behavior: "append",
          properties: {
            className: ["heading-anchor"],
            "aria-label": "Link to this section",
          },
          content: {
            type: "element",
            tagName: "span",
            properties: { "aria-hidden": "true" },
            children: [{ type: "text", value: "#" }],
          },
        },
      ],
    ],
  },
});

export default withMDX(nextConfig);
