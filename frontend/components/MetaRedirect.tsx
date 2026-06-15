// Static-export-friendly redirect. `next/navigation`'s `redirect()` needs a
// server runtime and breaks `output: "export"`, so instead we render a tiny
// page that bounces the browser on load: a synchronous script for JS clients,
// a <meta refresh> for no-JS clients, and a plain link as the final fallback.
export function MetaRedirect({ to }: { to: string }) {
  return (
    <>
      <script
        dangerouslySetInnerHTML={{ __html: `location.replace(${JSON.stringify(to)})` }}
      />
      <noscript>
        <meta httpEquiv="refresh" content={`0; url=${to}`} />
      </noscript>
      <p style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
        Redirecting to <a href={to}>{to}</a>…
      </p>
    </>
  );
}
