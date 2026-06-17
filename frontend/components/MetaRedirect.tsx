"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// Static-export-friendly redirect. `next/navigation`'s `redirect()` needs a
// server runtime and breaks `output: "export"`, so we bounce on the client:
//   * useEffect → router.replace covers every JS path — both a direct hit
//     (fires right after hydration) and a soft <Link> navigation. An earlier
//     version used an inline <script> for the direct-hit case, but React never
//     executes scripts it renders on the client, so soft navigations hung on
//     "Redirecting…" until a manual reload (and React 19 warns about the tag).
//   * <noscript> meta-refresh handles JS-disabled clients.
//   * the visible link is the final fallback.
export function MetaRedirect({ to }: { to: string }) {
  const router = useRouter();
  useEffect(() => {
    router.replace(to);
  }, [router, to]);

  return (
    <>
      <noscript>
        <meta httpEquiv="refresh" content={`0; url=${to}`} />
      </noscript>
      <p style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
        Redirecting to <a href={to}>{to}</a>…
      </p>
    </>
  );
}
