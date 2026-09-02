"use client";

import { useState } from "react";

// Real operator-console screenshots. Tabs swap the image; all four are emitted
// so switching is instant (no flash on first view).
//
// w/h are the images' intrinsic CSS sizes (the files themselves are 2×) and they
// reserve layout space, so a wrong value shifts the page as the image loads.
// engine/scripts/capture-console.sh prints the exact numbers to paste here after
// a recapture — the heights track content, so they change whenever the scene does.
const TABS = [
  { id: "overview", label: "Overview", src: "/assets/screenshots/console-overview.png", w: 1440, h: 1049 },
  { id: "attacks", label: "Attacks", src: "/assets/screenshots/console-attacks.png", w: 1440, h: 644 },
  { id: "hosts", label: "Hosts", src: "/assets/screenshots/console-hosts.png", w: 1440, h: 768 },
  { id: "mitigation", label: "Mitigation", src: "/assets/screenshots/console-mitigation.png", w: 1440, h: 973 },
] as const;

export function ConsoleShowcase() {
  const [active, setActive] = useState<(typeof TABS)[number]["id"]>("attacks");

  return (
    <div>
      {/* Tab switcher: underlined text tabs, the way a real app draws them. */}
      <div role="tablist" className="mb-6 flex gap-6 border-b border-border text-sm">
        {TABS.map((t) => {
          const on = active === t.id;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={on}
              onClick={() => setActive(t.id)}
              className={`-mb-px border-b-2 pb-3 font-medium transition-colors ${
                on ? "border-foreground text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Plain 1px frame; the screenshot is the real thing and needs no chrome. */}
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {TABS.map((t) => (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            key={t.id}
            src={t.src}
            alt={`Kapkan operator console — ${t.label} view`}
            width={t.w}
            height={t.h}
            loading="lazy"
            className={`h-auto w-full ${active === t.id ? "block" : "hidden"}`}
          />
        ))}
      </div>
    </div>
  );
}
