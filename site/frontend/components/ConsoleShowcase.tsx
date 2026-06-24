"use client";

import { useState } from "react";

// Real operator-console screenshots, framed in a browser window. Tabs swap the
// image; all four are emitted so switching is instant (no flash on first view).
const TABS = [
  { id: "overview", label: "Overview", src: "/assets/screenshots/console-overview.png", w: 1440, h: 1021 },
  { id: "attacks", label: "Attacks", src: "/assets/screenshots/console-attacks.png", w: 1440, h: 618 },
  { id: "hosts", label: "Hosts", src: "/assets/screenshots/console-hosts.png", w: 1440, h: 740 },
  { id: "mitigation", label: "Mitigation", src: "/assets/screenshots/console-mitigation.png", w: 1440, h: 769 },
] as const;

export function ConsoleShowcase() {
  const [active, setActive] = useState<(typeof TABS)[number]["id"]>("attacks");

  return (
    <div>
      {/* Tab switcher */}
      <div className="mb-8 flex justify-center">
        <div className="inline-flex rounded-full border border-border bg-surface p-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActive(t.id)}
              aria-pressed={active === t.id}
              className={`rounded-full px-5 py-2 text-sm font-medium transition-colors ${
                active === t.id
                  ? "bg-muted text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Window frame */}
      <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl ring-1 ring-black/5">
        {/* Browser chrome */}
        <div className="flex h-11 items-center gap-4 border-b border-border bg-muted px-4">
          <div className="flex gap-2">
            <span className="h-3 w-3 rounded-full bg-border" />
            <span className="h-3 w-3 rounded-full bg-border" />
            <span className="h-3 w-3 rounded-full bg-border" />
          </div>
          <div className="flex flex-1 justify-center">
            <span className="rounded-md border border-border bg-background px-4 py-1 text-center font-mono text-xs text-muted-foreground">
              kapkan.local:8080/ui
            </span>
          </div>
        </div>

        {/* Screenshots — keep all mounted, toggle visibility for instant switching */}
        <div className="relative bg-background">
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
    </div>
  );
}
