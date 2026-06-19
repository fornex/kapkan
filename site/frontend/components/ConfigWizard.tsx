"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Locale } from "@/lib/i18n";
import { wizardChrome, wizardHelp } from "@/lib/wizard/strings";
import { emitConfig, initialState, type WizardState } from "@/lib/wizard/emit";
import { fieldMeta, fieldNode } from "@/lib/wizard/schema";
import { validateNumber, validateString } from "@/lib/wizard/validate";
import { loadEngineValidator, type EngineResult, type EngineValidator } from "@/lib/wizard/wasm";

const inputCls =
  "w-full min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm outline-none transition-colors focus:border-accent";

function Field({
  label,
  help,
  error,
  children,
}: {
  label: string;
  help?: string;
  error?: string | null;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1 block text-sm font-medium">{label}</label>
      {children}
      {error ? (
        <p className="mt-1 text-xs text-red-500">{error}</p>
      ) : help ? (
        <p className="mt-1 text-xs text-muted-foreground">{help}</p>
      ) : null}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-surface p-5">
      <h3 className="mb-4 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

export function ConfigWizard({ lang }: { lang: Locale }) {
  const t = wizardChrome[lang];
  const vmsg = t.validation;
  const hp = (path?: string): string | undefined =>
    path ? (wizardHelp[lang]?.[path] ?? fieldMeta(path).description) : undefined;

  const [s, setS] = useState<WizardState>(initialState);
  const [step, setStep] = useState(0);
  const [copied, setCopied] = useState(false);
  const lastStep = t.steps.length - 1;
  const onReview = step === lastStep;

  const yaml = useMemo(() => emitConfig(s), [s]);

  // Engine-exact validation via the wasm build of the real Parse+validate. Runs
  // live as fields change so the result is ready the moment the review step opens.
  const validatorRef = useRef<EngineValidator | null>(null);
  const [engineReady, setEngineReady] = useState<boolean | null>(null);
  const [engineResult, setEngineResult] = useState<EngineResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadEngineValidator().then((fn) => {
      if (cancelled) return;
      validatorRef.current = fn;
      setEngineReady(!!fn);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const fn = validatorRef.current;
    if (!fn) return;
    const id = setTimeout(() => {
      try {
        setEngineResult(fn(yaml));
      } catch {
        setEngineResult(null);
      }
    }, 350);
    return () => clearTimeout(id);
  }, [yaml, engineReady]);

  function set<K extends keyof WizardState>(k: K, v: WizardState[K]) {
    setS((p) => ({ ...p, [k]: v }));
  }

  function copy() {
    navigator.clipboard?.writeText(yaml).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  function download() {
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "kapkan.yaml";
    a.click();
    URL.revokeObjectURL(url);
  }

  // --- typed field renderers (validation + help sourced from schema/overlay) ---
  const text = (
    label: string,
    key: keyof WizardState,
    path: string,
    opts: { required?: boolean; mono?: boolean } = {},
  ) => {
    const value = s[key] as string;
    const error =
      value.trim() === "" ? (opts.required ? vmsg.required : null) : validateString(path, value, vmsg);
    return (
      <Field label={label} help={hp(path)} error={error}>
        <input
          className={`${inputCls}${opts.mono ? " font-mono" : ""}`}
          value={value}
          spellCheck={false}
          onChange={(e) => set(key, e.target.value as WizardState[typeof key])}
        />
      </Field>
    );
  };

  const number = (
    label: string,
    key: keyof WizardState,
    path: string,
    opts: { required?: boolean } = {},
  ) => {
    const value = s[key] as string;
    const error =
      value.trim() === "" ? (opts.required ? vmsg.required : null) : validateNumber(path, Number(value), vmsg);
    return (
      <Field label={label} help={hp(path)} error={error}>
        <input
          className={inputCls}
          inputMode="numeric"
          value={value}
          onChange={(e) => set(key, e.target.value.replace(/[^\d]/g, "") as WizardState[typeof key])}
        />
      </Field>
    );
  };

  const list = (label: string, key: "networks" | "whitelist", path: string) => {
    const values = s[key];
    return (
      <Field label={label} help={hp(path)}>
        <div className="space-y-2">
          {values.map((v, i) => {
            const err = v.trim() ? validateString(path, v, vmsg) : null;
            return (
              <div key={i}>
                <div className="flex gap-2">
                  <input
                    className={`${inputCls} font-mono`}
                    value={v}
                    spellCheck={false}
                    onChange={(e) => {
                      const next = values.slice();
                      next[i] = e.target.value;
                      set(key, next);
                    }}
                  />
                  <button
                    type="button"
                    aria-label="remove"
                    className="shrink-0 rounded-md border border-border px-3 text-muted-foreground hover:bg-muted"
                    onClick={() => set(key, values.filter((_, j) => j !== i))}
                  >
                    ×
                  </button>
                </div>
                {err && <p className="mt-1 text-xs text-red-500">{err}</p>}
              </div>
            );
          })}
          <button
            type="button"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted"
            onClick={() => set(key, [...values, ""])}
          >
            {t.addItem}
          </button>
        </div>
      </Field>
    );
  };

  const mitigationOpts = fieldNode("mitigation")?.enum ?? ["blackhole", "flowspec", "divert"];

  // --- per-step form content (steps 0..lastStep-1; the review step is rendered below) ---
  function stepContent() {
    switch (step) {
      case 0:
        return (
          <>
            <Section title={t.sections.mode}>
              <label className="flex items-center justify-between gap-4">
                <span>
                  <span className="block text-sm font-medium">dry_run</span>
                  <span className="mt-1 block text-xs text-muted-foreground">{hp("dry_run")}</span>
                </span>
                <input
                  type="checkbox"
                  className="h-5 w-5 accent-[var(--accent)]"
                  checked={s.dry_run}
                  onChange={(e) => set("dry_run", e.target.checked)}
                />
              </label>
              {!s.dry_run && (
                <p className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-500">
                  {t.liveWarning}
                </p>
              )}
            </Section>
            <Section title={t.sections.telemetry}>
              {text("listen.sflow", "sflow", "listen.sflow", { mono: true })}
              {text("listen.netflow", "netflow", "listen.netflow", { mono: true })}
              {number("sampling.default_rate", "default_rate", "sampling.default_rate", { required: true })}
            </Section>
          </>
        );
      case 1:
        return (
          <Section title={t.sections.networks}>
            {list("networks", "networks", "networks")}
            {list("protected_whitelist", "whitelist", "protected_whitelist")}
          </Section>
        );
      case 2:
        return (
          <>
            <Section title={t.sections.thresholds}>
              {number("pps", "pps", "thresholds.pps", { required: true })}
              {number("mbps", "mbps", "thresholds.mbps", { required: true })}
              {number("flows_per_sec", "flows_per_sec", "thresholds.flows_per_sec", { required: true })}
            </Section>
            <Section title={t.sections.perProtocol}>
              {number("thresholds.tcp_syn_pps", "tcp_syn_pps", "thresholds.tcp_syn_pps")}
              {number("thresholds.udp_pps", "udp_pps", "thresholds.udp_pps")}
            </Section>
          </>
        );
      case 3:
        return (
          <>
            <Section title={t.sections.mitigationMethod}>
              <Field label="mitigation" help={hp("mitigation")}>
                <div className="grid grid-cols-3 gap-2">
                  {mitigationOpts.map((o) => (
                    <button
                      key={o}
                      type="button"
                      onClick={() => set("mitigation", o)}
                      className={`rounded-md border px-3 py-2 text-sm font-medium capitalize transition-colors ${
                        s.mitigation === o
                          ? "border-accent bg-accent/10 text-foreground"
                          : "border-border text-muted-foreground hover:bg-muted"
                      }`}
                    >
                      {o}
                    </button>
                  ))}
                </div>
              </Field>
              {text("bgp.next_hop6", "next_hop6", "bgp.next_hop6", { mono: true })}
            </Section>
            <Section title={t.sections.bgp}>
              {number("bgp.local_asn", "local_asn", "bgp.local_asn", { required: true })}
              {text("bgp.router_id", "router_id", "bgp.router_id", { mono: true, required: true })}
              {text("bgp.next_hop", "next_hop", "bgp.next_hop", { mono: true, required: true })}
              {text("bgp.community", "community", "bgp.community", { mono: true, required: true })}
              <Field label="bgp.neighbors" help={hp("bgp.neighbors.address")}>
                <div className="space-y-3">
                  {s.neighbors.map((n, i) => {
                    const addrErr = n.address.trim() ? validateString("bgp.neighbors.address", n.address, vmsg) : null;
                    const asnErr = n.remote_asn.trim() ? validateNumber("bgp.neighbors.remote_asn", Number(n.remote_asn), vmsg) : null;
                    return (
                      <div key={i} className="rounded-md border border-border p-3">
                        <div className="flex gap-2">
                          <input
                            className={`${inputCls} font-mono`}
                            placeholder="address"
                            value={n.address}
                            spellCheck={false}
                            onChange={(e) => {
                              const next = s.neighbors.slice();
                              next[i] = { ...next[i], address: e.target.value };
                              set("neighbors", next);
                            }}
                          />
                          <input
                            className={`${inputCls} w-32`}
                            inputMode="numeric"
                            placeholder="remote_asn"
                            value={n.remote_asn}
                            onChange={(e) => {
                              const next = s.neighbors.slice();
                              next[i] = { ...next[i], remote_asn: e.target.value.replace(/[^\d]/g, "") };
                              set("neighbors", next);
                            }}
                          />
                          <button
                            type="button"
                            aria-label="remove"
                            className="shrink-0 rounded-md border border-border px-3 text-muted-foreground hover:bg-muted"
                            onClick={() => set("neighbors", s.neighbors.filter((_, j) => j !== i))}
                          >
                            ×
                          </button>
                        </div>
                        {(addrErr || asnErr) && <p className="mt-1 text-xs text-red-500">{addrErr ?? asnErr}</p>}
                      </div>
                    );
                  })}
                  <button
                    type="button"
                    className="rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted"
                    onClick={() => set("neighbors", [...s.neighbors, { address: "", remote_asn: "" }])}
                  >
                    {t.addNeighbor}
                  </button>
                </div>
              </Field>
            </Section>
          </>
        );
      case 4:
        return (
          <>
            <Section title={t.sections.ban}>
              {number("ban.ttl_seconds", "ttl_seconds", "ban.ttl_seconds", { required: true })}
              {number("ban.unban_hysteresis_seconds", "unban_hysteresis_seconds", "ban.unban_hysteresis_seconds", { required: true })}
              {number("ban.max_active_bans", "max_active_bans", "ban.max_active_bans", { required: true })}
            </Section>
            <Section title={t.sections.notify}>
              {text("notify.telegram.token_env", "tg_token_env", "notify.telegram.token_env", { mono: true })}
              {text("notify.telegram.chat_id", "tg_chat_id", "notify.telegram.chat_id", { mono: true })}
            </Section>
            <Section title={t.sections.api}>
              {text("api.listen", "api_listen", "api.listen", { mono: true, required: true })}
              {text("api.token_env", "api_token_env", "api.token_env", { mono: true })}
            </Section>
          </>
        );
      default:
        return null;
    }
  }

  // The generated config + engine validation — shown only on the final review step.
  const reviewPanel = (
    <>
      <Section title={t.reviewTitle}>
        <p className="text-sm text-muted-foreground">{t.reviewIntro}</p>
      </Section>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t.output}</span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={copy}
              className="rounded-md border border-border px-3 py-1 text-xs font-medium hover:bg-muted"
            >
              {copied ? t.copied : t.copy}
            </button>
            <button
              type="button"
              onClick={download}
              className="rounded-md bg-accent px-3 py-1 text-xs font-medium text-accent-foreground hover:opacity-90"
            >
              {t.download}
            </button>
          </div>
        </div>
        <pre className="max-h-[60vh] overflow-y-auto whitespace-pre-wrap break-words px-4 py-3 font-mono text-xs leading-relaxed">
          {yaml}
        </pre>
      </div>

      {engineResult && (
        <div
          className={`rounded-md border px-3 py-2 text-xs ${
            engineResult.ok ? "border-emerald-500/40 bg-emerald-500/10" : "border-red-500/40 bg-red-500/10"
          }`}
        >
          {engineResult.ok ? (
            <>
              <p className="font-medium text-emerald-600 dark:text-emerald-400">✓ {t.accepts}</p>
              {engineResult.summary && (
                <pre className="mt-1 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-muted-foreground">
                  {engineResult.summary}
                </pre>
              )}
            </>
          ) : (
            <p className="font-medium text-red-500">✗ {engineResult.error}</p>
          )}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        {t.checkHint}{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono">kapkan -check-config kapkan.yaml</code>
      </p>
    </>
  );

  return (
    <div>
      {/* stepper */}
      <ol className="mb-6 flex items-center gap-1 overflow-x-auto pb-1">
        {t.steps.map((label, i) => {
          const active = i === step;
          const done = i < step;
          return (
            <li key={i} className="flex shrink-0 items-center">
              <button
                type="button"
                onClick={() => setStep(i)}
                aria-current={active ? "step" : undefined}
                className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm transition-colors ${
                  active
                    ? "border-accent bg-accent text-accent-foreground"
                    : "border-border text-muted-foreground hover:bg-muted"
                }`}
              >
                <span
                  className={`flex h-5 w-5 items-center justify-center rounded-full text-xs ${
                    active ? "bg-accent-foreground/20" : done ? "bg-accent/15 text-accent" : "bg-muted"
                  }`}
                >
                  {done ? "✓" : i + 1}
                </span>
                <span className="whitespace-nowrap">{label}</span>
              </button>
              {i < t.steps.length - 1 && <span className="mx-1 h-px w-4 shrink-0 bg-border" aria-hidden />}
            </li>
          );
        })}
      </ol>

      {/* single column: form while stepping, the config only on the review step */}
      <div className={`mx-auto space-y-6 ${onReview ? "max-w-4xl" : "max-w-2xl"}`}>
        {onReview ? reviewPanel : stepContent()}

        <div className="flex items-center justify-between pt-1">
          <button
            type="button"
            disabled={step === 0}
            onClick={() => setStep((n) => Math.max(0, n - 1))}
            className="rounded-full border border-border px-5 py-2 text-sm font-medium disabled:opacity-40 enabled:hover:bg-muted"
          >
            {t.back}
          </button>
          {step < lastStep && (
            <button
              type="button"
              onClick={() => setStep((n) => Math.min(lastStep, n + 1))}
              className="rounded-full bg-accent px-5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90"
            >
              {t.next}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
