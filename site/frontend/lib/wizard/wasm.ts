// Lazy loader for the engine's wasm config validator (built into public/ at
// predev/prebuild by scripts/build-wasm.mjs). When present, it runs the engine's
// REAL Parse+validate in the browser so the builder can show engine-exact errors
// — including the cross-field rules a JSON schema cannot express — without
// sending the config anywhere. When absent (e.g. a Go-less build), the loader
// resolves to null and the wizard keeps its schema-only inline validation.

export type EngineResult = { ok: boolean; error?: string; summary?: string };
export type EngineValidator = (yaml: string) => EngineResult;

declare global {
  interface Window {
    Go?: new () => {
      importObject: WebAssembly.Imports;
      run: (instance: WebAssembly.Instance) => void;
    };
    kapkanValidateConfig?: EngineValidator;
  }
}

let loadPromise: Promise<EngineValidator | null> | null = null;

export function loadEngineValidator(): Promise<EngineValidator | null> {
  if (loadPromise) return loadPromise;
  loadPromise = load();
  return loadPromise;
}

async function load(): Promise<EngineValidator | null> {
  if (typeof window === "undefined") return null;
  try {
    await loadScript("/wasm_exec.js");
    const Go = window.Go;
    if (!Go) return null;

    const resp = await fetch("/kapkan-validate.wasm");
    if (!resp.ok) return null;

    const go = new Go();
    const bytes = await resp.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
    // main() registers window.kapkanValidateConfig then blocks (select{}); do
    // not await go.run — it never resolves.
    void go.run(instance);

    // The global is set during the synchronous part of go.run; poll briefly.
    for (let i = 0; i < 50; i++) {
      if (typeof window.kapkanValidateConfig === "function") {
        return window.kapkanValidateConfig;
      }
      await delay(20);
    }
    return null;
  } catch {
    return null;
  }
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[data-src="${src}"]`)) return resolve();
    const s = document.createElement("script");
    s.src = src;
    s.dataset.src = src;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${src}`));
    document.head.appendChild(s);
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
