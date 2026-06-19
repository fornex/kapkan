// Build the engine's config validator to WebAssembly and drop it (plus Go's
// wasm_exec.js runtime) into public/, so the config builder can run the engine's
// REAL Parse+validate in the browser. Built fresh at predev/prebuild — NEVER
// committed (see .gitignore), which avoids a multi-MB binary in git and any
// toolchain-version skew.
//
// Tolerant by design: if the Go toolchain is absent or the build fails, it logs
// and exits 0. The wizard then falls back to schema-only validation, so a
// Go-less environment can still build the site.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";

const frontend = process.cwd(); // site/frontend (npm pre-scripts run here)
const engineRoot = resolve(frontend, "../../engine");
const publicDir = resolve(frontend, "public");
const wasmOut = join(publicDir, "kapkan-validate.wasm");

function go(args, opts = {}) {
  return execFileSync("go", args, { encoding: "utf8", ...opts });
}

try {
  go(["version"], { stdio: "ignore" });
} catch {
  console.warn("[build-wasm] go not found — skipping; the config builder falls back to schema-only validation.");
  process.exit(0);
}

try {
  mkdirSync(publicDir, { recursive: true });
  go(["build", "-trimpath", "-o", wasmOut, "./cmd/kapkan-validate"], {
    cwd: engineRoot,
    env: { ...process.env, GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" },
    stdio: "inherit",
  });
  const goroot = go(["env", "GOROOT"]).trim();
  let exec = join(goroot, "lib", "wasm", "wasm_exec.js");
  if (!existsSync(exec)) exec = join(goroot, "misc", "wasm", "wasm_exec.js");
  copyFileSync(exec, join(publicDir, "wasm_exec.js"));
  console.log(`[build-wasm] ${wasmOut} + public/wasm_exec.js`);
} catch (e) {
  // Never fail the site build over the optional wasm validator.
  console.warn("[build-wasm] wasm build failed — falling back to schema-only validation:", e.message);
  process.exit(0);
}
