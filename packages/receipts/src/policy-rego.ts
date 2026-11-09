// Rego policies. A policy file ending in .rego is compiled once per change with `opa build -t wasm` and evaluated
// in-process by the OPA WebAssembly SDK, so the opa binary is needed when the policy loads or changes, not to evaluate a
// call. A gateway or witness reloads on the first call after a change, and the compile is synchronous with no timeout,
// so the whole process waits for it (and an opa that hangs stalls it). An OPA
// server the operator runs answers the same contract over HTTP (opa-server.ts). Either way, fails closed.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import type { PolicyDecision, PolicyRequest } from "./policy.ts";

// The SDK's ES module entry exports only the async loader; its CommonJS entry has loadPolicySync, which lets a policy
// load inside the gateway's synchronous reload, like a Cedar file.
const require = createRequire(import.meta.url);
const opa: typeof import("@open-policy-agent/opa-wasm") = require("@open-policy-agent/opa-wasm");

/** The package a Rego policy file declares. Its `allow` and `deny` rules are the decision. */
export const REGO_PACKAGE = "agentcustody";

export type RegoPolicy = ReturnType<typeof opa.loadPolicySync>;

export function isRegoFile(path: string): boolean {
  return path.toLowerCase().endsWith(".rego");
}

/**
 * The input a Rego policy reads: the Cedar request with plain strings for the three identifiers. `context` holds `args`
 * (claimed), `facts` (observed), and `grant` (attested), exactly as Cedar sees them.
 */
export function regoInput(req: PolicyRequest): Record<string, unknown> {
  return { principal: req.agentId, action: req.tool, resource: req.tool, context: req.context };
}

/**
 * The decision from the document the policy package evaluates to. Default deny: `allow` must be exactly `true`. Any
 * entry in `deny` wins over `allow`, as a Cedar `forbid` wins over a `permit`, and its strings are the reasons. A
 * document of the wrong shape is an error, and an error is a deny.
 */
export function regoDecision(doc: unknown, policyDigest: string, rule = `data.${REGO_PACKAGE}`, where = rule): PolicyDecision {
  const deny = (errors: string[], reasons: string[] = []): PolicyDecision => ({ decision: "deny", reasons, errors, policyDigest });
  if (doc === undefined) return deny([`${where} is undefined`]);
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return deny([`${where} is not an object with allow and deny rules`]);
  const { allow, deny: denied } = doc as { allow?: unknown; deny?: unknown };
  if (allow !== undefined && typeof allow !== "boolean") return deny([`${where}.allow is not a boolean`]);
  if (denied !== undefined && (!Array.isArray(denied) || !denied.every((d) => typeof d === "string"))) return deny([`${where}.deny is not a set of strings`]);
  if (denied && denied.length > 0) return deny([], denied as string[]);
  return allow === true ? { decision: "allow", reasons: [`${rule}.allow`], errors: [], policyDigest } : deny([]);
}

export function evaluateRego(policy: RegoPolicy, policyDigest: string, req: PolicyRequest): PolicyDecision {
  let result: unknown;
  try {
    result = policy.evaluate(regoInput(req), REGO_PACKAGE);
  } catch (e) {
    return { decision: "deny", reasons: [], errors: [e instanceof Error ? e.message : String(e)], policyDigest };
  }
  const set = Array.isArray(result) ? result as { result?: unknown }[] : [];
  return regoDecision(set[0]?.result, policyDigest);
}

/** One file out of a gzipped tar, as `opa build` writes its bundle. */
function fromTarGz(gz: Buffer, name: string): Buffer | undefined {
  const tar = gunzipSync(gz);
  for (let at = 0; at + 512 <= tar.length;) {
    const header = tar.subarray(at, at + 512);
    if (header.every((b) => b === 0)) return undefined;
    const field = (from: number, to: number) => header.subarray(from, to).toString("utf8").replace(/\0.*$/s, "");
    const path = [field(345, 500), field(0, 100)].filter(Boolean).join("/").replace(/^\/+/, "");
    const size = parseInt(field(124, 136).trim() || "0", 8);
    if (path === name && (field(156, 157) === "0" || field(156, 157) === "")) return Buffer.from(tar.subarray(at + 512, at + 512 + size));
    at += 512 + Math.ceil(size / 512) * 512;
  }
  return undefined;
}

let capabilities: string | undefined;

/**
 * The builtins `opa build` may compile in: the current opa's capabilities, cut down to the builtins the WebAssembly
 * SDK can run. A policy calling another one, such as `http.send` or `time.now_ns`, is refused when it loads, instead of
 * failing on each call.
 */
function sdkCapabilities(opaBin: string): string {
  if (capabilities) return capabilities;
  const sdkFile = join(dirname(require.resolve("@open-policy-agent/opa-wasm")), "..", "capabilities.json");
  const supported = new Set((JSON.parse(readFileSync(sdkFile, "utf8")) as { builtins: { name: string }[] }).builtins.map((b) => b.name));
  const current = JSON.parse(execFileSync(opaBin, ["capabilities", "--current"], { encoding: "utf8" })) as { builtins: { name: string }[] };
  capabilities = JSON.stringify({ ...current, builtins: current.builtins.filter((b) => supported.has(b.name)) });
  return capabilities;
}

/**
 * Compiles Rego text with the opa binary on PATH. Answers the loaded policy, or why it cannot be used: a syntax or type
 * error, a builtin the SDK cannot run, no `package agentcustody`, or no opa binary.
 */
export function compileRego(text: string, opaBin = "opa"): { policy: RegoPolicy; errors: [] } | { policy?: undefined; errors: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "agent-custody-rego-"));
  try {
    writeFileSync(join(dir, "policy.rego"), text);
    writeFileSync(join(dir, "capabilities.json"), sdkCapabilities(opaBin));
    execFileSync(opaBin, ["build", "-t", "wasm", "-e", REGO_PACKAGE, "--capabilities", "capabilities.json", "-o", "bundle.tar.gz", "policy.rego"], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
    const wasm = fromTarGz(readFileSync(join(dir, "bundle.tar.gz")), "policy.wasm");
    if (!wasm) return { errors: ["opa build wrote no policy.wasm"] };
    return { policy: opa.loadPolicySync(wasm), errors: [] };
  } catch (e) {
    const err = e as NodeJS.ErrnoException & { stdout?: Buffer; stderr?: Buffer };
    if (err.code === "ENOENT") return { errors: [`compiling a Rego policy needs the opa binary on PATH (${opaBin} was not found)`] };
    const said = [err.stderr, err.stdout].map((b) => b?.toString("utf8").trim() ?? "").filter(Boolean).join("\n");
    const message = said ? said.replace(/^error: /, "") : err.message;
    return { errors: [/entrypoint "[^"]*" does not refer to a rule/.test(message) ? `${message}: the policy must declare package ${REGO_PACKAGE}` : message] };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
