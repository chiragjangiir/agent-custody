// The interceptor SDK: issues receipts from inside the agent's own process.
// Everything it records is "claimed", because the issuer shares a process with the agent. The receipt says so.
import { randomUUID } from "node:crypto";
import { captureKeyFrom } from "../capture.ts";
import { readFileSync } from "node:fs";
import type { SdkConfig } from "../config.ts";
import { digestOf, loadPrivateKey } from "../crypto.ts";
import { createIssuer } from "../issue.ts";
import { openExporter } from "../otel.ts";
import { openLog, type LogSink } from "../log-sink.ts";
import { evaluate, policyReasons, type PolicyDecision } from "../policy.ts";
import type { ReceiptBundle, ReceiptPredicate } from "../receipt.ts";

export const SDK_VERSION = "0.1.0";

export interface ToolEvent {
  tool: string;
  args: Record<string, unknown>;
  model?: string | null;
  session?: { id?: string | null; toolUseId?: string | null };
}

export type Outcome =
  | { status: "executed" | "failed"; result: unknown }
  | { status: "denied"; reason: string }
  | { status: "error"; error: string };

export interface SdkIssuer {
  agentId: string;
  keyid: string;
  /** where the leaves go: the local file or the remote log */
  log: LogSink;
  /** The `@reason` text of each policy in the policy file, in file order, or null for a policy without one. Parsed once at load. */
  ruleReasons: readonly (string | null)[];
  /** Evaluates the configured policy for a call. Returns null when no policy is configured. */
  decide(ev: ToolEvent): PolicyDecision | null;
  /** Issues one receipt for a completed, failed, denied, or errored call. Rejects if the log refuses it. */
  record(ev: ToolEvent, outcome: Outcome, policy?: PolicyDecision | null): Promise<ReceiptBundle>;
  /** Wraps a tool function: decide, run, record. Throws PolicyDeniedError on deny, after issuing the denial receipt. */
  wrap<A extends Record<string, unknown>, R>(tool: string, fn: (args: A) => R | Promise<R>, meta?: Omit<ToolEvent, "tool" | "args">): (args: A) => Promise<R>;
}

/** True when a decision is a deny that must be enforced: a deny made in observe mode (`enforced: false`) is recorded, not acted on. */
export function denies(policy: PolicyDecision | null | undefined): policy is PolicyDecision & { decision: "deny" } {
  return !!policy && policy.decision === "deny" && policy.enforced !== false;
}

export class PolicyDeniedError extends Error {
  readonly tool: string;
  readonly reason: string;
  readonly receiptId: string;
  constructor(tool: string, reason: string, receiptId: string) {
    super(`Denied by policy: ${reason} (receipt ${receiptId})`);
    this.name = "PolicyDeniedError";
    this.tool = tool;
    this.reason = reason;
    this.receiptId = receiptId;
  }
}

export function createSdkIssuer(cfg: SdkConfig): SdkIssuer {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const captureKey = cfg.captureKeyEnv ? captureKeyFrom(process.env[cfg.captureKeyEnv] ?? (() => { throw new Error(`capture key: environment variable ${cfg.captureKeyEnv} is not set`); })()) : undefined;
  for (const [tool, rule] of Object.entries(cfg.capture ?? {})) {
    for (const side of [rule.args, rule.result, rule.facts]) if (side?.mode === "encrypted" && !captureKey) throw new Error(`capture for ${tool} uses mode encrypted, which needs captureKeyEnv`);
  }
  // the capture rules are applied by the issuer to every statement it signs, so every adapter's receipt gets them
  const issuer = createIssuer(key, cfg.receiptsDir, openLog(cfg, key), { exporter: openExporter(cfg), capture: { rules: cfg.capture, key: captureKey } });
  const policyText = cfg.policyFile ? readFileSync(cfg.policyFile, "utf8") : null;

  const ruleReasons = policyText === null ? [] : policyReasons(policyText);

  const decide = (ev: ToolEvent): PolicyDecision | null => {
    if (policyText === null) return null;
    const d = evaluate(policyText, { agentId: cfg.agentId, tool: ev.tool, context: { args: ev.args, facts: {} } });
    return cfg.mode === "observe" ? { ...d, enforced: false } : d;
  };

  function record(ev: ToolEvent, outcome: Outcome, policy: PolicyDecision | null = null): Promise<ReceiptBundle> {
    // the call in full; the issuer withholds what the tool's capture rule says, the thrown message included
    const execution: ReceiptPredicate["execution"] =
      outcome.status === "denied"
        ? { status: "denied", reason: outcome.reason, provenance: "claimed" }
        : outcome.status === "error"
          ? { status: "error", error: outcome.error, provenance: "claimed" }
          : { status: outcome.status, result: outcome.result, resultDigest: digestOf(outcome.result), provenance: "claimed" };
    return issuer.issue({
      receiptId: randomUUID(),
      timestamp: new Date().toISOString(),
      issuer: { kind: "sdk", keyid: issuer.keyid, version: SDK_VERSION, ...(cfg.framework ? { framework: cfg.framework } : {}) },
      principal: { id: cfg.principalId ?? null, provenance: "claimed" },
      agent: { id: cfg.agentId, provenance: "claimed" },
      session: { id: ev.session?.id ?? null, toolUseId: ev.session?.toolUseId ?? null, provenance: "claimed" },
      model: { id: ev.model ?? null, provenance: "claimed" },
      tool: { name: ev.tool, provenance: "claimed" },
      request: { args: ev.args, argsDigest: digestOf(ev.args), provenance: "claimed" },
      facts: {},
      policy: policy ? { ...policy, provenance: "claimed" } : null,
      execution,
    });
  }

  return {
    agentId: cfg.agentId,
    keyid: issuer.keyid,
    log: issuer.log,
    ruleReasons,
    decide,
    record,
    wrap(tool, fn, meta = {}) {
      return async (args) => {
        const ev: ToolEvent = { tool, args, ...meta };
        const policy = decide(ev);
        if (denies(policy)) {
          const reason = [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched";
          const bundle = await record(ev, { status: "denied", reason }, policy);
          throw new PolicyDeniedError(tool, reason, receiptIdOf(bundle));
        }
        try {
          const result = await fn(args);
          await record(ev, { status: "executed", result }, policy);
          return result;
        } catch (e) {
          await record(ev, { status: "error", error: e instanceof Error ? e.message : String(e) }, policy);
          throw e;
        }
      };
    },
  };
}

export function receiptIdOf(bundle: ReceiptBundle): string {
  const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as { predicate: { receiptId: string } };
  return st.predicate.receiptId;
}
