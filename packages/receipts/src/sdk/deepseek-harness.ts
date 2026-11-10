// Adapter for DeepSeek Harness (dsh), where everything is a plugin. The harness runs two awaited waterfalls around
// every tool call: `tools/pre-execute`, whose handler returns `{ kind: "allow" }`, `{ kind: "deny", reason }` (the
// reason reaches the model), or delegates with `next()`; and `tools/post-execute`, which sees the result. This module
// is itself a harness plugin: it exports `name`, `inject`, `Config`, and `apply`, so it is listed by its package path
// with the SDK config as its only setting.
//
//   # cordis.yml (an overlay; `dsh web --patch ./cordis.yml`), or the plugin list the dsh CLI manages
//   - insert:
//       - id: agent-custody
//         name: "@agent-custody/receipts/sdk/deepseek-harness"
//         config:
//           config: /abs/path/sdk.json
//
// Typed loosely from the harness's `packages/core/tools/src/index.ts` on purpose, so this package does not depend on
// `@deepseek-ai/dsh-tools`; `deepseekHarnessHooks(issuer)` gives the two handlers for a plugin that registers them
// itself. The harness also ships `@deepseek-ai/dsh-hooks-claude-code`, which runs a Claude Code hooks.json: the
// `agent-custody hook` command works through it unchanged, one process per call. This plugin is the in-process path.
import { z } from "zod";
import { loadSdkConfig } from "../config.ts";
import { createSdkIssuer, denies, noReceipt, receiptIdOf, type SdkIssuer, type ToolEvent } from "./index.ts";

/** The fields of the harness's ToolExecution this adapter reads. */
export interface DshToolExecution {
  name: string;
  arguments?: unknown;
  callId?: string;
  agent?: { session?: { header?: { id?: string } } } | undefined;
  [k: string]: unknown;
}
/** ToolExecutionResult: success carries `content` blocks and a `value`; failure carries `error`. */
export interface DshToolExecutionResult {
  isError: boolean;
  content?: unknown[];
  value?: unknown;
  error?: unknown;
  [k: string]: unknown;
}
export type DshPreToolDecision = { kind: "allow" } | { kind: "deny"; reason: string } | { kind: "cancel" } | { kind: "ask"; reason?: string };
export type DshPostToolDecision = { kind: "accept"; [k: string]: unknown } | { kind: "block"; feedback: unknown[]; [k: string]: unknown };

function toEvent(exec: DshToolExecution): ToolEvent {
  const raw = exec.arguments;
  const args = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : { input: raw ?? null };
  return { tool: exec.name, args, session: { id: exec.agent?.session?.header?.id ?? null, toolUseId: exec.callId ?? null } };
}

/**
 * The two handlers. `preExecute` evaluates the policy: on an enforced deny it issues the denial receipt and returns
 * `{ kind: "deny" }` with the reason and the receipt id, which the model sees; otherwise it delegates with `next()`,
 * so the harness's own approvals and other plugins still apply. It never returns `allow` itself. If the denial
 * receipt cannot be issued the call is denied all the same. `postExecute` issues the receipt for the executed or
 * failed call and delegates; a refused leaf is thrown, which the harness reports.
 */
export function deepseekHarnessHooks(issuer: SdkIssuer) {
  return {
    preExecute: async (exec: DshToolExecution, next: () => Promise<DshPreToolDecision>): Promise<DshPreToolDecision> => {
      const ev = toEvent(exec);
      const policy = issuer.decide(ev);
      if (!denies(policy)) return next();
      const reason = [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched";
      try {
        const bundle = await issuer.record(ev, { status: "denied", reason }, policy);
        return { kind: "deny", reason: `agent-custody: ${reason} (receipt ${receiptIdOf(bundle)})` };
      } catch (e) {
        return { kind: "deny", reason: `agent-custody: ${reason} (${noReceipt(e)})` };
      }
    },
    postExecute: async (exec: DshToolExecution, result: DshToolExecutionResult, next: () => Promise<DshPostToolDecision>): Promise<DshPostToolDecision> => {
      const ev = toEvent(exec);
      const outcome = result.isError ? { status: "failed" as const, result: result.error ?? result.content ?? null } : { status: "executed" as const, result: result.content ?? result.value ?? null };
      await issuer.record(ev, outcome, issuer.decide(ev));
      return next();
    },
  };
}

/** Registers both handlers on a Cordis context (`ctx.on(event, handler)`), for a plugin's `apply(ctx)`. */
export function registerDeepSeekHarness(ctx: { on: (event: string, handler: (...args: any[]) => unknown) => unknown }, issuer: SdkIssuer): void {
  const hooks = deepseekHarnessHooks(issuer);
  ctx.on("tools/pre-execute", hooks.preExecute);
  ctx.on("tools/post-execute", hooks.postExecute);
}

// ---- the module as a plugin ----
export const name = "agent-custody";
/** the tool runtime must be up before the two events exist */
export const inject = ["tools"];
/** Cordis validates the plugin's settings with this (zod implements Standard Schema): the SDK config file, else AGENT_CUSTODY_CONFIG. */
export const Config = z.object({ config: z.string().optional() });
export type Config = z.infer<typeof Config>;
export function apply(ctx: { on: (event: string, handler: (...args: any[]) => unknown) => unknown }, config: Config = {}): void {
  const path = config.config ?? process.env.AGENT_CUSTODY_CONFIG;
  if (!path) throw new Error("agent-custody: set `config` in the plugin's settings to the SDK config file, or AGENT_CUSTODY_CONFIG in the environment");
  registerDeepSeekHarness(ctx, createSdkIssuer(loadSdkConfig(path)));
}
