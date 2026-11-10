// Adapter for OpenClaw plugin hooks. OpenClaw runs plugins in the agent's own process and offers two tool hooks:
// `before_tool_call`, which may block a call with a reason the model sees, and `after_tool_call`, which carries the
// result or the error. Both are awaited. This file mirrors OpenClaw's typed hook contract (src/plugins/hook-types.ts)
// loosely, on purpose, so it does not depend on the openclaw package; a plugin entry wires it with `api.on`.
//
//   import { definePluginEntry } from "openclaw/plugin-sdk/plugin-sdk";
//   import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
//   import { registerOpenClaw } from "@agent-custody/receipts/sdk/openclaw";
//   export default definePluginEntry({ id: "agent-custody", name: "agent-custody", description: "A receipt for every tool call",
//     register(api) { registerOpenClaw(api, createSdkIssuer(loadSdkConfig(process.env.AGENT_CUSTODY_CONFIG!))); } });
import { denies, noReceipt, receiptIdOf, type SdkIssuer, type ToolEvent } from "./index.ts";

/** What OpenClaw passes as the hook context (PluginHookToolContext), the fields this adapter reads. */
export interface OpenClawToolContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
  [k: string]: unknown;
}
/** PluginHookBeforeToolCallEvent */
export interface OpenClawBeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  [k: string]: unknown;
}
/** PluginHookAfterToolCallEvent */
export interface OpenClawAfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
  [k: string]: unknown;
}
/** The part of PluginHookBeforeToolCallResult this adapter produces. */
export interface OpenClawBeforeToolCallResult {
  block: true;
  blockReason: string;
}

function toEvent(event: { toolName: string; params: unknown; toolCallId?: string }, ctx: OpenClawToolContext | undefined): ToolEvent {
  const raw = event.params;
  const args = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : { input: raw ?? null };
  return { tool: event.toolName, args, session: { id: ctx?.sessionId ?? ctx?.sessionKey ?? null, toolUseId: event.toolCallId ?? ctx?.toolCallId ?? null } };
}

/**
 * The two handlers. `before_tool_call` evaluates the policy: on deny it issues a denial receipt and blocks with the
 * reason and the receipt id, which OpenClaw shows the model as the tool's result; on allow, or with no policy, it
 * returns nothing, so OpenClaw's own approvals and other plugins still apply. It never auto-approves. If the receipt
 * cannot be issued (the log refused it) the call is blocked too: nothing runs without evidence. `after_tool_call`
 * issues the receipt for the completed or failed call; a refused leaf is thrown, which OpenClaw logs.
 */
export function openclawHooks(issuer: SdkIssuer) {
  return {
    before_tool_call: async (event: OpenClawBeforeToolCallEvent, ctx?: OpenClawToolContext): Promise<OpenClawBeforeToolCallResult | undefined> => {
      const ev = toEvent(event, ctx);
      const policy = issuer.decide(ev);
      if (!denies(policy)) return undefined;
      const reason = [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched";
      try {
        const bundle = await issuer.record(ev, { status: "denied", reason }, policy);
        return { block: true, blockReason: `agent-custody: ${reason} (receipt ${receiptIdOf(bundle)})` };
      } catch (e) {
        return { block: true, blockReason: `agent-custody: ${reason} (${noReceipt(e)})` };
      }
    },
    after_tool_call: async (event: OpenClawAfterToolCallEvent, ctx?: OpenClawToolContext): Promise<void> => {
      const ev = toEvent(event, ctx);
      const outcome = event.error !== undefined ? { status: "failed" as const, result: event.error } : { status: "executed" as const, result: event.result ?? null };
      await issuer.record(ev, outcome, issuer.decide(ev));
    },
  };
}

/** Registers both hooks on a plugin api (`api.on(name, handler)`), for a plugin's `register(api)`. */
export function registerOpenClaw(api: { on: (name: string, handler: (event: any, ctx?: any) => unknown) => unknown }, issuer: SdkIssuer): void {
  const hooks = openclawHooks(issuer);
  api.on("before_tool_call", hooks.before_tool_call);
  api.on("after_tool_call", hooks.after_tool_call);
}
