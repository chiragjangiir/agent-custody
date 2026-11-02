// Adapter for Claude Code hooks (command hooks over stdin/stdout) and the Claude Agent SDK (in-process hooks).
// Both use the same input and output JSON, so one handler serves both.
import { createSdkIssuer, receiptIdOf, type SdkIssuer, type ToolEvent, denies } from "./index.ts";

export interface HookInput {
  hook_event_name: string;
  session_id?: string;
  tool_name: string;
  tool_input?: unknown;
  tool_response?: unknown;
  tool_use_id?: string;
  error?: unknown;
  [k: string]: unknown;
}

export interface HookOutput {
  continue?: boolean;
  hookSpecificOutput?: {
    hookEventName: string;
    permissionDecision?: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
  };
}

function toEvent(input: HookInput): ToolEvent {
  const raw = input.tool_input;
  const args = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : { input: raw ?? null };
  return { tool: input.tool_name, args, session: { id: input.session_id ?? null, toolUseId: input.tool_use_id ?? null } };
}

/**
 * PreToolUse: evaluate policy; on deny, issue a denial receipt and block. On allow or no policy, return no decision,
 * so the host's normal permission flow still applies. This adapter never auto-approves.
 * PostToolUse / PostToolUseFailure: issue the receipt for the completed call.
 */
export async function handleHookEvent(issuer: SdkIssuer, input: HookInput): Promise<HookOutput> {
  const ev = toEvent(input);
  switch (input.hook_event_name) {
    case "PreToolUse": {
      const policy = issuer.decide(ev);
      if (denies(policy)) {
        const reason = [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched";
        // A hook that throws does not block the call, so a log outage must not cost the denial.
        let evidence: string;
        try {
          evidence = `receipt ${receiptIdOf(await issuer.record(ev, { status: "denied", reason }, policy))}`;
        } catch (e) {
          evidence = `no receipt: ${e instanceof Error ? e.message : String(e)}`;
        }
        return {
          continue: true,
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: `agent-custody: ${reason} (${evidence})`,
          },
        };
      }
      return {};
    }
    case "PostToolUse":
      await issuer.record(ev, { status: "executed", result: input.tool_response ?? null }, issuer.decide(ev));
      return {};
    case "PostToolUseFailure":
      await issuer.record(ev, { status: "failed", result: input.error ?? input.tool_response ?? null }, issuer.decide(ev));
      return {};
    default:
      return {};
  }
}

/**
 * Hooks for the Claude Agent SDK's query({ hooks }) option. Register all three events.
 * Typed loosely on purpose so this file does not depend on the SDK package.
 */
export function claudeAgentHooks(issuer: SdkIssuer, matcher?: string) {
  const cb = async (input: unknown) => handleHookEvent(issuer, input as HookInput);
  const entry = matcher === undefined ? { hooks: [cb] } : { matcher, hooks: [cb] };
  return { PreToolUse: [entry], PostToolUse: [entry], PostToolUseFailure: [entry] };
}

export { createSdkIssuer };
