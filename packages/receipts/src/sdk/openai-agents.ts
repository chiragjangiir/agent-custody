// OpenAI Agents SDK (JS) adapter.
//   wrapTools:     enforcement + receipts, by wrapping each FunctionTool's invoke(). A denied call never runs; the
//                  model receives the denial text as the tool result and the run continues.
//   observeRunner: receipts only, from the runner's agent_tool_start / agent_tool_end events. Cannot block, so it
//                  evaluates no policy. Use one or the other per tool, not both.
// Typed structurally so this file does not import the package.
import { noReceipt, receiptIdOf, type SdkIssuer, type ToolEvent, denies } from "./index.ts";

interface ToolCallDetails {
  toolCall?: { callId?: string; arguments?: string };
}
// Parameters are `any` on purpose: the SDK's invoke() takes its own RunContext and ToolCallDetails types, and a
// narrower structural signature here would not be assignable under strictFunctionTypes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type InvokeFn = (runContext: any, input: string, details?: any) => Promise<unknown>;

function parseArgs(input: string | undefined): Record<string, unknown> {
  if (!input) return {};
  try {
    const v = JSON.parse(input) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : { input: v };
  } catch {
    return { input };
  }
}

function parseResult(result: unknown): unknown {
  if (typeof result !== "string") return result;
  try {
    return JSON.parse(result) as unknown;
  } catch {
    return result;
  }
}

export function wrapTools<T extends { name: string; invoke: InvokeFn }>(issuer: SdkIssuer, tools: readonly T[]): T[] {
  return tools.map((t) => {
    const invoke: InvokeFn = async (ctx, input, details?: ToolCallDetails) => {
      const ev: ToolEvent = { tool: t.name, args: parseArgs(input), session: { id: null, toolUseId: details?.toolCall?.callId ?? null } };
      const policy = issuer.decide(ev);
      if (denies(policy)) {
        const reason = [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched";
        try {
          return `Denied by policy: ${reason} (receipt ${receiptIdOf(await issuer.record(ev, { status: "denied", reason }, policy))})`;
        } catch (e) {
          return `Denied by policy: ${reason} (${noReceipt(e)})`;
        }
      }
      try {
        const result = await t.invoke(ctx, input, details);
        await issuer.record(ev, { status: "executed", result: parseResult(result) }, policy);
        return result;
      } catch (e) {
        await issuer.record(ev, { status: "error", error: e instanceof Error ? e.message : String(e) }, policy);
        throw e;
      }
    };
    return { ...t, invoke } as T;
  });
}

interface Listenable {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(event: any, listener: (...args: any[]) => void): unknown;
}

export function observeRunner(issuer: SdkIssuer, runner: Listenable): void {
  const pending = new Map<string, ToolEvent>();
  runner.on("agent_tool_start", (_ctx: unknown, _agent: unknown, tool: { name: string }, details?: ToolCallDetails) => {
    const callId = details?.toolCall?.callId;
    if (!callId) return;
    pending.set(callId, { tool: tool.name, args: parseArgs(details?.toolCall?.arguments), session: { id: null, toolUseId: callId } });
  });
  runner.on("agent_tool_end", (_ctx: unknown, _agent: unknown, tool: { name: string }, result: unknown, details?: ToolCallDetails) => {
    const callId = details?.toolCall?.callId ?? "";
    const ev = pending.get(callId) ?? { tool: tool.name, args: {}, session: { id: null, toolUseId: callId || null } };
    pending.delete(callId);
    // The runner does not await listeners. A log that refuses the leaf is reported on stderr; nothing else can see it here.
    issuer.record(ev, { status: "executed", result: parseResult(result) }, null).catch((e: unknown) => console.error(`agent-custody: receipt not issued: ${e instanceof Error ? e.message : e}`));
  });
}
