// OpenTelemetry export. Every receipt is also emitted as one span over OTLP/HTTP JSON, so the collectors and
// dashboards a team already runs carry agent actions without a new pipeline. The trace id is the receipt id, so a
// span in Datadog or Grafana leads straight to the receipt that proves it. Export is best effort and happens after
// the receipt is issued: a collector is not evidence, and an outage there must never cost a receipt.
// No SDK dependency: OTLP/HTTP with JSON is a stable wire format, and this writes it directly.
import type { AuthorizationBundle, ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
import { splunkExporter, type SplunkConfig } from "./splunk.ts";

export interface OtelConfig {
  /** the collector's OTLP/HTTP base, e.g. http://localhost:4318; spans go to <url>/v1/traces */
  url: string;
  /** header name to environment variable, for collectors that need a key; a missing variable fails at startup */
  headersEnv?: Record<string, string> | undefined;
  /** the service.name resource attribute; default agent-custody */
  serviceName?: string | undefined;
}

export interface ReceiptExporter {
  readonly where: string;
  /** called after a bundle is written; must not throw into the issuer */
  exported(predicate: ReceiptPredicate, bundle: ReceiptBundle): Promise<void>;
}

type Attr = { key: string; value: { stringValue: string } | { intValue: string } | { boolValue: boolean } };
const str = (key: string, v: string | null | undefined): Attr[] => (v === null || v === undefined ? [] : [{ key, value: { stringValue: v } }]);
const int = (key: string, v: number): Attr[] => [{ key, value: { intValue: String(v) } }];

/** The span for one receipt, as the OTLP JSON a collector accepts on /v1/traces. Exported so a test or another transport can reuse it. */
export function spanFor(p: ReceiptPredicate, bundle: ReceiptBundle, serviceName: string): unknown {
  const hex = p.receiptId.replace(/-/g, "");
  const traceId = hex.length === 32 ? hex : hex.padEnd(32, "0").slice(0, 32);
  const start = BigInt(Date.parse(p.timestamp)) * 1_000_000n;
  const end = BigInt(Date.now()) * 1_000_000n;
  // A reconciliation receipt records a provider read that the gateway made. The gateway evaluated no policy, and it did
  // not execute the payment tool again. The span says so: a dashboard must not count it as a second allowed call.
  const reconciliation = p.reconciliation !== undefined;
  const status = reconciliation ? "reconciled" : p.execution.status;
  const operationFailed = reconciliation && p.operation?.status === "failed";
  const auth = p.authorization as AuthorizationBundle | undefined;
  const attributes: Attr[] = [
    ...str("agent_custody.receipt_id", p.receiptId),
    ...str("agent_custody.issuer.kind", p.issuer.kind),
    ...str("agent_custody.issuer.keyid", p.issuer.keyid),
    ...str("agent_custody.tool", p.tool.name),
    ...(reconciliation ? [{ key: "agent_custody.reconciliation", value: { boolValue: true } }, ...str("agent_custody.reconciliation.lookup_tool", p.reconciliation!.lookup?.tool)] : []),
    ...str("agent_custody.operation.status", p.operation?.status),
    ...str("agent_custody.operation.original_receipt_id", p.operation?.originalReceiptId),
    ...str("agent_custody.upstream", p.tool.upstream),
    ...str("agent_custody.agent", p.agent.id),
    ...str("agent_custody.agent.provenance", p.agent.provenance),
    ...str("agent_custody.principal", p.principal.id),
    ...str("agent_custody.execution.status", status),
    ...(reconciliation ? [] : str("agent_custody.policy.decision", p.policy?.decision)),
    ...(reconciliation ? [] : str("agent_custody.policy.digest", p.policy?.policyDigest)),
    ...int("agent_custody.log.leaf_index", bundle.inclusion.leafIndex),
    ...int("agent_custody.log.tree_size", bundle.inclusion.treeSize),
    ...(auth ? int("agent_custody.authorization.leaf_index", auth.inclusion.leafIndex) : []),
    ...int("agent_custody.consumed.count", Array.isArray(p.consumed?.factIds) ? p.consumed.factIds.length : 0),
    ...str("agent_custody.model", typeof p.model.id === "string" ? p.model.id : undefined),
    ...str("agent_custody.session", typeof p.session.id === "string" ? p.session.id : undefined),
  ];
  return {
    resourceSpans: [
      {
        resource: { attributes: str("service.name", serviceName) },
        scopeSpans: [
          {
            scope: { name: "agent-custody", version: p.issuer.version },
            spans: [
              {
                traceId,
                spanId: traceId.slice(0, 16),
                name: reconciliation ? `${p.tool.name} reconciliation` : `${p.tool.name}`,
                kind: p.issuer.kind === "door" ? 2 : 3, // SERVER for an inbound request; CLIENT for the agent calling out
                startTimeUnixNano: start.toString(),
                endTimeUnixNano: (end > start ? end : start).toString(),
                attributes,
                // Status.message is a string in OTLP; under a capture rule the error is a commitment, and the span says so
                status: operationFailed ? { code: 2, message: "the provider reports that the operation failed" } : status === "executed" || status === "reconciled" || status === "denied" || status === "withheld" ? { code: 1 } : { code: 2, message: status === "failed" ? "the upstream reported failure" : typeof (p.execution as { error?: unknown }).error === "string" ? ((p.execution as { error: string }).error) : (p.execution as { error?: unknown }).error ? "the upstream reported an error (withheld under the capture rule)" : status },
              },
            ],
          },
        ],
      },
    ],
  };
}

export interface OtlpOptions {
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
  /** where export failures are reported; default stderr */
  warn?: (message: string) => void;
}

/** An exporter that posts each receipt's span to an OTLP/HTTP collector. Failures are reported, never thrown. */
export function otlpExporter(cfg: OtelConfig, opts: OtlpOptions = {}): ReceiptExporter {
  const f = opts.fetch ?? fetch;
  const env = opts.env ?? process.env;
  const warn = opts.warn ?? ((m) => console.error(m));
  const headers: Record<string, string> = { "content-type": "application/json" };
  for (const [header, variable] of Object.entries(cfg.headersEnv ?? {})) {
    const v = env[variable];
    if (!v) throw new Error(`otel: environment variable ${variable} is not set`);
    headers[header] = v;
  }
  const base = cfg.url.endsWith("/") ? cfg.url : `${cfg.url}/`;
  const url = new URL("v1/traces", base);
  const serviceName = cfg.serviceName ?? "agent-custody";
  return {
    where: cfg.url,
    async exported(p, bundle) {
      try {
        const res = await f(url, { method: "POST", headers, body: JSON.stringify(spanFor(p, bundle, serviceName)), signal: AbortSignal.timeout(5000) });
        if (!res.ok) warn(`agent-custody: otel export of receipt ${p.receiptId} refused by ${cfg.url}: ${res.status}`);
      } catch (e) {
        warn(`agent-custody: otel export of receipt ${p.receiptId} failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
  };
}

/** The exporters a config asks for, as one; undefined when it asks for none. Each is told independently, so one failing never silences another. */
export function openExporter(cfg: { otel?: OtelConfig | undefined; splunk?: SplunkConfig | undefined }): ReceiptExporter | undefined {
  const all: ReceiptExporter[] = [];
  if (cfg.otel) all.push(otlpExporter(cfg.otel));
  if (cfg.splunk) all.push(splunkExporter(cfg.splunk));
  if (all.length === 0) return undefined;
  if (all.length === 1) return all[0];
  return {
    where: all.map((e) => e.where).join(", "),
    async exported(p, bundle) {
      await Promise.all(all.map((e) => e.exported(p, bundle)));
    },
  };
}
