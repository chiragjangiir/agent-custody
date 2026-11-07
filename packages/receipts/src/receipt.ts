// The receipt: an in-toto Statement whose predicate records one tool call with per-field provenance.
import type { Envelope } from "./crypto.ts";
import type { CaptureNote, Commitment } from "./capture.ts";
import type { InclusionProof } from "./log.ts";
import type { PolicyDecision } from "./policy.ts";
import type { UpstreamEvidence } from "./upstream.ts";
import type { ApprovalRecord } from "./approval.ts";
export type { ApprovalRecord } from "./approval.ts";

export const RECEIPT_TYPE = "application/vnd.in-toto+json";
export const RECEIPT_PREDICATE_TYPE = "https://agent-custody.dev/receipt/v0.2";
/** The statement a gateway commits to the log before forwarding a consequential call; the receipt for that call embeds it. */
export const AUTHORIZATION_PREDICATE_TYPE = "https://agent-custody.dev/authorization/v0.1";
export const TREEHEAD_TYPE = "application/vnd.agent-custody.treehead+json";

/**
 * Provenance of a receipt field. This is the honest part of the design.
 *  - attested: signed by a key other than the issuer's (today: the principal's delegation key)
 *  - observed: the issuer obtained this deterministically, outside the agent's control (gateway only)
 *  - claimed:  originates from the agent, the model, or the agent's own process, with no independent check
 */
export type Provenance = "attested" | "observed" | "claimed";

/**
 * Who produced the receipt. This is the first thing a verifier should read.
 *  - gateway: an out-of-process enforcement point; the agent could neither skip nor forge it
 *  - sdk:     an interceptor inside the agent's own process; self-reported, tamper-evident after issue but not before
 *  - door:    an out-of-process enforcement point in front of a business's own HTTP surface; the arriving agent, caller,
 *             or browser could neither skip nor forge it, and has no grant unless it presented one
 */
export type IssuerKind = "gateway" | "sdk" | "door";

export interface FactRecord {
  tool: string;
  args: Record<string, unknown>;
  /** the value as recorded; under a capture rule, commitments where fields were withheld (the receipt's `capture` note names them) */
  value: unknown;
  /** the digest of the lookup's full result; under a capture rule a commitment to that result (the receipt shows only the selected value, the rest is private), named in the `capture` note */
  resultDigest: string | Commitment;
  provenance: "observed";
}

/** A gateway's durable financial operation identity; execution still describes only the tool/API call. */
export interface OperationEvidence {
  id: string;
  idempotencyKey: string;
  /** Commits the configured provider read and status mapping before the financial call is forwarded. */
  lookupDigest: string;
  status: "submitted" | "pending" | "confirmed" | "failed" | "unknown";
  /** Amounts stay in the original request, under its capture rule, rather than being copied into public metadata. */
  budget: { id: string; currency: string; period: string };
  originalReceiptId: string;
  provenance: "observed";
}

/** A later provider read, observed by the gateway, linked to the original signed, logged operation. */
export interface ReconciliationEvidence {
  original: ReceiptBundle | AuthorizationBundle;
  lookup: { tool: string; args: Record<string, unknown>; statusPath: string; identityPath: string; confirmed: string[]; failed: string[] };
}

export interface ReceiptPredicate {
  receiptId: string;
  timestamp: string;
  /** `strict` is the gateway's own statement that it ran in strict mode: every call precommitted to a remote, hash-only log, and no outbox */
  issuer: { kind: IssuerKind; keyid: string; version: string; framework?: string; strict?: boolean };
  principal: { id: string; keyid: string; provenance: "attested" } | { id: string | null; provenance: "claimed" };
  agent: { id: string; provenance: Provenance };
  /** Present on gateway receipts. Absent when the issuer had no signed grant to check against. */
  delegation?: { envelope: Envelope; provenance: "attested" };
  /** The gateway's payload-bound human approval check, when this tool requires approval. */
  approval?: ApprovalRecord;
  /** Correlation ids from the host, when it supplied any. Never checked, always claimed. */
  session: { id: string | null; toolUseId: string | null; provenance: "claimed" };
  model: { id: string | null; provenance: "claimed" };
  /** upstream names which of several upstreams served the tool; absent when the gateway has one */
  tool: { name: string; provenance: Provenance; upstream?: string };
  /** `args` as the receipt carries them; `argsDigest` is over the whole call's arguments, salted from the field salts when any are withheld. Withheld fields hold commitments. */
  request: { args: Record<string, unknown>; argsDigest: string; provenance: "claimed" };
  facts: Record<string, FactRecord>;
  /**
   * Fact ids the agent had been shown, through this gateway, by the time of this call: every id an upstream declared
   * in its result _meta under "agent-custody/facts" on an earlier call in the session. Observed, because the gateway
   * saw those results itself. Absent on SDK receipts. This is what the agent relied on, as an upper bound.
   */
  consumed?: { factIds: string[] | Commitment; provenance: "observed" };
  /** null when the issuer evaluated no policy. Under a capture rule a non-empty `errors` is a commitment: the evaluator's messages can repeat a withheld value. */
  policy: (Omit<PolicyDecision, "errors"> & { errors: string[] | Commitment; provenance: Provenance }) | null;
  /**
   * Present when the tool is one the gateway treats as consequential: the authorization statement it committed to the
   * log before forwarding the call, with that leaf's inclusion proof and tree head. A verifier checks that it names
   * this receipt, this tool, and these arguments, and that its leaf precedes the receipt's. Without it, evidence of a
   * side effect exists only after the side effect.
   */
  authorization?: AuthorizationBundle;
  operation?: OperationEvidence;
  /** The provider read's full result is execution.result and follows the ordinary result capture rule. */
  reconciliation?: ReconciliationEvidence;
  execution:
    | {
        status: "executed" | "failed";
        /** the result as the receipt carries it; `resultDigest` is over the whole result, salted from the field salts when any are withheld */
        result: unknown;
        resultDigest: string;
        provenance: Provenance;
        /** an upstream's own signature over what it returned, bound to this receipt and checked with the upstream's key; or a provider's delivery, checked with the provider's shared secret */
        upstream?: UpstreamEvidence;
      }
    | { status: "denied"; reason: string | Commitment; provenance: Provenance }
    | { status: "error"; error: string | Commitment; provenance: Provenance }
    /** the policy allowed the call but the gateway did not forward it, because the log would not commit the authorization first */
    | { status: "withheld"; reason: string | Commitment; provenance: Provenance };
  /**
   * Private evidence: present when a capture rule withheld anything. Names every path in this predicate that holds a
   * commitment in place of its value, and the mode. A verifier trusts this note, not the shape of the data.
   */
  capture?: CaptureNote;
}

/** What the gateway commits before a consequential call goes out: everything the receipt will say, except the outcome. */
export type AuthorizationPredicate = Pick<ReceiptPredicate, "receiptId" | "timestamp" | "issuer" | "principal" | "agent" | "delegation" | "approval" | "tool" | "request" | "facts" | "consumed" | "policy" | "capture" | "operation">;

export interface AuthorizationStatement {
  _type: "https://in-toto.io/Statement/v1";
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: typeof AUTHORIZATION_PREDICATE_TYPE;
  predicate: AuthorizationPredicate;
}

/** The committed authorization: the same three parts as a receipt bundle. Written to `receipts/<receiptId>.authorization.json` and embedded in the receipt. */
export interface AuthorizationBundle {
  envelope: Envelope; // signed AuthorizationStatement
  treeHead: Envelope;
  inclusion: InclusionProof;
}

export function buildAuthorizationStatement(p: AuthorizationPredicate): AuthorizationStatement {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: `tool-call:${p.tool.name}:${p.receiptId}`, digest: { sha256: p.request.argsDigest } }],
    predicateType: AUTHORIZATION_PREDICATE_TYPE,
    predicate: p,
  };
}

export interface ReceiptStatement {
  _type: "https://in-toto.io/Statement/v1";
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: typeof RECEIPT_PREDICATE_TYPE;
  predicate: ReceiptPredicate;
}

export interface TreeHead {
  treeSize: number;
  rootHash: string;
  timestamp: string;
  /** which log this head belongs to, when the log serves more than one; a verifier told which log to expect checks it */
  log?: string;
}

/** What gets written to disk and handed to a verifier. Self-contained apart from public keys. */
export interface ReceiptBundle {
  envelope: Envelope; // signed ReceiptStatement
  treeHead: Envelope; // signed TreeHead
  inclusion: InclusionProof;
}

export function buildStatement(p: ReceiptPredicate): ReceiptStatement {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: `tool-call:${p.tool.name}:${p.receiptId}`, digest: { sha256: p.request.argsDigest } }],
    predicateType: RECEIPT_PREDICATE_TYPE,
    predicate: p,
  };
}
