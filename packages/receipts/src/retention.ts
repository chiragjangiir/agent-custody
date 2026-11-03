// Retention on the receipt log. A receipt's request arguments and results hold values, and the log is append-only and
// hashed, so values cannot simply be deleted. Pruning replaces a leaf's content in the log file with its leaf hash:
// the Merkle tree, every root, and every inclusion and consistency proof for the remaining leaves are unchanged, while
// the pruned receipt's content is gone from the log and its bundle file is removed. A verifier holding a pruned
// receipt's bundle can still prove inclusion; nobody holding only the log can recover what the receipt said.
import { appendFileSync, existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Envelope } from "./crypto.ts";
import { leafHash, logLocked } from "./log.ts";

/** where the issuer keeps the salts behind a receipt's commitments, under the receipts directory; private, pruned with the receipt */
export const SALTS_DIR = "salts";
/** a receipt id as the issuer mints it; anything else never becomes part of a path */
export const RECEIPT_ID = /^[A-Za-z0-9-]{1,64}$/;
/** the salts file of a receipt, or a throw when the id (which may come from a bundle or a log line) is not one */
export function saltsFileFor(receiptsDir: string, receiptId: string): string {
  if (!RECEIPT_ID.test(receiptId)) throw new Error(`receipt id ${JSON.stringify(receiptId)} is not a valid id`);
  return join(receiptsDir, SALTS_DIR, `${receiptId}.json`);
}

export interface PruneResult {
  pruned: { leafIndex: number; receiptId: string | null; timestamp: string | null }[];
  kept: number;
  bundlesRemoved: number;
}

function receiptOf(leaf: string): { receiptId: string | null; timestamp: string | null } {
  try {
    const env = JSON.parse(leaf) as Envelope;
    const st = JSON.parse(Buffer.from(env.payload, "base64").toString()) as { predicate?: { receiptId?: string; timestamp?: string } };
    return { receiptId: st.predicate?.receiptId ?? null, timestamp: st.predicate?.timestamp ?? null };
  } catch {
    return { receiptId: null, timestamp: null };
  }
}

/**
 * Prunes every leaf whose receipt timestamp is before the cutoff. Leaves already pruned, and leaves that are not
 * receipts, are left as they are. Rewrites the log file in place and deletes the pruned receipts' bundle files, and
 * the salts the issuer kept for them. It holds the log lock, so a receipt that a hook appends during the prune is not lost.
 */
export function pruneLog(logFile: string, before: string, receiptsDir?: string): PruneResult {
  return logLocked(logFile, () => pruneLocked(logFile, before, receiptsDir));
}

function pruneLocked(logFile: string, before: string, receiptsDir?: string): PruneResult {
  let text = readFileSync(logFile, "utf8");
  const whole = text.lastIndexOf("\n") + 1;
  if (whole < text.length) {
    // the remains of a writer that died in its write: kept apart, as an append keeps them
    appendFileSync(`${logFile}.torn`, text.slice(whole), { mode: 0o600 });
    text = text.slice(0, whole);
  }
  const lines = text.split("\n").filter((l) => l.trim());
  const out: string[] = [];
  const result: PruneResult = { pruned: [], kept: 0, bundlesRemoved: 0 };
  lines.forEach((line, i) => {
    const parsed = JSON.parse(line) as string | { pruned: string };
    if (typeof parsed !== "string") {
      out.push(line);
      return;
    }
    const { receiptId, timestamp } = receiptOf(parsed);
    if (timestamp !== null && timestamp < before) {
      out.push(JSON.stringify({ pruned: leafHash(parsed).toString("hex") }));
      result.pruned.push({ leafIndex: i, receiptId, timestamp });
      // the id comes from a log line: it never becomes part of a path unless it is one the issuer could have minted
      if (receiptsDir && receiptId && RECEIPT_ID.test(receiptId)) {
        const bundle = join(receiptsDir, `${receiptId}.json`);
        if (existsSync(bundle)) {
          unlinkSync(bundle);
          result.bundlesRemoved++;
        }
        const salts = saltsFileFor(receiptsDir, receiptId);
        if (existsSync(salts)) unlinkSync(salts);
        // the authorization committed before the call carries the same call: it goes too
        const authorization = join(receiptsDir, `${receiptId}.authorization.json`);
        if (existsSync(authorization)) unlinkSync(authorization);
      }
    } else {
      out.push(line);
      result.kept++;
    }
  });
  const tmp = `${logFile}.tmp`;
  writeFileSync(tmp, out.join("\n") + "\n");
  renameSync(tmp, logFile);
  return result;
}
