# What a receipt costs

A receipt adds a policy decision, two Ed25519 signatures, and a log append to a tool call. This page says how long each step takes on one machine, how to measure it on yours, and what is written to disk.

## Measuring it

From `packages/receipts`:

```bash
bun run bench
```

This runs `scripts/hot-path-bench.ts` (`node scripts/hot-path-bench.ts [iterations]`, default 20,000 after 2,000 warm-up). It is not part of `ci`. Each iteration issues one receipt the way the issuer does, and times each step on its own:

| step | what it times |
| --- | --- |
| cedar evaluate | `evaluate()` on the fixture's Cedar policy. The requests vary by tool, amount, customer, and verification, so a decision cache could not answer them from one entry. |
| receipt signature | `dsseSign` over a receipt statement |
| log append (all) | `MerkleLog.append` on a local file: the lock, reading what other writers appended, the torn-tail check, the write, and the Merkle push, inclusion proof, and root |
| of which Merkle | the push, proof, and root alone, on an in-memory copy of the tree |
| tree-head signature | `dsseSign` over the new tree head |
| rego evaluate (alternative) | the same requests decided by the same policy in Rego, compiled once with `opa build`. The script checks that both engines give the same decision for each request. It is skipped when `opa` is not on `PATH`. |

The reference rows time a bare `appendFileSync`, a bare write on a descriptor held open, and the lock owner stamp (see below). There is no network and no fsync. The script writes to a temporary directory and removes it. The site's three numbers (a decision, a gateway call, a verification) come from `scripts/bench.ts`.

## On one machine

An Apple M5 laptop, macOS, Node 22.21.1, 9 November 2026, 20,000 receipts per run, means and medians in microseconds. The two runs were interleaved on a machine that was also running other work (load average about 5).

| step | before, mean | before, p50 | after, mean | after, p50 |
| --- | --- | --- | --- | --- |
| cedar evaluate | 196.5 | 187.8 | 85.9 | 78.8 |
| receipt signature | 30.4 | 26.9 | 29.7 | 25.5 |
| log append (all) | 1392.5 | 1305.6 | 1308.6 | 1218.9 |
| of which Merkle | 10.9 | 9.5 | 9.7 | 8.4 |
| tree-head signature | 26.1 | 23.1 | 25.0 | 21.7 |
| rego evaluate (alternative) | 11.3 | 10.0 | 10.0 | 8.4 |
| appendFileSync (reference) | 22.8 | 19.5 | 28.1 | 24.1 |
| write on open fd (reference) | 5.0 | 4.4 | 4.4 | 3.3 |
| lock owner stamp (reference) | 1170.2 | 1095.8 | 1124.8 | 1054.4 |

A second interleaved pair agreed: Cedar went from a mean of 178.1 µs to 91.8 µs, and the log append stayed at about 1.3 ms.

What changed:

- **Cedar parses each policy once.** `evaluate()` used to hand the policy text to Cedar on every call, so Cedar parsed the whole file for every decision, and the text was hashed for the digest every time. Each text is now parsed once with `preparsePolicySet`, and decided with `statefulIsAuthorized`. The cache is keyed by the text, so an edited file is parsed again and gets its new digest. It holds 8 policy sets and evicts the least recently used, only after the new set is in place, and a new text never takes a slot that a live entry holds. A text that does not parse is a deny with Cedar's errors, as before.
- **The log keeps its file open.** An append used to open and close the file. The log now keeps one descriptor open for append. It reopens the file when a prune has replaced it, when the file was removed, and after a failed write. On this machine the saving, about 20 µs, is smaller than the run-to-run spread of the lock, so the table cannot show it. The reference rows show the write itself.

Rego needed no change: a `.rego` file is compiled once per change, and the gateway passes the digest it computed when the file loaded.

## Where the rest of the time goes

On macOS most of a log append is the lock that keeps the processes writing one log in order. Its owner record carries the process's start time, so that a later process with the same PID is not taken for the owner. On Linux that comes from `/proc/<pid>/stat`. macOS has no `/proc`, so each append runs `ps` (about 1.1 ms). A gateway on Linux does not pay this. This is not changed here.

No decision is cached, only the parsed policy. Receipts are signed and appended before the call returns, never after: `authorize` never defers, strict mode defers nothing, and a financial operation's receipt does not defer (see the security invariants in `CONTRIBUTING.md`).

## What is on disk when an append returns

The log line has been written to the file with `O_APPEND`, so it is in the operating system's page cache. Nothing fsyncs the log: neither `appendFileSync` before nor the held descriptor now. A process crash loses nothing that was acknowledged. A power failure or a kernel crash can lose the last appends. A line cut short by a writer that died during its write is moved to `<log>.torn` by the next append, and that leaf was never acknowledged.

Some other files are fsynced: the issuer writes a receipt it keeps in the outbox with `fsync` on the file and its directory, and an approval's single-use record is synced the same way. A receipt bundle, its authorization file, its salts, and the log are not.
