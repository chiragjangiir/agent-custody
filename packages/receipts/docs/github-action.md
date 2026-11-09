# Verifying receipts on a pull request

A pull request is where a team reviews the work of an agent. The GitHub Action in this repository verifies the receipts of that work and puts the result on the pull request. A reviewer sees the result and installs nothing. The action is listed on the GitHub Marketplace as [agent-custody receipts](https://github.com/marketplace/actions/agent-custody-receipts).

The action runs `agent-custody verify --markdown` on a directory of receipt bundles. It writes one table to the job summary. On a pull request it also posts the same table as one comment, and it edits that comment on each later push. The `agent-custody export` command puts the receipts into the branch, and it refuses a receipt that publishes the call.

## The workflow file

Copy this file to `.github/workflows/receipts.yml`.

```yaml
name: receipts
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: svayatta/agent-custody@<commit sha of the release> # 0.16.0
        with:
          path: .custody/receipts
          issuer-key: .custody/keys/agent.pub
```

Pin the action to the commit of a release, as you pin every other action. A moving tag lets a third party change what runs with your token.

## The inputs

| input | meaning | default |
| --- | --- | --- |
| `path` | a directory of receipt bundles; the action reads the `.json` files in it, not `<id>.authorization.json` files, not symbolic links, and not subdirectories | `.custody/receipts` |
| `issuer-key` | the public key files of the issuers you trust, one path on each line (required) | |
| `principal-key` | the public key files of the principals whose grants a gateway receipt carries, one path on each line; SDK and Claude Code hook receipts need none | |
| `log-url` | the URL of the log; the action fetches the log key from it (`verify --log-url`) | |
| `log-id` | the id that every tree head must name (`verify --log-id`) | |
| `version` | the `@agent-custody/receipts` version that `npx` runs | `0.16.0` |
| `github-token` | a token that can write pull request comments | `github.token` |
| `comment-author` | the login of the account that `github-token` posts as; the action edits only a comment from this account | `github-actions[bot]` |

## What the action does

1. It sets up Node 22 and runs `npx @agent-custody/receipts@<version> verify --markdown <path> --issuer-key ...`.
2. It writes the table to `$GITHUB_STEP_SUMMARY`.
3. On a `pull_request` event, it looks for an earlier comment that starts with `<!-- agent-custody -->` and that the account in `comment-author` posted, and it edits that comment. When there is none, it posts a new comment.
4. It fails the step when one receipt does not verify, and when the directory holds no receipt.

Any user can post a comment that starts with the marker line. The action ignores such a comment, because the author does not match. If you give `github-token` the token of a user or of an app, set `comment-author` to the login of that account. With the wrong login, the action does not find its own comment, and it posts a new comment on each push.

When the token cannot write a comment, the action prints a warning and keeps the job summary. This is the case for a pull request from a fork, where GitHub gives the `pull_request` event a read-only token. The step does not fail for that reason. Do not switch to `pull_request_target` to get the comment. That event gives a write token to a workflow that handles code from the fork.

The table has one row for each receipt. The failed rows come first.

| Receipt | Tool | Status | Result |
| --- | --- | --- | --- |
| `981d2afd-63f2-49ed-854a-83fc1bf1c035` | - | - | `receipt signature (issuer key)` |
| `6e2de8f3-4e51-43e5-af8b-a2b283dd7709` | `stripe.refund` | executed | verified |

- `Status` is the execution status in the signed receipt: `executed`, `denied`, `failed`, `error`, or `withheld`. When the signature does not verify, the table shows `-`, because nothing in that receipt is trusted.
- `Result` is `verified`, or the names of the checks that failed. [Verifying a receipt](verification.md#what-each-check-means) explains each check.
- A file that is not valid JSON shows `not a JSON file`, and a file with the wrong shape shows `not a receipt bundle`. The table never shows text from the file, because anyone who can change the branch can choose the file. The action does not read a symbolic link in `path`, so a link cannot bring a file from the runner into the comment.
- `verify --markdown` follows a symbolic link when the link is the file argument or the directory argument itself, but not a link inside the directory. The table shows only fixed error text or verified fields, so a followed link shows no text from its target.
- A file whose name is not `<receipt id>.json` fails with `file name matches receipt id`. A valid receipt under the name of another receipt could hide that receipt.
- The table shows 200 rows at most. Every failed row is in it.

## What the table proves, and what it does not

A `verified` row proves that the issuer key you gave signed the receipt, that the receipt has not changed since, and that its checks hold. It does not prove that the receipts are all the calls the agent made. The author of the pull request chooses which receipts to commit. [Completeness](completeness.md) answers that question from the provider's side.

Keep the key files out of reach of the pull request. With the `pull_request` event, the workflow checks out the merge of the pull request. An author who changes `.custody/keys/agent.pub` in the same pull request can sign a receipt with a key of their own. Protect the key path with a code owner rule, or keep the key in a repository that the author cannot change.

## How receipts get into the pull request

Receipts stay on the machine of the developer, in the `receiptsDir` of the gateway or the SDK. The action reads a directory in the checkout, so the receipts you want reviewed must be in the branch. The `export` command puts them there.

```bash
agent-custody export --receipts ~/.config/agent-custody/receipts --out .custody/receipts \
  --issuer-key .custody/keys/agent.pub --since 2026-11-02T09:00:00Z
git add .custody/receipts
```

The command prints one line for each receipt, then a count.

```
copied  6e2de8f3-4e51-43e5-af8b-a2b283dd7709.json
refused 981d2afd-63f2-49ed-854a-83fc1bf1c035.json: args and result in clear: a capture rule must withhold it (or give --allow-clear)
skipped 0b7c5f6e-93f7-4f06-a1f1-2f8d2d5f63a0.json: issued 2026-11-01T17:02:11.480Z, before --since
1 copied, 1 refused, 1 skipped
```

| flag | meaning |
| --- | --- |
| `--receipts <dir>` | the receipts directory of the machine |
| `--out <dir>` | where the copies go; the command creates it when it copies a receipt |
| `--issuer-key <pub>` | the public key of the issuer; repeat it for more than one issuer (required) |
| `--principal-key <pub>` | the public key of a principal whose grant a gateway receipt carries; SDK and Claude Code hook receipts need none |
| `--approval-key <pub>` | the public key of an approver, for a gateway receipt that carries approval evidence |
| `--since <ISO time>` | keep the receipts issued at or after this time, for example the start of the branch |
| `--allow-clear` | copy a receipt that carries plain values; see the warning below |

What the command does, in this order, for each file:

1. It reads only the `<id>.json` files at the top level of `--receipts`. It never reads or copies `salts/`, `outbox/`, `*.authorization.json`, a subdirectory, a symbolic link, or any other file.
2. It verifies the receipt with the issuer key. It refuses a receipt that does not verify, and a receipt whose file name is not its signed receipt id (`file name matches receipt id`, as the action does). `--issuer-key` is required, because the next step trusts what the signed receipt says about its own capture. An unverified file can claim anything.
3. It skips a receipt issued before `--since`. A skipped receipt is not a failure.
4. It runs the privacy check below. It refuses a receipt that fails the check.
5. It copies the file byte for byte. It never rewrites a receipt, because the signature covers it. It writes nothing to `--out` for a refused or a skipped receipt.

The command exits 1 when it refuses any receipt, and when it copies none. The other receipts are still copied. A file in the directory with a `.json` name that is not a receipt bundle is refused as well.

### The privacy check

The signed receipt has a capture note. The note lists the paths that hold a commitment in place of the value. The check reads the note, and it refuses a receipt when a side that holds data has no withheld path under it. The sides are the arguments (`request.args`), the result (`execution.result`, with the error message and the denial reason), and the value of each fact (`facts.<name>.value`). The command prints the sides in the reason, for example `args and result in clear`.

A field that a rule lists in its `clear` list stays in clear on purpose, so the check allows it when the rule withholds the other fields of that side. An empty side is not data.

`--allow-clear` turns the check off. The command then copies the receipt, marks it `(plain values: args, result)`, and prints this warning on standard error: each receipt marked with plain values publishes its arguments or its result to everyone who can read the output directory.

The check has limits. Read them before you rely on it.

- A receipt cannot be redacted after it is issued. The arguments and the result are signed as they are, and a change breaks the signature. Only a capture rule at issue time keeps a value out of the receipt. A receipt that an agent made before you set the rule stays in clear. Use `--since` to leave it out.
- A side whose every field is on the `clear` list has nothing left to withhold, so it has no commitment. The check cannot tell it from a side in mode `clear`, and it refuses it. A `Bash` call with the argument `command` alone is such a side under the second rule below. Read the receipt, and give `--allow-clear` if you accept it.
- The check does not look inside a value that the rule keeps in clear. The command text of a `Bash` call can hold a secret as well, for example a token in a `curl` header or in an `export` line. Keep a field in clear only when you accept that a reader sees all of it.
- The tool name, the ids, the timestamps, the status, and the policy decision always stay in clear.

### A committed receipt publishes the call

By default a receipt carries the call in plain text. It holds the arguments the agent sent and the result the tool returned. For a `Bash` call that is the command and its output. For a file tool it is the content of the file. Anyone who can read the repository can read these values. If the repository is public, everyone can.

Before you commit a receipt, check these points.

1. Set a capture rule before the session starts. A `capture` rule in the gateway config or in the SDK config (`sdk.json`) withholds a side of the call. With mode `digest`, the receipt holds one commitment over the fields you do not list in `clear`. With mode `encrypted`, it holds the same commitment and the value encrypted under a key that only you hold (`captureKeyEnv`). The rule applies to the receipt, to the log, and to every exporter. [Private evidence](usage.md#private-evidence) has the full rules. Two rules follow.

   The strict rule. Every tool, every side, in mode `digest`. A reviewer sees the tool name, the status, and the decision of each call, and no value.

   ```json
   "capture": {
     "*": { "args": { "mode": "digest" }, "result": { "mode": "digest" }, "facts": { "mode": "digest" } }
   }
   ```

   The rule that shows the commands. The `command` argument of `Bash` stays in clear, and the result is in mode `digest`. A reviewer sees what the agent ran, and not what it printed. Every other tool takes the strict rule from `"*"`.

   ```json
   "capture": {
     "*": { "args": { "mode": "digest" }, "result": { "mode": "digest" }, "facts": { "mode": "digest" } },
     "Bash": { "args": { "mode": "digest", "clear": ["command"] }, "result": { "mode": "digest" } }
   }
   ```

   The second rule has a cost. The command text can hold a secret: a token on a command line, a password in a connection string, a path that names a customer. The rule publishes that text. In the second rule the other arguments of `Bash` (`description`, `timeout`) are withheld together in one commitment. Use the strict rule when you cannot read every command.

2. Run `agent-custody export` instead of a copy by hand. It leaves `salts/`, `outbox/`, `*.authorization.json`, and a local `log.jsonl` behind. The salts let a reader confirm a guess of a withheld value, and the authorization files and the log hold the call data as well. Never copy these files into a branch.
3. Keep the capture key out of the repository and out of the workflow. The action needs no key. A receipt with withheld values verifies as committed, and the table still shows the tool and the status, because those parts stay in clear.
4. Read one exported receipt before the first push. Run `agent-custody verify <file> --issuer-key <pub>` and read the `args` and `execution` rows.

A reviewer who needs a withheld value asks the owner of the key for a disclosure (`agent-custody reveal`), and verifies it with `verify --disclose`.

If you set up the Claude Code hook with `agent-custody init claude-code`, the `sdk.json` that it writes has no `capture` rule. Add the rule to that file before the session, and run `export` on the `receipts` directory next to it.

An agent that runs inside the CI job needs no transport. Write its receipts in the job and run the action in the same job.
