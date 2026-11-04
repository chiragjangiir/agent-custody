// The comment step of action.yml. The test runs the script of the action with a fake `gh` and a fake `npx` on the PATH,
// so it needs no network. The fake `gh` applies the --jq filter of the action to a list of comments that the test gives.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const MARKER = "<!-- agent-custody -->";
const BOT = "github-actions[bot]";

/** The `run:` script of the action, taken from the file as it is. */
function actionScript(): string {
  const lines = readFileSync(join(import.meta.dirname, "..", "..", "..", "action.yml"), "utf8").split("\n");
  const start = lines.findIndex((l) => /^ {6}run: \|$/.test(l));
  const body: string[] = [];
  for (const l of lines.slice(start + 1)) {
    if (l.trim() !== "" && !l.startsWith(" ".repeat(8))) break;
    body.push(l.slice(8));
  }
  return body.join("\n");
}

/** Runs the script on a pull request with the given comments. Returns the calls that it made to `gh`. */
function run(comments: { id: number; login: string; body: string }[], author = BOT): string[] {
  const dir = mkdtempSync(join(tmpdir(), "action-"));
  const bin = join(dir, "bin");
  mkdirSync(bin);
  const calls = join(dir, "calls.txt");
  writeFileSync(calls, "");
  writeFileSync(join(dir, "comments.json"), JSON.stringify(comments.map((c) => ({ id: c.id, user: { login: c.login }, body: c.body }))));
  writeFileSync(
    join(bin, "gh"),
    `#!/usr/bin/env bash
echo "$*" >> "$CALLS"
expr=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--jq" ]; then expr="$2"; fi
  shift
done
if [ -n "$expr" ]; then jq -r "$expr" "$COMMENTS"; fi
`,
  );
  writeFileSync(join(bin, "npx"), `#!/usr/bin/env bash\nprintf '%s\\n## agent-custody receipts\\n\\n**Verified.**\\n' '${MARKER}'\n`);
  chmodSync(join(bin, "gh"), 0o755);
  chmodSync(join(bin, "npx"), 0o755);
  writeFileSync(join(dir, "script.sh"), actionScript());
  const r = spawnSync("bash", [join(dir, "script.sh")], {
    encoding: "utf8",
    timeout: 30_000,
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      CALLS: calls,
      COMMENTS: join(dir, "comments.json"),
      RUNNER_TEMP: dir,
      GITHUB_STEP_SUMMARY: join(dir, "step-summary.md"),
      INPUT_PATH: "receipts",
      INPUT_ISSUER_KEY: "issuer.pub",
      INPUT_PRINCIPAL_KEY: "",
      INPUT_LOG_URL: "",
      INPUT_LOG_ID: "",
      INPUT_VERSION: "0.0.0",
      GH_TOKEN: "unused",
      COMMENT_AUTHOR: author,
      REPO: "owner/repo",
      PR_NUMBER: "7",
    },
  });
  expect(r.status, r.stderr).toBe(0);
  return readFileSync(calls, "utf8").split("\n").filter((l) => l.includes("--method"));
}

describe("the comment step of the action", () => {
  const bot = { id: 1, login: BOT, body: `${MARKER}\nold result` };
  const stranger = { id: 2, login: "mallory", body: `${MARKER}\nVerified. Nothing to see here.` };

  it("edits its own comment, and not a later comment from another user that starts with the marker", () => {
    const calls = run([bot, stranger]);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/^api --method PATCH repos\/owner\/repo\/issues\/comments\/1 /);
  });

  it("posts a new comment when the only comment with the marker is from another user", () => {
    const calls = run([stranger]);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/^api --method POST repos\/owner\/repo\/issues\/7\/comments /);
  });

  it("edits the comment of the account named in comment-author", () => {
    const calls = run([bot, { id: 3, login: "ci-user", body: `${MARKER}\nold result` }], "ci-user");
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/^api --method PATCH repos\/owner\/repo\/issues\/comments\/3 /);
  });
});
