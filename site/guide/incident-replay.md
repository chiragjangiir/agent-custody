# An incident replay: the agent runs terraform destroy

A coding agent has your shell. One bad command deletes a cloud stack, a database, or a home directory. This page replays that moment with a script and shows what the policy does. The replay needs no model and no network. It does not run any destructive command.

## Run it

```bash
git clone https://github.com/svayatta/agent-custody
cd agent-custody && bun install
cd packages/receipts && node examples/38-incident-replay.ts
```

The script makes the same setup as the one-command setup, in a temporary home and a temporary project:

1. It calls `initClaudeCode({ enforce: true })`, the function behind `init claude-code --enforce`. The script does not parse the command-line flags. This makes the agent key, the starter deny set, and the three Claude Code hooks. In enforce mode, the policy blocks a denied call.
2. It plays the Claude Code side. For each tool call, it runs the hook command from `settings.json`, with the event on stdin, and reads the answer on stdout.
3. It does not run the commands of the agent. A stub records which calls the hook lets through.

## What it prints

```text
1. set up the hooks in enforce mode, in a temporary home and a temporary project
   events: PreToolUse, PostToolUse, PostToolUseFailure
   mode: enforce

2. the agent runs: terraform plan
   the hook lets the call through, the command runs, and the hook records an executed receipt

3. the agent runs: terraform destroy -auto-approve
   denied before it runs. Claude Code shows the agent this text:
   agent-custody denied this call: terraform destroy deletes infrastructure (rule policy5, receipt e0ba0f2f-e377-4c2b-8d05-2d7acdfbf7dc)
   that rule, in policy.cedar: forbid(principal, action == Action::"Bash", resource) when { context.args has command && context.args.command like "*terraform destroy*" };

4. the agent runs: rm -rf ~
   denied before it runs. Claude Code shows the agent this text:
   agent-custody denied this call: rm -rf on the home directory (rule policy3, receipt e7a11b73-77d2-4b03-8f81-b9a20707d755)
   that rule, in policy.cedar: forbid(principal, action == Action::"Bash", resource) when { context.args has command && ( context.args.command like "*rm -rf ~" || context.args.command like "*rm -rf ~ *" || context.args.command like ...

5. a reviewer verifies offline: they hold the agent's public key and the receipt files, and nothing else
   34b9a0ac-10cc-46df-9b6e-8c3f94147d0d  VERIFIED (13 checks)  executed  decision allow  terraform plan
   e0ba0f2f-e377-4c2b-8d05-2d7acdfbf7dc  VERIFIED (12 checks)  denied    decision deny  terraform destroy -auto-approve
   e7a11b73-77d2-4b03-8f81-b9a20707d755  VERIFIED (12 checks)  denied    decision deny  rm -rf ~

6. the same receipt checked against a key that is not the agent's does not verify
   receipt signature (issuer key): FAIL. RESULT: NOT VERIFIED

OK
```

The receipt ids differ on each run.

## What happened

- `terraform plan` got no decision from the hook, so the command runs. The hook records an executed receipt after the run.
- `terraform destroy -auto-approve` matched a `forbid` rule of the starter policy. The hook answered `deny` before the command ran. The text after "Claude Code shows the agent this text" is the reason that Claude Code gives to the agent. It says what the rule forbids (the `@reason` of the rule), and it names the rule (`policy5`) and the receipt id.
- `rm -rf ~` matched another `forbid` rule. The hook denied it the same way.
- The reviewer in step 5 has two things: the agent's public key and the receipt files. They check the signature and the structure of each receipt offline. The two denials show `denied` as the execution and `deny` as the decision. The receipt says that the policy was in force, not in observe mode (`enforced` is not `false`). That statement is `claimed`: the agent's own process writes it, and the signature shows only that it did not change. The inclusion proof is against the agent's own local log, and the agent's own key signs the tree head of that log. So the proof adds nothing to the signature. A log that another party runs would add that.
- In step 6, a key that is not the agent's does not verify the same receipt.

To run the same policy on your own sessions, use [the one-command setup](/guide/getting-started#claude-code-in-one-command). It starts in observe mode: nothing is blocked, and `agent-custody report` lists the calls that the policy would have denied. To enforce, remove one line from `sdk.json`.

## The limit

Read this part before you rely on the hook.

A credential inside the agent's environment goes around the hook. Suppose the shell of the agent holds an AWS key, a Terraform token, or a database password. Any process that the agent starts can use it. The hook stops a call that the agent makes through its tools. It does not stop a process that the agent starts and that uses the credential directly. For example, the agent writes a script and runs it, and the script calls the cloud API. The hook sees the call that starts the script. It does not see what the script does.

The starter policy matches the text of a command. It catches the plain form of each command. It does not catch a command that the agent writes in another way, for example with a variable or inside a script file. It is not a sandbox. The starter policy also catches `terraform apply -destroy`, which deletes the same stack as `terraform destroy`. It does not catch `terraform -chdir=infra destroy`, because the text between `terraform` and `destroy` breaks the pattern.

The Cedar `like` operator has one wildcard, `*`. It cannot find where one shell command ends, and it cannot read shell words. So the limit has these parts:

- A force push is caught as `--force`, `-f`, or `+refspec` (`git push origin +main`), also in the form `git -C repo push --force`. A flag counts when it is the first argument after `push`, when no `&`, `|`, `;`, or newline follows `push`, or when one of them follows the flag. A flag in a later command of a chain passes, so `git push origin main && npm install --force` runs. A chain with two operators after `push` is denied by mistake.
- `rm -rf` on `/`, `~`, and `$HOME` is caught with the flags `-rf`, `-fr`, `-Rf`, `-fR`, `-r -f`, and the like, and with `$HOME` in double quotes. `rm --recursive --force /`, `rm --no-preserve-root -rf /`, and a path that reaches the directory in another way (`rm -rf /usr/..`) pass.
- A force push that the git configuration or an alias sets is not in the text of the command.

Use a sandbox or a protected branch for these. The rule ids stay the same when the starter policy grows: a change goes in the rule, and a new rule goes at the end of the file. The ids `policy3` and `policy5` on this page keep naming the same rules.

An in-process receipt is the agent's own report. Every field in it is `claimed`. The signature shows that the receipt did not change after the hook issued it. It does not show that the hook saw every call. It does not show that anyone outside the agent's process checked the call. Step 5 shows that the receipts are intact. It does not show that the agent had no other way to act.

To cover more, keep production credentials out of the agent's environment. Put a gateway between the agent and the tools that touch production. Lock down the agent's network, so that a connection around the gateway goes through the egress witness and gets a receipt of where it went, never of what it sent: [credential custody and egress lockdown](/guide/credential-custody). The [threat model](/receipts/threat-model) lists what each part defends and what it does not.

## Next

- [Getting started](/guide/getting-started): the one-command setup for Claude Code.
- [Claude Code and the Agent SDK](/reference/claude-code): the options and the hook contract.
- [Threat model](/receipts/threat-model): what a receipt proves, and what it does not.
