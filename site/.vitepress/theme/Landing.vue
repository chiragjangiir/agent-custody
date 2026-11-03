<script setup lang="ts">
// The product's front door, outside the docs theme. It speaks to one reader: an engineer who runs a coding agent, such
// as Claude Code, against a repository or a system that touches production. The order is the command, what the user
// sees (the report), the incident replay, how a reviewer checks the record, and the limits of the hook. Everything else
// is on /advanced. The word "receipt" comes after the page shows what a receipt does. The terminal text below is
// real output: the report is from tutorial 36, and the replay is from tutorial 38 (packages/receipts/examples). Colours
// are tokens on .landing. Light and dark share the names. Every section uses the same 1200px container, so all left
// edges line up.
import { onBeforeUnmount, ref } from "vue";
import { useData } from "vitepress";

const { isDark } = useData();
const year = new Date().getUTCFullYear();

const repo = "https://github.com/svayatta/agent-custody";
const commands = ["npm install -g @agent-custody/receipts", "agent-custody init claude-code"];
const command = commands.join("\n");
const tryCommand = "npx @agent-custody/receipts init claude-code";
const setupHref = "/guide/getting-started#claude-code-in-one-command";

// The Copy button shows "Copied" for 1.5 seconds. The id says which of the two command boxes was used.
// When the browser refuses the clipboard, the button says "Copy failed" and a note asks the visitor to select the text.
const copied = ref("");
const failed = ref("");
let copyTimer: ReturnType<typeof setTimeout> | undefined;
async function copy(id: string) {
  let ok = true;
  try {
    await navigator.clipboard.writeText(command);
  } catch {
    ok = false;
  }
  copied.value = ok ? id : "";
  failed.value = ok ? "" : id;
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => (copied.value = failed.value = ""), ok ? 1500 : 6000);
}
const label = (id: string) => (copied.value === id ? "Copied" : failed.value === id ? "Copy failed" : "Copy");
onBeforeUnmount(() => clearTimeout(copyTimer));

// The output of `report` after a session of four calls in observe mode (tutorial 36). The path of sdk.json is shortened.
const reportCommand = "agent-custody report --config ~/.config/agent-custody/sdk.json";
const report = `would have denied 2 calls (the policy recorded each one and blocked nothing)

  Bash: git push --force origin main
    reason:  force push rewrites shared history (git push --force-with-lease is allowed)
    rule:    forbid(principal, action == Action::"Bash", resource) when { context.args has command && ( context.args.command like "*git push*--force *" || context.args.command like "*git push*--force" || context.args.command like "*git push -f*" || context.args.command like "*git push* -f" ) } [policy1]
    receipt: 191e1095-db76-45fc-82d4-3dc9a6e14023  (2026-11-02T11:15:18.824Z)

  Bash: terraform destroy -auto-approve
    reason:  terraform destroy deletes infrastructure
    rule:    forbid(principal, action == Action::"Bash", resource) when { context.args has command && context.args.command like "*terraform destroy*" } [policy5]
    receipt: 6f4c2455-b578-4a0f-b7ed-7fee177e5a9b  (2026-11-02T11:15:18.827Z)

Checked 4 receipts: 4 verified, 0 did not verify.

To enforce this policy, remove the "mode": "observe" line from ~/.config/agent-custody/sdk.json. A denied call is then blocked before it runs.`;

// The replay (tutorial 38): the text that Claude Code shows the agent, and the offline check.
const denial = `agent-custody denied this call: terraform destroy deletes infrastructure (rule policy5, receipt 980d078f-2922-42b7-a5de-de3b99b00997)`;
const verified = `6dd02745-62bd-46fa-9866-2e51adc0f682  VERIFIED (13 checks)  executed  decision allow  terraform plan
980d078f-2922-42b7-a5de-de3b99b00997  VERIFIED (12 checks)  denied    decision deny  terraform destroy -auto-approve
095d119e-5da7-4c74-bcc1-c91f0f2873c4  VERIFIED (12 checks)  denied    decision deny  rm -rf ~
the same receipt checked against a key that is not the agent's does not verify
receipt signature (issuer key): FAIL. RESULT: NOT VERIFIED`;

const steps = [
  { t: "Run the command", d: "It makes a key, a starter deny list, and the Claude Code hooks for the current directory." },
  { t: "Work as usual", d: "In observe mode the hook blocks nothing. It records each shell command, file edit, and MCP tool call." },
  { t: "Read the report", d: "It lists each call that the policy would have denied." },
  { t: "Enforce", d: "Remove one line from the config. A denied call then stops before it runs." },
];
const replay = [
  { cmd: "terraform plan", tone: "allow", badge: "Runs", d: "The hook has no objection. The command runs, and the hook records it." },
  { cmd: "terraform destroy -auto-approve", tone: "deny", badge: "Denied", d: "A rule of the deny list matches. The command does not run." },
  { cmd: "rm -rf ~", tone: "deny", badge: "Denied", d: "A second rule matches. The command does not run." },
];
const limits = [
  { t: "A credential in the environment", d: "If the agent's shell holds a cloud key or a database password, a process that the agent starts can use it. The hook stops a call that the agent makes through its tools. It does not stop that process." },
  { t: "The match is on text", d: "The starter list matches the text of a command. It catches the plain form of each command. It is not a sandbox." },
  { t: "Some tools are not seen", d: "The hook matches shell commands, file edits, and MCP tools. It does not see Read, Grep, Glob, WebFetch, WebSearch, or Task. The starter deny list has rules for shell commands only." },
  { t: "The record is the agent's own report", d: "The signature shows that the record did not change after the hook wrote it. It does not show that the hook saw every call." },
];
</script>

<template>
  <div class="landing">
    <header class="nav">
      <div class="wrap">
        <a class="brand" href="/" aria-label="agent-custody home">
          <svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" class="tile" /><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff" /><path d="M25 20h14M25 27h14" class="ink" stroke-width="2.6" stroke-linecap="round" /><path d="M25 37.5l5 4.5 9.5-10" fill="none" class="ink" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" /></svg>
          <span>agent-custody</span>
        </a>
        <nav class="navlinks" aria-label="Site">
          <a href="#report">What you see</a><a href="#replay">Incident replay</a><a href="#limits">Limits</a><a href="/advanced">Advanced</a><a href="/pricing">Pricing</a><a href="/guide/getting-started">Docs</a>
        </nav>
        <div class="right">
          <button class="icon-btn" type="button" aria-label="Switch between light and dark mode" @click="isDark = !isDark">
            <svg class="sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
            <svg class="moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>
          </button>
          <a class="icon-btn" :href="repo" aria-label="agent-custody on GitHub">
            <svg viewBox="0 0 16 16" class="mark" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" /></svg>
          </a>
          <a class="btn sm" href="https://app.agent-custody.dev/">Sign in</a>
        </div>
      </div>
    </header>

    <main>
      <section class="hero">
        <div class="wrap">
          <div>
            <h1>Stop your coding agent from running destructive commands, and keep a signed record that a reviewer can check.</h1>
            <p class="lede">For engineers who run Claude Code against repositories and systems that touch production. One command adds a hook to Claude Code. The hook checks each shell command, file edit, and MCP tool call against a deny list before the call runs. The starter list covers force push, <code>rm -rf</code> on <code>/</code> and <code>~</code>, <code>terraform destroy</code>, and <code>drop database</code>.</p>
            <div class="cmd"><div class="lines"><div v-for="c in commands" :key="c"><span class="prompt" aria-hidden="true">$</span><code>{{ c }}</code></div></div><button type="button" aria-live="polite" @click="copy('hero')">{{ label("hero") }}</button></div>
            <p v-if="failed === 'hero'" class="note" role="status">Copy failed. Select the command and copy it by hand.</p>
            <p class="note">Needs Node 22. It starts in observe mode: nothing is blocked until you say so.</p>
            <p class="note">To try it once, run <code>{{ tryCommand }}</code>. Do not keep the npx form: npm can clear its cache, and the hooks then stop working.</p>
            <div class="ctas">
              <a class="btn primary" href="/guide/incident-replay">See the incident replay</a>
              <a class="btn" :href="setupHref">Setup for Claude Code</a>
            </div>
          </div>

          <article class="denied" aria-label="A Claude Code tool call that the deny list refused">
            <header>
              <div><div class="t">Claude Code · Bash</div><div class="d">enforce mode</div></div>
              <span class="badge deny">Denied</span>
            </header>
            <dl>
              <dt>The agent ran</dt><dd>terraform destroy -auto-approve</dd>
              <dt>Rule</dt><dd>terraform destroy deletes infrastructure</dd>
              <dt>Result</dt><dd>denied before it ran</dd>
              <dt>The agent was told</dt><dd>{{ denial }}</dd>
            </dl>
            <footer><span>From the incident replay. No command ran.</span><a href="/guide/incident-replay">Read the replay →</a></footer>
          </article>
        </div>
      </section>

      <section id="report" class="sec alt">
        <div class="wrap">
          <h2>What you see</h2>
          <p class="sub">Work in Claude Code as usual. The hook signs a record of each shell command, file edit, and MCP tool call. The record is called a receipt. The report checks the signature of every receipt, and then it lists the calls that the deny list would have stopped.</p>
          <div class="two">
            <ol class="steps">
              <li v-for="(s, i) in steps" :key="s.t"><span class="n">{{ String(i + 1).padStart(2, "0") }}</span><div><b>{{ s.t }}</b><p>{{ s.d }}</p></div></li>
            </ol>
            <div>
              <div class="term" role="group" aria-label="The report">
                <div class="termbar" tabindex="0" role="group" aria-label="The report command"><span class="prompt" aria-hidden="true">$</span><code>{{ reportCommand }}</code></div>
                <pre tabindex="0" aria-label="The output of the report command">{{ report }}</pre>
              </div>
              <p class="caption">Output of <a :href="`${repo}/blob/main/packages/receipts/examples/36-claude-code-init.ts`">tutorial 36</a>, with the path of <code>sdk.json</code> shortened. The tutorial runs four calls: two match the list.</p>
            </div>
          </div>
        </div>
      </section>

      <section id="replay" class="sec">
        <div class="wrap">
          <h2>An incident replay</h2>
          <p class="sub">A coding agent runs <code>terraform destroy</code>. This is the moment that you want the hook for. A script plays the session in enforce mode. It needs no model and no network, and it runs no destructive command.</p>
          <div class="cards c3">
            <div v-for="r in replay" :key="r.cmd" class="card">
              <span class="badge" :class="r.tone">{{ r.badge }}</span>
              <h3><code>{{ r.cmd }}</code></h3>
              <p>{{ r.d }}</p>
            </div>
          </div>
          <div class="two replay-out">
            <div>
              <p class="h3">What Claude Code shows the agent</p>
              <div class="term"><pre tabindex="0" aria-label="The text that Claude Code shows the agent">{{ denial }}</pre></div>
              <p class="caption">The text says what the rule forbids. It names the rule, <code>policy5</code>, and the id of the signed record of the denial.</p>
            </div>
            <div>
              <p class="h3">What a reviewer checks, offline</p>
              <div class="term"><pre tabindex="0" aria-label="The offline check of the receipts">{{ verified }}</pre></div>
              <p class="caption">The reviewer holds the agent's public key and the receipt files. Nothing else. The last line is the <code>terraform destroy</code> receipt checked with a key that is not the agent's. <a href="/verify">Verify a receipt in your browser →</a></p>
            </div>
          </div>
          <div class="ctas after">
            <a class="btn primary" href="/guide/incident-replay">Read the replay, with its full output →</a>
          </div>
        </div>
      </section>

      <section id="limits" class="sec alt">
        <div class="wrap">
          <h2>What the hook does not stop</h2>
          <p class="sub">The hook stops a shell command, a file edit, or an MCP tool call that the agent makes. Read these limits before you rely on it.</p>
          <div class="cards c2">
            <div v-for="l in limits" :key="l.t" class="card"><h3>{{ l.t }}</h3><p>{{ l.d }}</p></div>
          </div>
          <p class="after">To cover more, keep production credentials out of the agent's environment, and put a gateway between the agent and the tools that touch production. The gateway is on the <a href="/advanced">advanced page</a>. The <a href="/receipts/threat-model">threat model</a> lists what each part defends, and what it does not. No independent witness runs yet, and the hosted log is not anchored on mainnet yet.</p>
        </div>
      </section>

      <section id="start" class="sec final">
        <div class="wrap">
          <h2>Try it on your own sessions</h2>
          <p class="sub">Needs Node 22. No account. A global install keeps the hooks working.</p>
          <div class="cmd"><div class="lines"><div v-for="c in commands" :key="c"><span class="prompt" aria-hidden="true">$</span><code>{{ c }}</code></div></div><button type="button" aria-live="polite" @click="copy('final')">{{ label("final") }}</button></div>
          <p v-if="failed === 'final'" class="note" role="status">Copy failed. Select the command and copy it by hand.</p>
          <div class="ctas">
            <a class="btn primary" :href="setupHref">Setup for Claude Code →</a>
            <a class="btn" href="/advanced">Advanced: the gateway, memory, and the hosted log</a>
          </div>
        </div>
      </section>
    </main>

    <footer class="site">
      <div class="wrap">
        <div class="cols">
          <div class="about">
            <a class="brand" href="/" aria-label="agent-custody home">
              <svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" class="tile" /><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff" /><path d="M25 20h14M25 27h14" class="ink" stroke-width="2.6" stroke-linecap="round" /><path d="M25 37.5l5 4.5 9.5-10" fill="none" class="ink" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" /></svg>
              <span>agent-custody</span>
            </a>
            <p>A deny list and a signed record for coding agents.</p>
          </div>
          <nav aria-label="Product"><h2>Product</h2><ul><li><a href="/advanced">Advanced</a></li><li><a href="/use-cases">Use cases</a></li><li><a href="/pricing">Pricing</a></li><li><a href="/early-access">Hosted log</a></li><li><a href="/verify">Verify</a></li></ul></nav>
          <nav aria-label="Docs"><h2>Docs</h2><ul><li><a href="/guide/getting-started">Getting started</a></li><li><a href="/guide/incident-replay">Incident replay</a></li><li><a href="/reference/">Reference</a></li><li><a href="/receipt/v0.2">Receipt spec</a></li><li><a href="/changelog">Changelog</a></li></ul></nav>
          <nav aria-label="Trust"><h2>Trust</h2><ul><li><a href="/security">Security</a></li><li><a href="/faq">FAQ: where data goes</a></li><li><a href="/receipts/threat-model">Threat model</a></li><li><a href="/custody">This repository</a></li></ul></nav>
          <nav aria-label="Company"><h2>Company</h2><ul><li><a href="/blog/">Writing</a></li><li><a href="/contact">Contact</a></li><li><a href="/privacy">Privacy</a></li><li><a href="/terms">Terms</a></li></ul></nav>
        </div>
        <div class="legal">
          <span>Apache-2.0 · Charioteer Consulting Ltd, {{ year }}</span>
          <span><a :href="repo">GitHub</a> · <a href="https://www.npmjs.com/org/agent-custody">npm</a> · <a href="https://pypi.org/project/agent-custody/">PyPI</a></span>
        </div>
      </div>
    </footer>
  </div>
</template>

<style scoped>
/* Tokens. VitePress bundles Inter, so the type needs no font request. The --vp-c-* aliases make Flow.vue and Demo.vue
   follow the same palette. --ink-3 is for decoration only; it fails AA contrast for small text on white. */
.landing {
  --sans: var(--vp-font-family-base); --mono: var(--vp-font-family-mono);
  --bg: #ffffff; --bg-2: #fafaf9; --line: #e7e5e4; --line-2: #d6d3d1; --ink: #1c1917; --ink-2: #57534e; --ink-3: #a8a29e;
  --brand: #b45309; --brand-hover: #92400e; --brand-ink: #ffffff; --brand-soft: #fef3c7;
  --allow: #15803d; --allow-soft: #dcfce7; --deny: #b91c1c; --deny-soft: #fee2e2;
  --term: #1c1917; --term-ink: #e7e5e4; --r: 12px;
  --vp-c-bg: var(--bg); --vp-c-bg-soft: var(--bg-2); --vp-c-divider: var(--line);
  --vp-c-text-1: var(--ink); --vp-c-text-2: var(--ink-2); --vp-c-text-3: var(--ink-3); --vp-c-brand-1: var(--brand);
  min-height: 100vh; background: var(--bg); color: var(--ink); font: 16px/1.6 var(--sans); -webkit-font-smoothing: antialiased;
}
a { color: inherit; }
.landing :focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
.landing code, .landing pre { font-family: var(--mono); }
.sr-only { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.wrap { max-width: 1200px; margin: 0 auto; padding: 0 32px; }

/* Nav */
.nav { position: sticky; top: 0; z-index: 10; background: color-mix(in srgb, var(--bg) 85%, transparent); backdrop-filter: blur(8px); border-bottom: 1px solid var(--line); }
.nav .wrap { display: flex; align-items: center; height: 64px; gap: 40px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; text-decoration: none; }
.brand svg { width: 28px; height: 28px; flex: none; } .tile { fill: var(--brand); } .ink { stroke: var(--brand); }
.navlinks { display: flex; gap: 28px; font-size: 14px; color: var(--ink-2); white-space: nowrap; }
.navlinks a { text-decoration: none; } .navlinks a:hover { color: var(--ink); }
.right { margin-left: auto; display: flex; align-items: center; gap: 12px; font-size: 14px; }
.icon-btn { width: 36px; height: 36px; display: grid; place-items: center; padding: 0; border: 1px solid var(--line); border-radius: 8px; background: transparent; color: var(--ink-2); cursor: pointer; }
.icon-btn:hover { color: var(--ink); border-color: var(--line-2); }
.icon-btn svg { width: 18px; height: 18px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.icon-btn svg.mark { fill: currentColor; stroke: none; }
/* Both icons are in the markup, so the server and the client render the same tree. The html.dark class picks one. */
.icon-btn svg.sun { display: none; }
html.dark .icon-btn svg.sun { display: block; }
html.dark .icon-btn svg.moon { display: none; }

/* Buttons */
.btn { display: inline-flex; align-items: center; gap: 8px; height: 44px; padding: 0 18px; border-radius: 8px; font-weight: 500; font-size: 15px; text-decoration: none; white-space: nowrap; border: 1px solid var(--line-2); background: var(--bg); color: var(--ink); }
.btn:hover { border-color: var(--ink-3); }
.btn.sm { height: 36px; padding: 0 14px; font-size: 14px; }
.btn.primary { background: var(--brand); border-color: var(--brand); color: var(--brand-ink); }
.btn.primary:hover { background: var(--brand-hover); border-color: var(--brand-hover); }

/* Section rhythm */
.sec { padding: 96px 0; border-top: 1px solid var(--line); scroll-margin-top: 64px; }
.alt { background: var(--bg-2); }
h1 { font-size: clamp(28px, 4.4vw, 44px); line-height: 1.12; letter-spacing: -.03em; font-weight: 700; margin: 0 0 20px; }
h2 { font-size: clamp(28px, 4vw, 36px); line-height: 1.15; letter-spacing: -.025em; font-weight: 650; margin: 0 0 16px; max-width: 22ch; border: 0; padding: 0; }
.sub { font-size: 18px; color: var(--ink-2); max-width: 60ch; margin: 0 0 48px; }
.sub code { font-size: .9em; color: var(--ink); }

/* Hero */
.hero { padding: 88px 0 72px; }
.hero .wrap { display: grid; grid-template-columns: 1.1fr .9fr; gap: 64px; align-items: center; }
.hero .wrap > * { min-width: 0; }
.lede { font-size: 19px; color: var(--ink-2); margin: 0 0 32px; max-width: 34em; }
.hero .ctas { margin-top: 24px; }
.ctas { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
.cmd { display: flex; align-items: center; gap: 12px; background: var(--term); color: var(--term-ink); border-radius: 10px; padding: 12px 12px 12px 16px; font: 13.5px var(--mono); max-width: 560px; }
.cmd .prompt { color: #a8a29e; flex: none; }
.cmd .lines { flex: 1; min-width: 0; display: grid; gap: 4px; user-select: all; }
.cmd .lines > div { display: flex; gap: 12px; min-width: 0; }
.cmd code { flex: 1; min-width: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.cmd button { flex: none; min-width: 64px; font: 12px var(--sans); background: #292524; color: var(--term-ink); border: 1px solid #44403c; border-radius: 6px; padding: 6px 10px; cursor: pointer; }
.cmd button:hover { background: #44403c; }
.note { font-size: 13px; color: var(--ink-2); margin: 10px 0 0; }
.watch { display: inline-flex; align-items: center; gap: 10px; margin-top: 20px; font-size: 14px; font-weight: 500; color: var(--ink-2); text-decoration: none; }
.watch:hover { color: var(--ink); }
.play { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; border: 1px solid var(--line-2); font-size: 10px; color: var(--brand); padding-left: 2px; }

/* The denied-call card in the hero */
.denied { border: 1px solid var(--line); border-radius: var(--r); background: var(--bg); box-shadow: 0 1px 2px rgba(0, 0, 0, .04), 0 24px 48px -24px rgba(28, 25, 23, .18); overflow: hidden; }
.denied header { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--line); }
.denied .t { font-weight: 600; font-size: 14px; } .denied .d { font: 12px var(--mono); color: var(--ink-2); }
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; border-radius: 999px; padding: 3px 10px; white-space: nowrap; }
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge.deny { background: var(--deny-soft); color: var(--deny); } .badge.allow { background: var(--allow-soft); color: var(--allow); }
.denied dl { margin: 0; padding: 8px 20px; display: grid; grid-template-columns: 128px 1fr; font-size: 13.5px; }
.denied dt, .denied dd { padding: 9px 0; border-bottom: 1px solid var(--line); margin: 0; }
.denied dl > :nth-last-child(-n+2) { border-bottom: 0; }
.denied dt { color: var(--ink-2); } .denied dd { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.denied dd small { color: var(--ink-2); font-family: var(--sans); font-size: 12px; }
.denied footer { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 14px 20px; background: var(--bg-2); border-top: 1px solid var(--line); font-size: 13px; color: var(--ink-2); }
.denied footer a { flex: none; white-space: nowrap; font-weight: 600; color: var(--brand); text-decoration: none; }
.denied footer a:hover { color: var(--brand-hover); }

/* Cards */
.cards { display: grid; gap: 20px; }
.c3 { grid-template-columns: repeat(3, 1fr); }
.c2 { grid-template-columns: repeat(2, 1fr); }
.card { border: 1px solid var(--line); border-radius: var(--r); padding: 24px; background: var(--bg); min-width: 0; }
.card h3 { font-size: 16px; margin: 0 0 8px; font-weight: 600; } .card p { margin: 0; font-size: 14.5px; color: var(--ink-2); }
.card .badge { margin-bottom: 14px; }
.card h3 code { font-size: 13.5px; overflow-wrap: anywhere; }

/* Two columns, the steps, and the terminal blocks */
.two { display: grid; grid-template-columns: 1fr 1.5fr; gap: 48px; align-items: start; }
.two > * { min-width: 0; }
.replay-out { grid-template-columns: 1fr 1fr; margin-top: 32px; }
.steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 24px; }
.steps li { display: grid; grid-template-columns: 36px 1fr; gap: 8px; }
.steps .n { font: 12px var(--mono); color: var(--brand); padding-top: 4px; }
.steps b { display: block; font-size: 15.5px; font-weight: 600; margin-bottom: 2px; }
.steps p { margin: 0; font-size: 14.5px; color: var(--ink-2); }
.term { background: var(--term); color: var(--term-ink); border-radius: 10px; overflow: hidden; }
.term pre { margin: 0; padding: 16px; font-size: 12.5px; line-height: 1.6; overflow-x: auto; white-space: pre; }
.termbar { display: flex; gap: 12px; padding: 12px 16px; border-bottom: 1px solid #292524; font: 12.5px var(--mono); overflow-x: auto; white-space: nowrap; }
.termbar .prompt { color: #a8a29e; flex: none; }
.h3 { font-size: 15px; font-weight: 600; margin: 0 0 14px; }
.caption { font-size: 13px; color: var(--ink-2); margin: 12px 0 0; }
.caption a, .after a { color: var(--brand); font-weight: 500; }
.caption code { font-size: .95em; }
.after { margin: 24px 0 0; font-size: 15px; color: var(--ink-2); max-width: 70ch; }
.ctas.after { margin-top: 32px; }
.lede code { font-size: .88em; color: var(--ink); }
.denied dd code { font-size: 12.5px; }

/* Final call to action */
.final { text-align: center; }
.final h2 { margin: 0 auto 16px; }
.final .sub { margin: 0 auto 32px; }
.final .cmd { margin: 0 auto 24px; text-align: left; }
.final .note { margin: 0 0 24px; }
.final .ctas { justify-content: center; margin-bottom: 0; }

/* Footer */
footer.site { border-top: 1px solid var(--line); padding: 56px 0 40px; font-size: 14px; }
.cols { display: grid; grid-template-columns: 2fr repeat(4, 1fr); gap: 32px; }
.about p { color: var(--ink-2); font-size: 14px; max-width: 28ch; margin: 12px 0 0; }
.cols h2 { margin: 0 0 12px; font-size: 13px; line-height: 1.6; letter-spacing: 0; font-weight: 600; max-width: none; }
.cols ul { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
.cols a { text-decoration: none; color: var(--ink-2); } .cols a:hover { color: var(--ink); }
.legal { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--line); color: var(--ink-2); font-size: 13px; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px 24px; }
.legal a:hover { color: var(--ink); }

@media (prefers-reduced-motion: no-preference) {
  .btn, .icon-btn, .cmd button { transition: background-color .15s, border-color .15s, color .15s; }
}

@media (max-width: 64rem) {
  .hero .wrap { grid-template-columns: 1fr; gap: 48px; }
  .denied { max-width: 560px; }
  .c3 { grid-template-columns: repeat(2, 1fr); }
  .c3 > :last-child:nth-child(odd) { grid-column: 1 / -1; }
  .two, .replay-out { grid-template-columns: 1fr; gap: 40px; }
  .cols { grid-template-columns: repeat(2, 1fr); } .about { grid-column: 1 / -1; }
  /* The nav needs two rows below this width: the links move under the logo and scroll sideways. */
  .nav .wrap { flex-wrap: wrap; height: auto; gap: 8px 16px; padding-top: 10px; padding-bottom: 10px; }
  .right { gap: 8px; }
  .navlinks { order: 3; flex: 1 0 100%; min-width: 0; gap: 22px; overflow-x: auto; scrollbar-width: none; padding: 4px 0; }
  .navlinks::-webkit-scrollbar { display: none; }
  .sec { scroll-margin-top: 104px; }
}
@media (max-width: 48rem) {
  .sec { padding: 64px 0; }
  .hero { padding: 48px 0 40px; }
  .sub { font-size: 17px; margin-bottom: 32px; }
}
@media (max-width: 40rem) {
  .wrap { padding: 0 24px; }
  .c3, .c2 { grid-template-columns: 1fr; }
  .ctas .btn { height: auto; min-height: 44px; padding-top: 8px; padding-bottom: 8px; white-space: normal; max-width: 100%; }
  .denied dl { grid-template-columns: 1fr; }
  .denied dt { padding-bottom: 0; border-bottom: 0; } .denied dd { padding-top: 2px; }
  .denied dl > :nth-last-child(2) { border-bottom: 0; }
  .denied footer { flex-wrap: wrap; gap: 8px 16px; }
  .legal { flex-direction: column; }
}
</style>

<style>
/* Dark tokens live outside the scoped block: Vue's scoped compiler collapses `:global(.dark) .landing` to `.dark`, which
   sets the variables on the root where the scoped light values on .landing override them. html.dark .landing outranks
   .landing[data-v]. */
html.dark .landing {
  --bg: #0c0a09; --bg-2: #1c1917; --line: #292524; --line-2: #44403c; --ink: #fafaf9; --ink-2: #a8a29e; --ink-3: #78716c;
  --brand: #f59e0b; --brand-hover: #fbbf24; --brand-ink: #1c1917; --brand-soft: #451a03;
  --allow: #4ade80; --allow-soft: #052e16; --deny: #f87171; --deny-soft: #450a0a;
  --term: #0c0a09; --term-ink: #e7e5e4;
}
html.dark .landing .cmd { border: 1px solid var(--line); }
html.dark .landing .denied { box-shadow: none; }
</style>
