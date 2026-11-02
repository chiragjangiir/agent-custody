<script setup lang="ts">
// The product's front door, outside the docs theme. The page leads with one action: run the refund demo on your
// own machine. It then shows one complete story (a refund the policy allows, one it denies, and the audit), and the
// pieces behind it. The one decorated object in the hero is the receipt card. It is the gateway-denied conformance
// vector, decoded at build time: every byte verifies against the published keys, and the identities are the
// fixture's. Colours are tokens on .landing. Light and dark share the names, and Flow.vue and Demo.vue read the
// --vp-c-* aliases. Every section uses the same 1200px container, so all left edges line up.
import { onBeforeUnmount, ref } from "vue";
import { useData } from "vitepress";
import vectors from "../../../packages/receipts/vectors/receipts.json";
import Flow from "./Flow.vue";
import Demo from "./Demo.vue";

const { isDark } = useData();
const sample = "gateway-denied";
const bundle = (vectors.cases as any[]).find((c) => c.name === sample).bundle;
const decode = (b64: string) => JSON.parse(typeof Buffer !== "undefined" ? Buffer.from(b64, "base64").toString("utf8") : atob(b64));
const receipt = decode(bundle.envelope.payload).predicate;
const head = decode(bundle.treeHead.payload);
const short = (h: string) => h.slice(0, 12) + "…";
const pounds = (pence: number) => "£" + (pence / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 });
const customer = receipt.facts.customer;
const when = receipt.timestamp.replace("T", " ").slice(0, 19) + " UTC";
const status: string = receipt.execution.status;
const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);
const year = new Date().getUTCFullYear();

const repo = "https://github.com/svayatta/agent-custody";
const example = (file: string) => `${repo}/blob/main/packages/receipts/examples/${file}`;
const verifyHref = `/verify?sample=${sample}`;
const command = `git clone ${repo} && cd agent-custody && bun install && bun run demo`;

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

// The film. A chapter button seeks and plays. The timeupdate event marks the chapter that holds the playhead.
const video = ref<HTMLVideoElement | null>(null);
const chapters = [
  { t: 0, at: "0:00", title: "The problem", line: "The only record of an agent's action is its own log." },
  { t: 14, at: "0:14", title: "The gateway", line: "Between your agents and their tools, a signed receipt for every call." },
  { t: 24, at: "0:24", title: "How it works", line: "A signed grant, a policy check before the tool runs, a Merkle log." },
  { t: 40, at: "0:40", title: "The refund story", line: "£500 approved. Then a prompt injection asks for £5,000." },
  { t: 72, at: "1:12", title: "The audit", line: "Months later, an auditor checks it with public keys and a copy of the log." },
];
const chapter = ref(0);
function mark() {
  const now = video.value?.currentTime ?? 0;
  let on = 0;
  chapters.forEach((c, i) => { if (now >= c.t) on = i; });
  chapter.value = on;
}
function seek(i: number) {
  const v = video.value;
  if (!v) return;
  v.currentTime = chapters[i].t;
  chapter.value = i;
  v.play().catch(() => {});
}

const steps = [
  { t: "Authorize", d: "A person signs a grant: which agent, which tools, for how long." },
  { t: "Gate", d: "The gateway fetches the facts itself, evaluates the policy, and forwards or denies." },
  { t: "Record", d: "One signed receipt per call: who authorized it, what was asked, what was checked, what happened." },
  { t: "Log", d: "The receipt's hash goes to a Merkle log with signed heads. A rewrite is detectable by anyone who kept a checkpoint." },
  { t: "Verify", d: "Anyone with the public keys checks a receipt, in the shell or the browser, offline." },
];
const rules = [
  { t: "Limits", d: "A ceiling per call, in minor units. No floats, no rounding.", c: 'permit(principal, action == Action::"stripe.refund", resource)\nwhen { context.args.amount <= 100000 };' },
  { t: "Facts, not claims", d: "The gateway looks the customer up itself before deciding. The agent's own arguments are never enough.", c: 'permit(principal, action == Action::"stripe.refund", resource)\nwhen { context.facts.customer.verified\n    && context.args.customer_id == context.facts.customer.id };' },
  { t: "Allowed targets", d: "Only these accounts, these hosts, these paths. Anything else is refused before it leaves.", c: 'permit(principal, action == Action::"payout.send", resource)\nwhen { ["acct_treasury", "acct_payroll"].contains(context.args.to) };' },
  { t: "Human approval", d: "A larger change needs a person the gateway can see approved it, in the system of record.", c: 'permit(principal, action == Action::"pr.merge", resource)\nwhen { context.facts.checks.all_green\n    && context.facts.reviews.human_count >= 1 };' },
  { t: "Boundaries", d: "Where an agent may write, and what it must say when it does.", c: 'permit(principal, action == Action::"kb.write", resource)\nwhen { context.args.path like "notes/*"\n    && context.args has source };' },
  { t: "Evidence before effect", d: "Name a tool as consequential and the authorization is logged before the call is forwarded. If the log refuses, nothing happens.", c: '"precommit": ["stripe.refund", "pr.merge", "deploy.promote"]' },
];
// The short line under each tab title.
const tabLine: Record<string, string> = {
  "Limits": "A ceiling per call, in minor units",
  "Facts, not claims": "The gateway looks the customer up",
  "Allowed targets": "Only these accounts and hosts",
  "Human approval": "A person the gateway can see",
  "Boundaries": "Where an agent may write",
  "Evidence before effect": "Logged before it is forwarded",
};
// The tabs follow the ARIA tabs pattern: one tab is in the tab order, and the arrow keys move between tabs.
const rule = ref(0);
const tabs = ref<HTMLButtonElement[]>([]);
function pick(i: number) {
  rule.value = i;
  tabs.value[i]?.focus();
}
function tabKey(e: KeyboardEvent, i: number) {
  const n = rules.length;
  const next = { ArrowDown: (i + 1) % n, ArrowRight: (i + 1) % n, ArrowUp: (i + n - 1) % n, ArrowLeft: (i + n - 1) % n, Home: 0, End: n - 1 }[e.key];
  if (next === undefined) return;
  e.preventDefault();
  pick(next);
}
// Splits Cedar code so the two keywords get their own colour.
const keywords = (code: string) => code.split(/(\bpermit\b|\bwhen\b)/).map((s) => ({ s, k: s === "permit" || s === "when" }));
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
          <a href="#film">Overview</a><a href="#story">The demo</a><a href="#how">How it works</a><a href="#policies">Policies</a><a href="/use-cases">Use cases</a><a href="/pricing">Pricing</a><a href="/guide/getting-started">Docs</a>
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
            <h1>Proof of what your AI agents did.</h1>
            <p class="lede">A gateway between an agent and its tools. It checks every call against a grant a person signed and a policy, forwards or denies it, and issues a signed receipt either way. Anyone with the public keys can verify the receipt, offline.</p>
            <div class="ctas">
              <a class="btn primary" href="#run">Run the refund demo locally</a>
              <a class="btn" :href="verifyHref">Verify a receipt in your browser</a>
            </div>
            <div class="cmd"><span class="prompt" aria-hidden="true">$</span><code>{{ command }}</code><button type="button" aria-live="polite" @click="copy('hero')">{{ label("hero") }}</button></div>
          <p v-if="failed === 'hero'" class="note" role="status">Copy failed. Select the command and copy it by hand.</p>
            <p class="note">Requires Node 22 and Bun. Runs four calls through the gateway, three refunds and a payout, and verifies each receipt.</p>
            <a class="watch" href="#film"><span class="play" aria-hidden="true">▶</span>Watch the overview (1:32)</a>
          </div>

          <article class="receipt" :aria-label="`A receipt: a ${pounds(receipt.request.args.amount).replace('.00', '')} refund the policy refused`">
            <header>
              <div><div class="t">Receipt · {{ receipt.tool.name }}</div><div class="d">{{ when }}</div></div>
              <span class="badge" :class="receipt.policy.decision">{{ statusLabel }}</span>
            </header>
            <dl>
              <dt>Asked for</dt><dd>refund {{ pounds(receipt.request.args.amount) }} to {{ receipt.request.args.customer_id }}</dd>
              <dt>Gateway checked</dt><dd>customer {{ customer.value.id }}, verified {{ customer.value.verified }} <small>{{ customer.provenance }}</small></dd>
              <dt>Policy</dt><dd>refunds to £1,000 for a verified customer <small>sha256 {{ short(receipt.policy.policyDigest) }}</small></dd>
              <dt>Decision</dt><dd>{{ receipt.policy.decision }} · {{ receipt.execution.reason }}</dd>
              <dt>Agent</dt><dd>{{ receipt.agent.id }} <small>{{ receipt.agent.provenance }}</small></dd>
              <dt>Authorized by</dt><dd>{{ receipt.principal.id }} <small>a grant they signed</small></dd>
              <dt>Log</dt><dd>leaf {{ bundle.inclusion.leafIndex + 1 }} of {{ head.treeSize }} · root {{ short(head.rootHash) }}</dd>
            </dl>
            <footer><span>Checked with the published keys. Nothing is uploaded.</span><a :href="verifyHref">Verify this receipt →</a></footer>
          </article>
        </div>
      </section>

      <section class="integrations" aria-labelledby="integrations-h">
        <div class="wrap">
          <div class="int-head"><h2 id="integrations-h">Integrations</h2><p>Also DeepSeek Harness, Hermes, CrewAI, and the Claude Agent SDK. <a href="/guide/getting-started">Setup for each →</a></p></div>
          <div class="int-grid">
            <a class="int" href="/guide/getting-started"><b>Claude Code</b><code>PreToolUse hook</code></a>
            <a class="int" href="/guide/getting-started"><b>Any MCP host</b><code>gateway as MCP server</code></a>
            <a class="int" href="/guide/getting-started"><b>OpenAI Agents SDK</b><code>wrapTools</code></a>
            <a class="int" href="/guide/getting-started"><b>LangChain, LangGraph</b><code>issuer.wrap + callback</code></a>
            <a class="int" href="/guide/getting-started"><b>Vercel AI SDK</b><code>wrapTools</code></a>
            <a class="int" href="/guide/getting-started"><b>Google ADK</b><code>tool callbacks</code></a>
            <a class="int" href="/guide/getting-started"><b>OpenClaw</b><code>before_tool_call hook</code></a>
            <a class="int" href="/guide/getting-started"><b>Python, Go, Java, Rust</b><code>HTTP sidecar</code></a>
          </div>
        </div>
      </section>

      <section id="film" class="sec alt">
        <div class="wrap">
          <h2>Product overview</h2>
          <p class="sub">Narrated, with captions.</p>
          <div class="film">
            <div class="screen">
              <video ref="video" controls playsinline preload="none" poster="/promo-poster.jpg" width="1920" height="1080" aria-label="A 93-second narrated film: the problem, the gateway, and a refund agent caught by a prompt injection, then the audit." @timeupdate="mark" @seeked="mark">
                <source src="/promo.mp4" type="video/mp4" />
                <track kind="captions" src="/promo.vtt" srclang="en" label="English" />
              </video>
            </div>
            <ol class="chapters" aria-label="Chapters">
              <li v-for="(c, i) in chapters" :key="c.t" :class="{ on: chapter === i }">
                <button type="button" :aria-current="chapter === i ? 'true' : undefined" @click="seek(i)">
                  <span class="at">{{ c.at }}</span>
                  <span class="what"><b>{{ c.title }}</b>{{ c.line }}</span>
                </button>
              </li>
            </ol>
          </div>
        </div>
      </section>

      <section id="problem" class="sec">
        <div class="wrap">
          <h2>The problem</h2>
          <p class="sub">An agent's only record is the log its own process wrote. Nobody outside the team can check it.</p>
          <div class="cards c3">
            <div class="card"><h3>Made-up authority</h3><p>The agent refunds £50,000. Its log says the customer asked. Nobody signed anything that allowed it.</p></div>
            <div class="card"><h3>A log that can be edited</h3><p>The team that ran the agent holds the log. After the incident, the entry that matters is gone or different.</p></div>
            <div class="card"><h3>Evidence nobody else can check</h3><p>Traces sit in a vendor account. The auditor gets a screenshot and a promise.</p></div>
          </div>
        </div>
      </section>

      <section id="story" class="sec alt">
        <div class="wrap">
          <h2>The refund demo</h2>
          <p class="sub"><code>bun run demo</code> runs a support agent against a test Stripe server. Each call writes a signed receipt to your disk. Then the demo verifies the receipts and edits one.</p>
          <Demo />
        </div>
      </section>

      <section id="how" class="sec">
        <div class="wrap">
          <h2>How it works</h2>
          <p class="sub">Every call goes through the same five steps.</p>
          <div class="cards c5">
            <div v-for="(s, i) in steps" :key="s.t" class="card"><span class="n">{{ String(i + 1).padStart(2, "0") }}</span><h3>{{ s.t }}</h3><p>{{ s.d }}</p></div>
          </div>
          <div class="flowbox"><Flow /></div>
        </div>
      </section>

      <section id="policies" class="sec alt">
        <div class="wrap">
          <h2>Policies</h2>
          <p class="sub">Written in Cedar and evaluated on facts the gateway fetches itself. Each receipt records the policy digest.</p>
          <div class="policy">
            <div class="tabs" role="tablist" aria-label="Policy rules">
              <button v-for="(r, i) in rules" :id="`tab-${i}`" :key="r.t" :ref="(el) => { if (el) tabs[i] = el as HTMLButtonElement }" type="button" role="tab" class="tab" :class="{ on: rule === i }" :aria-selected="rule === i" aria-controls="rule-panel" :tabindex="rule === i ? 0 : -1" @click="rule = i" @keydown="tabKey($event, i)">
                <b>{{ r.t }}</b><span>{{ tabLine[r.t] }}</span>
              </button>
            </div>
            <div id="rule-panel" class="panel" role="tabpanel" :aria-labelledby="`tab-${rule}`" tabindex="0">
              <pre><template v-for="(p, i) in keywords(rules[rule].c)" :key="i"><span v-if="p.k" class="kw">{{ p.s }}</span><template v-else>{{ p.s }}</template></template></pre>
              <p>{{ rules[rule].d }}</p>
            </div>
          </div>
          <p class="after">Nine more, each run by the test suite, are in <a href="/receipts/policies">Writing policies</a>.</p>
        </div>
      </section>

      <section id="compare" class="sec">
        <div class="wrap">
          <h2>Receipts compared with logs and traces</h2>
          <p class="sub">Receipts export to OpenTelemetry and Splunk, so you keep your current tools.</p>
          <div class="two">
            <div class="tablewrap">
              <table>
                <thead><tr><th scope="col"><span class="sr-only">Question</span></th><th scope="col">Application log</th><th scope="col">Trace</th><th scope="col">Gateway receipt</th></tr></thead>
                <tbody>
                  <tr><th scope="row">Written by</th><td>the agent's process</td><td>the agent's process</td><td class="yes">a gateway, with its own key</td></tr>
                  <tr><th scope="row">Allowed or denied before the tool ran</th><td class="no">—<span class="sr-only">no</span></td><td class="no">—<span class="sr-only">no</span></td><td class="yes">yes, and a denial is a receipt</td></tr>
                  <tr><th scope="row">Who authorized it</th><td class="no">—<span class="sr-only">not recorded</span></td><td class="no">—<span class="sr-only">not recorded</span></td><td class="yes">the grant a person signed</td></tr>
                  <tr><th scope="row">A rewrite is detectable</th><td class="no">—<span class="sr-only">no</span></td><td class="no">—<span class="sr-only">no</span></td><td class="yes">yes, by anyone who kept a checkpoint</td></tr>
                  <tr><th scope="row">Who can check it</th><td>log access holders</td><td>the tracing account</td><td class="yes">anyone with the public keys</td></tr>
                </tbody>
              </table>
            </div>
            <div>
              <p class="h3">Measured on a laptop <small>(lower is better)</small></p>
              <div class="stats">
                <div class="stat"><b>0.10 ms</b><span>a policy decision</span></div>
                <div class="stat"><b>0.52 ms</b><span>a full gateway call</span></div>
                <div class="stat"><b>0.14 ms</b><span>verifying a receipt</span></div>
                <div class="stat"><b>5.7 KB</b><span>a receipt; the log gets 32 bytes</span></div>
              </div>
              <p class="caption">Medians, Apple silicon, Node 22, from <a :href="`${repo}/blob/main/packages/receipts/scripts/bench.ts`">scripts/bench.ts</a>. You can run it.</p>
            </div>
          </div>
        </div>
      </section>

      <section id="use-cases" class="sec alt">
        <div class="wrap">
          <h2>Use cases</h2>
          <p class="sub">Each one has a runnable example.</p>
          <div class="cards c4">
            <div class="card"><h3>Payments and refunds</h3><p>Refund within a limit, for a customer the gateway verified.</p><div class="links"><a href="#story">The demo above →</a><a :href="example('17-rest-upstream.ts')">Example 17: a REST upstream →</a></div></div>
            <div class="card"><h3>Agents that write code</h3><p>Risk-tiered merges. Change-management evidence for SOC 2 and ISO 27001.</p><div class="links"><a href="/blog/risk-tiered-merges-with-evidence">Risk-tiered merges, with evidence →</a><a :href="example('24-agentic-cicd-merge-gate.ts')">Example 24: the merge gate →</a></div></div>
            <div class="card"><h3>Knowledge bases</h3><p>Read anything, write only under notes/, with a source.</p><div class="links"><a href="/demo-langchain-kb.mp4">A 22-second film →</a><a :href="example('23-langchain-kb-agent.ts')">Example 23: LangChain →</a></div></div>
            <div class="card"><h3>Your own repository</h3><p>Every Claude Code tool call as a receipt.</p><div class="links"><a href="/custody">This repository →</a><a href="/reference/claude-code">The hook →</a></div></div>
          </div>
        </div>
      </section>

      <section id="run" class="sec final">
        <div class="wrap">
          <h2>Run the demo</h2>
          <p class="sub">Requires Node 22 and Bun. No account needed.</p>
          <div class="cmd"><span class="prompt" aria-hidden="true">$</span><code>{{ command }}</code><button type="button" aria-live="polite" @click="copy('final')">{{ label("final") }}</button></div>
          <p v-if="failed === 'final'" class="note" role="status">Copy failed. Select the command and copy it by hand.</p>
          <div class="ctas">
            <a class="btn primary" href="/guide/getting-started">Put the gateway in front of your agent →</a>
            <a class="btn" :href="verifyHref">Verify a receipt in your browser</a>
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
            <p>Signed, verifiable receipts for every tool call an AI agent makes.</p>
          </div>
          <nav aria-label="Product"><h2>Product</h2><ul><li><a href="/use-cases">Use cases</a></li><li><a href="/pricing">Pricing</a></li><li><a href="/early-access">Hosted log</a></li><li><a href="/verify">Verify</a></li></ul></nav>
          <nav aria-label="Docs"><h2>Docs</h2><ul><li><a href="/guide/getting-started">Getting started</a></li><li><a href="/reference/">Reference</a></li><li><a href="/receipt/v0.2">Receipt spec</a></li><li><a href="/changelog">Changelog</a></li></ul></nav>
          <nav aria-label="Trust"><h2>Trust</h2><ul><li><a href="/security">Security</a></li><li><a href="/faq">FAQ: where data goes</a></li><li><a href="/receipts/threat-model">Threat model</a></li><li><a href="/custody">Under custody</a></li></ul></nav>
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
h1 { font-size: clamp(34px, 6vw, 56px); line-height: 1.06; letter-spacing: -.035em; font-weight: 700; margin: 0 0 20px; }
h2 { font-size: clamp(28px, 4vw, 36px); line-height: 1.15; letter-spacing: -.025em; font-weight: 650; margin: 0 0 16px; max-width: 22ch; border: 0; padding: 0; }
.sub { font-size: 18px; color: var(--ink-2); max-width: 60ch; margin: 0 0 48px; }
.sub code { font-size: .9em; color: var(--ink); }

/* Hero */
.hero { padding: 88px 0 72px; }
.hero .wrap { display: grid; grid-template-columns: 1.1fr .9fr; gap: 64px; align-items: center; }
.hero .wrap > * { min-width: 0; }
.lede { font-size: 19px; color: var(--ink-2); margin: 0 0 32px; max-width: 34em; }
.ctas { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
.cmd { display: flex; align-items: center; gap: 12px; background: var(--term); color: var(--term-ink); border-radius: 10px; padding: 12px 12px 12px 16px; font: 13.5px var(--mono); max-width: 560px; }
.cmd .prompt { color: #a8a29e; flex: none; }
.cmd code { flex: 1; min-width: 0; white-space: pre-wrap; overflow-wrap: anywhere; user-select: all; }
.cmd button { flex: none; min-width: 64px; font: 12px var(--sans); background: #292524; color: var(--term-ink); border: 1px solid #44403c; border-radius: 6px; padding: 6px 10px; cursor: pointer; }
.cmd button:hover { background: #44403c; }
.note { font-size: 13px; color: var(--ink-2); margin: 10px 0 0; }
.watch { display: inline-flex; align-items: center; gap: 10px; margin-top: 20px; font-size: 14px; font-weight: 500; color: var(--ink-2); text-decoration: none; }
.watch:hover { color: var(--ink); }
.play { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; border: 1px solid var(--line-2); font-size: 10px; color: var(--brand); padding-left: 2px; }

/* Receipt card */
.receipt { border: 1px solid var(--line); border-radius: var(--r); background: var(--bg); box-shadow: 0 1px 2px rgba(0, 0, 0, .04), 0 24px 48px -24px rgba(28, 25, 23, .18); overflow: hidden; }
.receipt header { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--line); }
.receipt .t { font-weight: 600; font-size: 14px; } .receipt .d { font: 12px var(--mono); color: var(--ink-2); }
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; border-radius: 999px; padding: 3px 10px; white-space: nowrap; }
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge.deny { background: var(--deny-soft); color: var(--deny); } .badge.allow { background: var(--allow-soft); color: var(--allow); }
.receipt dl { margin: 0; padding: 8px 20px; display: grid; grid-template-columns: 128px 1fr; font-size: 13.5px; }
.receipt dt, .receipt dd { padding: 9px 0; border-bottom: 1px solid var(--line); margin: 0; }
.receipt dl > :nth-last-child(-n+2) { border-bottom: 0; }
.receipt dt { color: var(--ink-2); } .receipt dd { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.receipt dd small { color: var(--ink-2); font-family: var(--sans); font-size: 12px; }
.receipt footer { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 14px 20px; background: var(--bg-2); border-top: 1px solid var(--line); font-size: 13px; color: var(--ink-2); }
.receipt footer a { flex: none; white-space: nowrap; font-weight: 600; color: var(--brand); text-decoration: none; }
.receipt footer a:hover { color: var(--brand-hover); }

/* Integrations. The grid background shows through a 1px gap, so every inner line is one line at each column count. */
.integrations { padding: 48px 0 56px; border-top: 1px solid var(--line); }
.int-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px 24px; margin-bottom: 20px; }
.int-head h2 { margin: 0; font-size: 15px; line-height: 1.6; letter-spacing: 0; font-weight: 600; max-width: none; }
.int-head p { margin: 0; font-size: 14px; color: var(--ink-2); }
.int-head a { color: var(--brand); font-weight: 500; text-decoration: none; } .int-head a:hover { color: var(--brand-hover); }
.int-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; border: 1px solid var(--line); border-radius: var(--r); overflow: hidden; background: var(--line); }
.int { display: flex; flex-direction: column; gap: 6px; padding: 18px 20px; min-width: 0; text-decoration: none; background: var(--bg); }
.int b { font-size: 15px; font-weight: 600; }
.int code { font-size: 12.5px; color: var(--ink-2); overflow-wrap: anywhere; }
.int:hover { background: var(--bg-2); } .int:hover b { color: var(--brand); }

/* Cards */
.cards { display: grid; gap: 20px; }
.c3 { grid-template-columns: repeat(3, 1fr); } .c4 { grid-template-columns: repeat(4, 1fr); } .c5 { grid-template-columns: repeat(5, 1fr); }
.card { border: 1px solid var(--line); border-radius: var(--r); padding: 24px; background: var(--bg); min-width: 0; }
.card h3 { font-size: 16px; margin: 0 0 8px; font-weight: 600; } .card p { margin: 0; font-size: 14.5px; color: var(--ink-2); }
.card .n { font: 12px var(--mono); color: var(--brand); margin-bottom: 14px; display: block; }
.card .links { margin-top: 16px; display: flex; flex-direction: column; gap: 4px; font-size: 14px; white-space: normal; }
.card .links a { color: var(--brand); text-decoration: none; font-weight: 500; } .card .links a:hover { color: var(--brand-hover); text-decoration: underline; }

/* Film */
.film { display: grid; grid-template-columns: 1fr 340px; gap: 24px; align-items: stretch; }
.screen { border: 1px solid var(--line); border-radius: var(--r); overflow: hidden; background: #000; box-shadow: 0 24px 48px -28px rgba(28, 25, 23, .35); min-width: 0; }
.screen video { display: block; width: 100%; height: auto; aspect-ratio: 16 / 9; }
.chapters { list-style: none; margin: 0; padding: 8px; border: 1px solid var(--line); border-radius: var(--r); background: var(--bg); display: flex; flex-direction: column; }
.chapters button { appearance: none; background: none; border: 0; font: inherit; color: inherit; text-align: left; width: 100%; display: grid; grid-template-columns: 44px 1fr; gap: 8px; padding: 12px; border-radius: 8px; cursor: pointer; }
.chapters button:hover { background: var(--bg-2); }
.chapters .at { font: 12.5px var(--mono); color: var(--ink-2); padding-top: 2px; }
.chapters .what { font-size: 13.5px; color: var(--ink-2); line-height: 1.45; }
.chapters b { display: block; font-size: 14.5px; color: var(--ink); font-weight: 600; margin-bottom: 2px; }
.chapters .on button { background: var(--bg-2); box-shadow: inset 2px 0 0 var(--brand); }
.chapters .on .at { color: var(--brand); }

/* How */
.flowbox { margin-top: 24px; border: 1px solid var(--line); border-radius: var(--r); padding: 32px; background: var(--bg); overflow-x: auto; }

/* Policies */
.policy { border: 1px solid var(--line); border-radius: var(--r); overflow: hidden; background: var(--bg); }
.tabs { display: flex; gap: 4px; padding: 8px 8px 0; border-bottom: 1px solid var(--line); overflow-x: auto; scrollbar-width: thin; }
.tab { flex: none; appearance: none; background: none; border: 0; font: inherit; color: var(--ink-2); text-align: left; padding: 10px 14px 12px; border-radius: 8px 8px 0 0; cursor: pointer; }
.tab b { display: block; font-size: 14.5px; font-weight: 600; } .tab span { display: none; }
.tab:hover { background: var(--bg-2); color: var(--ink); }
.tab.on { background: var(--bg-2); color: var(--ink); box-shadow: inset 0 -2px 0 var(--brand); }
.panel { background: var(--bg-2); min-width: 0; }
.panel pre { margin: 0; padding: 28px 28px 16px; font-size: 13.5px; line-height: 1.7; color: var(--ink); overflow-x: auto; white-space: pre; }
.panel p { margin: 0; padding: 0 28px 28px; font-size: 14px; color: var(--ink-2); }
.kw { color: var(--brand); }
.after { margin: 20px 0 0; font-size: 14.5px; color: var(--ink-2); }
.after a { color: var(--brand); font-weight: 500; }

/* Compare and numbers */
.two { display: grid; grid-template-columns: 1.4fr 1fr; gap: 48px; align-items: start; }
.two > * { min-width: 0; }
.tablewrap { border: 1px solid var(--line); border-radius: var(--r); overflow-x: auto; background: var(--bg); }
table { width: 100%; min-width: 36rem; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child > * { border-bottom: 0; }
thead th { background: var(--bg-2); font-size: 13px; color: var(--ink-2); font-weight: 600; }
tbody th { font-weight: 500; } td { color: var(--ink-2); } td.yes { color: var(--ink); font-weight: 500; }
td.no { color: var(--ink-3); }
.h3 { font-size: 15px; font-weight: 600; margin: 0 0 14px; } .h3 small { font-weight: 400; color: var(--ink-2); }
.stats { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.stat { border: 1px solid var(--line); border-radius: var(--r); padding: 20px; background: var(--bg); min-width: 0; }
.stat b { display: block; font-size: 32px; line-height: 1.25; font-weight: 650; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
.stat span { font-size: 13.5px; color: var(--ink-2); }
.caption { font-size: 13px; color: var(--ink-2); margin: 12px 0 0; }
.caption a { color: var(--brand); }

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
  .btn, .icon-btn, .tab, .chapters button, .cmd button { transition: background-color .15s, border-color .15s, color .15s; }
}

@media (max-width: 64rem) {
  .hero .wrap { grid-template-columns: 1fr; gap: 48px; }
  .receipt { max-width: 560px; }
  .film { grid-template-columns: 1fr; }
  .int-grid { grid-template-columns: repeat(2, 1fr); }
  .c3, .c4, .c5 { grid-template-columns: repeat(2, 1fr); }
  .c3 > :last-child:nth-child(odd), .c5 > :last-child:nth-child(odd) { grid-column: 1 / -1; }
  .two { grid-template-columns: 1fr; gap: 40px; }
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
  .int-head { flex-direction: column; }
  .hero { padding: 48px 0 40px; }
  .sub { font-size: 17px; margin-bottom: 32px; }
  .panel pre { padding: 20px 20px 12px; font-size: 13px; }
  .panel p { padding: 0 20px 20px; }
  .flowbox { padding: 16px; }
}
@media (max-width: 40rem) {
  .wrap { padding: 0 24px; }
  .c3, .c4, .c5, .int-grid { grid-template-columns: 1fr; }
  .receipt dl { grid-template-columns: 1fr; }
  .receipt dt { padding-bottom: 0; border-bottom: 0; } .receipt dd { padding-top: 2px; }
  .receipt dl > :nth-last-child(2) { border-bottom: 0; }
  .receipt footer { flex-wrap: wrap; gap: 8px 16px; }
  .stat b { font-size: 26px; }
  .stat { padding: 16px; }
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
html.dark .landing .screen { box-shadow: none; }
html.dark .landing .receipt { box-shadow: none; }
</style>
