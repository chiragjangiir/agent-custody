import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";
import { cpSync, existsSync } from "node:fs";
import { dirname, posix, relative, resolve } from "node:path";

// The site is generated from the repository's own markdown. Nothing here is a second copy of the docs.
const REPO = "https://github.com/svayatta/agent-custody/blob/main/";

/** Repository-relative markdown path to site path, mirroring `rewrites` below; null when the file is not a page. */
function sitePath(repoPath: string): string | null {
  const m = (re: RegExp) => repoPath.match(re);
  let x: RegExpMatchArray | null;
  if (repoPath === "README.md") return "/repo";
  if (repoPath === "CHANGELOG.md") return "/changelog";
  if (repoPath === "packages/receipts/README.md") return "/receipts/";
  if ((x = m(/^packages\/receipts\/docs\/([^/]+)\.md$/))) return `/receipts/${x[1]}`;
  if (repoPath === "packages/state/README.md") return "/state/";
  if (repoPath === "packages/python/README.md") return "/python/";
  if ((x = m(/^site\/(.+)\.md$/))) return `/${x[1] === "index" ? "" : x[1]}`;
  return null;
}

export default withMermaid(
  defineConfig({
    title: "agent-custody",
    description: "Proof of what your AI agents did. Give your agents real power, without losing control of them.",
    srcDir: "..",
    srcExclude: ["deploy/**", "site/verifier/**", "**/node_modules/**", "**/dist/**", "**/examples-out/**", "**/demo-out/**", "**/.venv/**", "**/target/**", "CLAUDE.md", "CONTRIBUTING.md", "SECURITY.md", "packages/receipts/examples/**", "packages/state/examples/**", "packages/python/tests/**", "site/README.md"],
    rewrites: {
      "site/index.md": "index.md",
      "site/verify.md": "verify.md",
      "site/advanced.md": "advanced.md",
      "site/early-access.md": "early-access.md",
      "site/security.md": "security.md",
      "site/pricing.md": "pricing.md",
      "site/privacy.md": "privacy.md",
      "site/terms.md": "terms.md",
      "site/contact.md": "contact.md",
      "site/custody.md": "custody.md",
      "site/faq.md": "faq.md",
      "site/use-cases.md": "use-cases.md",
      "site/blog/:page": "blog/:page",
      "site/reference/:page": "reference/:page",
      "site/guide/:page": "guide/:page",
      "site/receipt/:page": "receipt/:page",
      "README.md": "repo.md",
      "CHANGELOG.md": "changelog.md",
      "packages/receipts/README.md": "receipts/index.md",
      "packages/receipts/docs/:page": "receipts/:page",
      "packages/state/README.md": "state/index.md",
      "packages/python/README.md": "python/index.md",
    },
    cleanUrls: true,
    head: [
      // ?v= changes when the mark changes, so browsers that cached the old favicon fetch the new one
      ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg?v=2" }],
      ["link", { rel: "icon", type: "image/png", sizes: "32x32", href: "/favicon-32.png?v=2" }],
      ["link", { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png?v=2" }],
      ["meta", { name: "theme-color", content: "#b45309" }],
      ["meta", { property: "og:title", content: "agent-custody" }],
      ["meta", { property: "og:description", content: "Proof of what your AI agents did. Give your agents real power, without losing control of them." }],
    ],
    // The conformance vectors are published as files next to the spec, straight from the receipts package.
    buildEnd(siteConfig) {
      const src = resolve(__dirname, "..", "..", "packages", "receipts", "vectors");
      cpSync(src, resolve(siteConfig.outDir, "vectors"), { recursive: true });
    },
    // Pages live at the repository root, so the public dir must be named explicitly; and the site's dependencies live under site/ (Bun installs are isolated).
    vite: { publicDir: resolve(__dirname, "..", "public"), resolve: { alias: [{ find: /^vue$/, replacement: resolve(__dirname, "..", "node_modules", "vue") }, { find: /^vue\/(.*)$/, replacement: resolve(__dirname, "..", "node_modules", "vue") + "/$1" }] } },
    lastUpdated: false,
    themeConfig: {
      logo: "/logo.svg?v=2",
      // Six entries. Receipts, State, Python, the spec, and security live in the sidebar under Docs.
      nav: [
        { text: "Product", link: "/" },
        { text: "Docs", link: "/guide/getting-started" },
        { text: "Advanced", link: "/advanced" },
        { text: "Pricing", link: "/pricing" },
        { text: "Verify", link: "/verify" },
        { text: "Sign in", link: "https://app.agent-custody.dev/" },
      ],
      sidebar: {
        "/reference/": [
          { text: "Reference", items: [
            { text: "Overview", link: "/reference/" },
            { text: "The gateway", link: "/reference/gateway" },
            { text: "The door", link: "/reference/door" },
            { text: "The egress witness", link: "/reference/egress" },
            { text: "The ACS Guardian", link: "/reference/acs" },
            { text: "TypeScript SDK", link: "/reference/sdk-typescript" },
            { text: "Sidecar HTTP API", link: "/reference/sidecar" },
            { text: "Python", link: "/reference/python" },
            { text: "Claude Code and Agent SDK", link: "/reference/claude-code" },
            { text: "Log API", link: "/reference/log-api" },
            { text: "Verify, audit, export", link: "/reference/verify" },
            { text: "Hosted log and portal", link: "/reference/hosted" },
            { text: "Memory: ledger and server", link: "/reference/memory" },
            { text: "Explain, review, packs", link: "/reference/state-tools" },
            { text: "Command line", link: "/reference/cli" },
          ] },
          { text: "Guides", items: [{ text: "Getting started", link: "/guide/getting-started" }, { text: "Put the door in front of a site", link: "/receipts/door-quickstart" }, { text: "Architecture", link: "/guide/architecture" }, { text: "Deployment", link: "/guide/deployment" }, { text: "Credential custody and lockdown", link: "/guide/credential-custody" }, { text: "Writing policies", link: "/receipts/policies" }, { text: "Writing egress policies", link: "/guide/egress-policies" }, { text: "Verifying a receipt", link: "/receipts/verification" }] },
        ],
        "/": [
        { text: "Start here", items: [
          { text: "Advanced: everything else", link: "/advanced" },
          { text: "What each piece is for", link: "/guide/pieces" },
          { text: "FAQ: where the data goes", link: "/faq" },
          { text: "Use cases, with their policies", link: "/use-cases" },
          { text: "Getting started", link: "/guide/getting-started" },
          { text: "An incident replay", link: "/guide/incident-replay" },
          { text: "Architecture", link: "/guide/architecture" }, { text: "Deployment", link: "/guide/deployment" },
          { text: "Credential custody and lockdown", link: "/guide/credential-custody" },
          { text: "Agent sessions in this repository", link: "/custody" },
          { text: "Changelog", link: "/changelog" },
        ] },
        { text: "Writing", items: [{ text: "All pieces", link: "/blog/" }, { text: "Risk-tiered merges, with evidence", link: "/blog/risk-tiered-merges-with-evidence" }, { text: "Logs are claims. Receipts are evidence.", link: "/blog/logs-are-claims" }] },
        { text: "Receipts", items: [
          { text: "Overview", link: "/receipts/" },
          { text: "Tutorials", link: "/receipts/tutorials" },
          { text: "Configuring the gateway", link: "/receipts/configuration" },
          { text: "The gateway console", link: "/receipts/console" },
          { text: "The gateway", link: "/receipts/usage" },
          { text: "The door", link: "/receipts/door" },
          { text: "Door signals", link: "/receipts/door-signals" },
          { text: "The egress witness", link: "/receipts/egress" },
          { text: "Writing egress policies", link: "/guide/egress-policies" },
          { text: "The ACS Guardian", link: "/receipts/acs" },
          { text: "Live Codex recovery demo", link: "/receipts/codex-recovery" },
          { text: "Payload-bound approvals", link: "/receipts/approvals" },
          { text: "The interceptor SDK and other languages", link: "/receipts/sdk" },
          { text: "Writing policies", link: "/receipts/policies" },
          { text: "Verifying a receipt", link: "/receipts/verification" },
          { text: "Receipts on a pull request", link: "/receipts/github-action" },
          { text: "What the evidence satisfies", link: "/receipts/compliance" },
          { text: "Threat model", link: "/receipts/threat-model" },
        ] },
        { text: "State", items: [{ text: "The fact ledger", link: "/state/" }] },
        { text: "Python", items: [{ text: "The Python client", link: "/python/" }] },
        { text: "Specification", items: [{ text: "Receipt v0.2", link: "/receipt/v0.2" }, { text: "Conformance vectors", link: "/receipt/vectors" }] },
        { text: "Tools", items: [{ text: "Verify a receipt in the browser", link: "/verify" }] },
        { text: "Hosted", items: [{ text: "Register", link: "https://app.agent-custody.dev/#register" }, { text: "Pricing", link: "/pricing" }, { text: "The hosted log", link: "/early-access" }, { text: "Security questionnaire", link: "/security" }, { text: "Privacy", link: "/privacy" }, { text: "Terms for early access", link: "/terms" }, { text: "Contact", link: "/contact" }] },
      ] },
      socialLinks: [{ icon: "github", link: "https://github.com/svayatta/agent-custody" }, { icon: "npm", link: "https://www.npmjs.com/org/agent-custody" }],
      footer: { message: 'Apache-2.0 · <a href="https://github.com/svayatta/agent-custody">GitHub</a> · <a href="https://www.npmjs.com/org/agent-custody">npm</a> · <a href="https://pypi.org/project/agent-custody/">PyPI</a> · <a href="/reference/">Docs</a> · <a href="/faq">FAQ</a> · <a href="/use-cases">Use cases</a> · <a href="/blog/">Writing</a> · <a href="/security">Security</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="/contact">Contact</a>', copyright: "Charioteer Consulting Ltd" },
      search: { provider: "local" },
    },
    markdown: {
      config(md) {
        // Links are written for the repository. Here they become site links where the target is a page of the site,
        // and repository links otherwise. Relative markdown links must be mapped through the rewrites by hand,
        // because VitePress resolves them against the source path, not the rewritten one.
        const root = resolve(__dirname, "..", "..");
        const open = md.renderer.rules.link_open ?? ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));
        md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
          const href = tokens[idx]!.attrGet("href");
          const file: string | undefined = env?.realPath ?? env?.path; // realPath is the source file when the page was rewritten
          if (href && file && !/^(https?:|mailto:|#|\/)/.test(href)) {
            const [path, hash = ""] = href.split("#");
            // Included fragments keep their source file's links, which are relative to the including file's original
            // location; when the link resolves to nothing next to the including file, try it from the repository root.
            // A link may name the page without its .md, as the reference pages do (`./gateway#grants`); resolve that
            // to the file, or the link becomes a repository URL that does not exist.
            const beside = resolve(dirname(file), path!);
            const candidates = [beside, `${beside}.md`, resolve(root, path!), `${resolve(root, path!)}.md`];
            const abs = candidates.find((c) => existsSync(c)) ?? beside;
            const target = posix.normalize(relative(root, abs).split("\\").join("/"));
            const page = sitePath(target);
            if (page) {
              tokens[idx]!.attrSet("href", page + (hash ? `#${hash}` : ""));
            } else {
              tokens[idx]!.attrSet("href", REPO + target + (hash ? `#${hash}` : ""));
              tokens[idx]!.attrSet("target", "_blank");
            }
          }
          return open(tokens, idx, options, env, self);
        };
      },
    },
  }),
);
