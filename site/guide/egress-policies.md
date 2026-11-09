# Writing egress policies

The [egress witness](/receipts/egress) decides each connection that an agent makes around the gateway with a Cedar policy. This page shows how to write that policy. Each example on it is run against the real evaluator by `packages/receipts/test/docs-egress-policies.test.ts`, in the same way as the examples in [writing policies](/receipts/policies). The exact contract is in the [reference](/reference/egress).

## What the policy sees

For each `CONNECT host:port`, and for each plain `GET http://host[:port]/…`, the witness asks Cedar one question:

- **Principal:** `Agent::"<id>"`, but only when the agent's `Proxy-Authorization` verified. Otherwise it is `Agent::"unknown"`, and the witness answers 407 whatever the policy says.
- **Action:** the destination as `host:port`, for example `Action::"registry.npmjs.org:443"`. The host is lowercase, with no final dot. An IPv6 address is in brackets: `Action::"[fd00::5]:8443"`.
- **Resource:** the same string. Leave it as `resource`.
- **`context.facts.destination`:** what the witness observed, `{ host, port, scheme, credential, declared?, remote }`. `scheme` is `connect` for a tunnel and `http` for a plain request. `credential` is `verified`, `invalid`, or `absent`.
- **`context.args`:** `{ method, host, port }`, as the agent asked. They hold the same values, but write conditions on `context.facts.destination`: that is the record the witness signs as observed.

Nothing is permitted unless a rule permits it. A rule that fails to evaluate counts as a deny.

## An allow list per agent

Start with an allow list for each agent, naming each destination:

```cedar
// The research agent may reach the package registry and the Python docs over TLS. Nothing else.
permit(
  principal == Agent::"research-agent",
  action in [Action::"registry.npmjs.org:443", Action::"docs.python.org:443"],
  resource
);
```

Another agent that asks for the same hosts is refused, and so is the research agent on port 80. Write one `permit` for each agent. A rule with no `principal ==` applies to every agent that has a verified credential.

## Wildcard hosts with `like`

To allow a whole domain, match the observed host with `like`. In a `like` pattern, `*` stands for any run of characters, dots included:

```cedar
// The build agent may reach example.com and any host under it, on 443.
permit(principal == Agent::"build-agent", action, resource)
when {
  context.facts.destination.port == 443 &&
  (context.facts.destination.host == "example.com" || context.facts.destination.host like "*.example.com")
};
```

**`*.example.com` does not match `example.com`.** The pattern needs the dot before `example.com`, and the bare domain has none. If you mean the domain itself as well, add it by name, as the rule above does.

**Never drop the dot.** `*example.com` looks like the same rule, but it matches any host whose name ends in those letters, including a domain someone else registered:

```cedar
// Do not write this: "evilexample.com" ends in "example.com" too.
permit(principal == Agent::"build-agent", action, resource)
when { context.facts.destination.host like "*example.com" };
```

## Ports

The port is part of the action. `Action::"registry.npmjs.org:443"` does not match port 80 or 8443. When a rule matches on the host, also check `context.facts.destination.port`. Otherwise the rule allows every port on that host:

```cedar
// The mirror serves HTTPS on 443 and plain HTTP on 80. Nothing else on that host is allowed.
permit(principal == Agent::"build-agent", action, resource)
when {
  context.facts.destination.host == "mirror.example.net" &&
  [80, 443].contains(context.facts.destination.port)
};
```

To allow only tunnels, which carry TLS end to end, add `context.facts.destination.scheme == "connect"`. A plain HTTP request (`scheme == "http"`) is relayed in clear.

## IP literals

When an agent connects to an address rather than a name, the policy decides on the address, written in one canonical form. The witness parses an IPv4 address as the URL parser does: `2130706433` and `0x7f.1` become `127.0.0.1`, and `010.0.0.1` becomes `8.0.0.1`. An IPv6 address is written in its short form, in brackets. So a rule on an address cannot be dodged by spelling the address another way:

```cedar
// The research agent may reach one service on the private network, by its address.
permit(principal == Agent::"research-agent", action == Action::"10.20.0.5:8443", resource);
```

`0xa.20.0.5:8443` matches this rule too, because it names the same address.

**An IP literal is never looked up, so the witness's internal-address filter never sees it.** For a host name, the witness drops loopback, private, link-local, and metadata addresses (`169.254.169.254`) from the DNS answer before it connects. An address the agent wrote is the Cedar action itself, and when a rule permits it, the witness dials it. The rule above reaches `10.20.0.5` because you named it. **Only the platform's own deny list refuses an internal address that a rule permits.** On Kubernetes, that list is `deploy/gateway/lockdown/k8s/egress-networkpolicy.yaml`. Docker compose has no such list: the witness can reach the host, the private ranges, and the metadata address, so on a cloud VM block the metadata address in the host firewall too. On any other platform, the deny list is the firewall you build, as [credential custody and lockdown](/guide/credential-custody) describes.

That makes a rule with no condition on the destination dangerous:

```cedar
// Do not write this: it permits every destination, and 169.254.169.254:80 is a destination.
permit(principal == Agent::"research-agent", action, resource);
```

Do not try to forbid address ranges with Cedar's `ip()` either. `ip()` fails on a host name. A rule that fails makes the decision a deny, so the rule below refuses every connection to a name:

```cedar
// Do not write this either: ip("docs.python.org") is an error, and an error denies.
permit(principal == Agent::"research-agent", action, resource)
when { context.facts.destination.host == "docs.python.org" };
forbid(principal, action, resource)
when { ip(context.facts.destination.host).isLoopback() };
```

Name each destination, and leave internal ranges to the platform's deny list.

## Providers that need a credential belong in the gateway

Do not permit `api.stripe.com`, `api.openai.com`, or any other provider that needs a credential. Call it through the gateway instead.

- **The gateway holds the key.** Under [credential custody](/guide/credential-custody), the agent does not have it. A permit on the provider is useful only to an agent that has a key of its own, and that is the bypass the witness exists to catch.
- **The gateway decides on the call.** It sees which tool was called and with which arguments, such as a refund of 4,500 pence for this customer. The witness sees only `api.stripe.com:443`, because the tunnel is encrypted. A permit here would allow every call to that provider.
- **The gateway's receipt records the call.** The witness's receipt records only that a connection was made, with its times and byte counts.

Leave these hosts unpermitted. A direct call to one is then refused, and its receipt is evidence of the attempt.

## `forbid` overrides every `permit`

A `forbid` that matches wins, whatever else permits the connection. Use it for carve-outs from a broad rule, and for destinations that must stay closed whatever is added later:

```cedar
// Any verified agent may reach hosts under example.com on 443 ...
permit(principal, action, resource)
when {
  context.facts.destination.credential == "verified" &&
  context.facts.destination.port == 443 &&
  context.facts.destination.host like "*.example.com"
};

// ... except the paste service under it.
forbid(principal, action, resource)
when { context.facts.destination.host == "paste.example.com" };

// Providers go through the gateway, which holds their keys, even if a later permit would match them.
forbid(principal, action, resource)
when { ["api.stripe.com", "api.openai.com", "api.anthropic.com"].contains(context.facts.destination.host) };
```

## Rolling out: observe, draft, review, enforce

A first policy is easier to write from what the agents actually do than from a guess.

1. **Observe.** Set `"mode": "observe"` in `egress.json`, with any policy, even an empty one. The witness then relays every connection from a verified agent. It records the policy's decision with `enforced: false` and receipts the connection as usual. A connection without a valid credential is still refused with 407.
2. **Draft.** After a representative window (a release cycle, or a week), draft a policy from the receipts:

   ```bash
   agent-custody egress draft-policy --receipts receipts --issuer-key keys/egress.pub --log log.jsonl > egress-policy.draft.cedar
   ```

   The command reads only regular files in the directory, never through a symlink. It verifies each receipt and skips any that does not verify, naming it on stderr. It keeps the connections that the witness relayed for a verified agent. It prints one `permit` per agent and scheme over the `host:port` destinations that agent used, sorted and with no duplicates. A plain request and a tunnel to the same `host:port` are the same action, so each permit names the scheme it saw: an observed plain GET never becomes a permitted CONNECT tunnel. Each permit and each destination has a comment with its count and the times it was first and last seen.
3. **Review.** The draft starts with a warning, and the warning is meant literally: the draft permits whatever the agents did in the window, including any destination they should not have reached. Read each line. Delete each destination you do not recognise and each provider that belongs in the gateway. Merge hosts into a `like` rule where that is what you mean. A destination marked `INTERNAL ADDRESS` is an IP literal in a private or reserved range. The witness dials it if a rule permits it, as described [above](#ip-literals).
4. **Replay.** Check the reviewed policy against the same receipts before you enforce it. `agent-custody policy simulate` lists every connection whose decision would change:

   ```bash
   agent-custody policy simulate --policy egress-policy.cedar --receipts receipts --issuer-key keys/egress.pub
   ```

   An observe-mode witness writes a receipt for a 407 that does not verify today. `draft-policy` skips that receipt, but `policy simulate` stops on it. Move such receipts aside before you replay.
5. **Enforce.** Point `policyFile` at the reviewed policy and set `"mode": "enforce"`. The witness re-reads the policy file when the file changes, but it reads the mode only at start, so restart the witness.

Tutorial [42-egress-draft.ts](/receipts/tutorials) runs these steps. A review catches the agent's visit to a paste site, and the enforced policy refuses it.

## How a refused connection shows up

When the policy refuses a connection, the witness relays nothing and answers 403 with a JSON body:

```json
{ "error": "refused by the egress policy", "reason": "no permit policy matched", "receipt": "4d0c…" }
```

When a `forbid` refused it, `reason` names the rule by its position in the file: `policy0` is the first rule, `policy1` the second, and so on. The receipt id is also in the `x-agent-custody-receipt` header. A tunnel client often shows only "403 Forbidden" from the proxy, so look the receipt up.

The receipt is a `denied` receipt with `issuer.kind: "egress"`. It names the agent, the destination as the observed tool name, the decision, and the reason. It sits in the log like any other receipt, and anyone with the witness's public key can check it:

```bash
agent-custody verify receipts/<id>.json --issuer-key keys/egress.pub --log log.jsonl
```

A connection with no valid credential gets a 407 and a `denied` receipt whose agent is `unknown`. In observe mode, nothing is refused for the policy: the receipt is `executed`, and its decision carries `enforced: false`. `agent-custody policy simulate` and `egress draft-policy` read these receipts.
