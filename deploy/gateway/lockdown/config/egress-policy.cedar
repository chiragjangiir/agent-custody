// What a locked-down agent may reach directly, around the gateway. The action is the destination, host:port.
// Everything not permitted is refused and receipted. Tool calls that need a credential belong in the gateway,
// which holds the credential: do not permit a provider here (api.stripe.com, api.openai.com, ...).

// The research agent may read the package registry and the public docs over TLS.
permit(principal == Agent::"research-agent", action in [Action::"registry.npmjs.org:443", Action::"docs.python.org:443"], resource);

// Any known agent may reach hosts under example.com on 443; context.facts.destination is the witness's own observation.
permit(principal, action, resource)
when { context.facts.destination.credential == "verified" && context.facts.destination.port == 443 && context.facts.destination.host like "*.example.com" };
