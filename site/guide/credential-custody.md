# Credential custody and egress lockdown

The gateway can only receipt calls that pass through it. If an agent holds a tool credential, or can reach the internet on its own, it can call the tool directly, and the gateway never sees that call. This page covers the two deployment steps that close that route:

1. **Credential custody.** Tool credentials live only in the gateway.
2. **Egress lockdown.** The agent's network reaches only the gateway and the [egress witness](/receipts/egress). The witness receipts and decides by policy every connection that is not a tool call.

Do both. Lockdown without custody leaves a credential the agent can use through any permitted destination. Custody without lockdown leaves the agent free to call public APIs, and to send data out, with nothing recorded.

## Credential custody: tool credentials live only in the gateway

- **Give the credential to the gateway, never the agent.** Each upstream's key is in the gateway's environment (`headerEnv` for the REST connector, `env` for a stdio server). See [configuring the gateway](/receipts/configuration). The agent holds its grant, which works only through the gateway and only for the tools in its scope.
- **Describe the API as gateway tools.** If agent code calls an HTTP API directly, describe its endpoints as REST tools in the gateway config, so the agent calls them through the gateway. [Deployment](/guide/deployment#where-interception-stops) has the details.
- **Keep the agent's environment clean.** Check the agent's container image, its environment, its mounted files, and its host config. Look for API keys, cloud credentials (an instance role or a mounted service account token counts), and a second MCP server entry that points at the tool directly. Set `automountServiceAccountToken: false` on the agent's pod unless the agent needs the Kubernetes API.
- **Check the gateway for leaks.** A stdio upstream starts with a minimal environment, never the gateway's, so one tool cannot read another tool's token. The console runs as a service of its own and is not given the gateway's credentials. `deploy/gateway/docker-compose.yaml` shows both.

What custody cannot do: it cannot take back a credential that the agent already copied, or one that a tool's output handed to the agent. Rotate a credential that was ever in an agent's environment.

## Egress lockdown: the agent reaches only the gateway and the witness

`deploy/gateway/lockdown` has the manifests.

**Kubernetes** (`lockdown/k8s`):

- A NetworkPolicy gives every agent pod labelled `agent-custody.dev/egress: locked` default-deny egress. It allows the gateway on 8790, the witness on 8791, and the cluster DNS.
- The witness runs as a Deployment beside the gateway, from the same image. Its own NetworkPolicy accepts connections only from locked agents. It refuses the cloud metadata address and private ranges on their behalf.
- A NetworkPolicy has no effect unless the cluster's network plugin enforces it. Calico, Cilium, and most managed CNIs do; flannel alone does not.

```bash
kubectl label namespace agents agent-custody.dev/agents=true
kubectl -n agent-custody-gateway create configmap egress-config --from-file=deploy/gateway/lockdown/config
kubectl -n agent-custody-gateway create secret generic egress-env --from-literal=EGRESS_SECRET_RESEARCH_AGENT="$(openssl rand -hex 32)"
kubectl apply -k deploy/gateway/lockdown/k8s
```

**Docker compose** (`lockdown/docker-compose.yaml`, an override for the gateway's compose file):

- The agent sits on an internal network (`internal: true`), which has no route out.
- The gateway and the witness sit on that network and on the default one. They are the only way out.
- Each agent's proxy secret goes in a file of its own, `lockdown/agents/<agent>.env`. The witness loads every agent's file, and each agent loads only its own, so no agent holds another's password.
- No proxy secret goes in `.env`. The gateway loads that file, and a gateway that held a witness password could connect through the witness as that agent. The gateway image runs no command but `egress` (the gateway, the console, init, or a CLI command) when any `EGRESS_SECRET_*` variable is in its environment, and names the variable without printing its value. `docker exec` does not go through the image's entrypoint, but a running gateway container has already passed that check.
- The agent builds its `HTTPS_PROXY` from its own secret when it starts (the stand-in's entrypoint shows how), so compose never interpolates the secret from the shell or `.env`. A blank secret stops the agent.
- The compose files use the long form of `env_file` (`path`, `required`), which needs Docker Compose 2.24 or later.

```bash
cd deploy/gateway
cp lockdown/agents/research-agent.env.example lockdown/agents/research-agent.env   # set the secret: openssl rand -hex 32
chmod 600 lockdown/agents/research-agent.env
docker compose -f docker-compose.yaml -f lockdown/docker-compose.yaml --profile demo-agent up -d
```

On Kubernetes and in compose alike, the witness runs from the gateway image in `egress` mode. It creates its own signing key on first start and prints the public half in its log. Give that key to whoever verifies its receipts; it is not the gateway's key.

On Docker, the witness sits on the default network, so it can reach the host, the other services, the private ranges, and the metadata address, which the agent cannot. Compose has no equivalent of the Kubernetes exception list. The witness itself refuses an internal address for a host name before it connects. It dials an IP literal only when the policy names that address, so do not permit internal addresses. On a cloud VM, also block the metadata address for the witness's container in the host firewall.

**A VM or bare metal** (`lockdown/vm`): each agent runs as its own Unix user, and the gateway and the witness run beside it as systemd services.

- `agent-lockdown.nft` is an nftables table that matches the agent's user (`meta skuid`). Whatever that user runs may reach only the gateway on 8790 and the witness on 8791. Everything else, loopback and the DNS resolver included, is logged and refused. The agent reaches both by address, and the witness resolves every other name, so the agent needs no DNS. A resolver that forwards to the internet would carry data in its queries that the witness does not see. An agent that must resolve names gets commented-out lines for a resolver on loopback. Packets from every other user, the gateway and the witness among them, are not touched.
- `agent-custody-lockdown.service` loads that table at boot and replaces only that table. Do not load it through `nftables.service`: on Debian and Ubuntu that service runs `/etc/nftables.conf`, which starts with `flush ruleset` and deletes every other table on the host, docker's and ufw's included. Every start and reload of that service also deletes our table. `nftables-lockdown.conf` is a drop-in for that service that loads our table again after each one. If that load fails, the drop-in stops the agent.
- `agent-lockdown.conf` is a systemd drop-in for the agent's own unit. It requires `agent-custody-lockdown.service`, so an agent whose table fails to load stays down. It runs the agent as that user with `NoNewPrivileges`, and allows only IP, Unix, and netlink sockets (`RestrictAddressFamilies=`), so the agent cannot use vsock to reach the hypervisor. It loads the proxy settings from a root-only file, and sets `IPAddressDeny=any` plus `IPAddressAllow=` for the gateway and the witness. Like the table, it allows no resolver, and an allow would open every port on that address.
- `agent-custody-egress.service` runs the witness under a user of its own, with the same `egress.json` as the other recipes. It denies the witness the internal ranges from its own address list, including the metadata addresses, so a policy that permits a private IP literal is still refused. NAT64 (`64:ff9b::/96`) stays open, since an IPv6-only host sends all public traffic there, so do not permit a NAT64 literal. The gateway uses the existing `deploy/gateway/agent-custody-gateway.service`.
- `check-lockdown.sh` runs the three tests below as the agent user. It reads the agent's proxy secret from `/etc/agent-custody/agent.env`, or from a file named by `EGRESS_SECRET_FILE`, so the secret stays off the command line and out of `ps`. With `--unit`, it runs them inside the agent unit's IP filter. Before the direct probe, it makes the same connection as root, so a host with no route out cannot pass for a locked-down one. Check 2 opens the new receipt and requires the refused host and `denied`. A fourth check opens a port of its own on loopback and requires that the agent cannot reach it over IPv4 or IPv6. The drop-in alone fails that check.

Use the nftables rule and the drop-in together. The nftables rule covers everything the user runs, a cron job or a shell included, and it matches ports. The drop-in holds even if the host firewall is flushed. But `IPAddressAllow=` takes addresses, not ports, so allowing `127.0.0.1` allows every service on loopback. Neither can hold an agent that changes user, so give the agent user no sudo and keep it out of the docker group. CI installs this recipe on a fresh Ubuntu runner. It runs the checks with no lockdown, which must fail, then with the whole recipe, then with the drop-in alone. It also checks that the table comes back after a start or a reload of `nftables.service`. It checks that a table that fails to load keeps the agent down, that the agent gets no answer from the host's DNS resolver while root does, that the agent's unit refuses vsock, and that the witness refuses a private address its policy permits.

```bash
sudo useradd --system --home /var/lib/agent --create-home --shell /usr/sbin/nologin agent
sudo install -D -m 0644 deploy/gateway/lockdown/vm/agent-lockdown.nft /etc/agent-custody/agent-lockdown.nft  # edit the addresses
sudo install -m 0644 deploy/gateway/lockdown/vm/agent-custody-lockdown.service /etc/systemd/system/
sudo install -D -m 0644 deploy/gateway/lockdown/vm/nftables-lockdown.conf /etc/systemd/system/nftables.service.d/agent-custody-lockdown.conf
sudo systemctl daemon-reload && sudo systemctl enable --now agent-custody-lockdown
sudo install -D -m 0644 deploy/gateway/lockdown/vm/agent-lockdown.conf /etc/systemd/system/my-agent.service.d/lockdown.conf
sudo systemctl daemon-reload && sudo systemctl restart my-agent
sudo deploy/gateway/lockdown/vm/check-lockdown.sh --unit my-agent.service
```

The header of each file lists the remaining steps, such as the witness's user and key.

**The witness's resolver.** The witness resolves names through `/etc/resolv.conf`, and its unit denies the private and link-local ranges. Where that file names the systemd-resolved stub, `127.0.0.53` (the default on Ubuntu and Amazon Linux 2023), nothing more is needed: the witness talks only to loopback, and resolved queries the VPC resolver from its own unit, which the witness's deny list does not cover. Where the file names the VPC resolver directly, the witness can resolve nothing until you allow that one address in its unit: `169.254.169.253` or the VPC base + 2 (such as `10.0.0.2`) on AWS, or `169.254.169.254` on GCP, which is also the metadata service. Add a drop-in with `IPAddressAllow=` for it. That allow opens every port on the address. Azure's `168.63.129.16` is a public address, so it is not denied.

**Other setups.** The witness itself runs anywhere: `agent-custody egress` is a Node 22 process, from npm or the gateway image. The lockdown is the part that depends on the platform. Anywhere else, build the same default-deny egress with the platform's own controls. The rule is always the same: from the agent, allow only the gateway, the witness, and DNS, and drop everything else.

- **Cloud tasks and instances** (ECS, Cloud Run, EC2, GCE, Azure). Give the agent a security group or firewall rule with no general egress, only the gateway and the witness. On a serverless function in a VPC, the agent must have no NAT route out. On an instance you manage yourself, the VM recipe above applies inside it too.
- **A developer laptop.** An agent that runs as you, with your network, cannot be locked down, and the witness is only advice there. Run the agent in a container with the compose override instead.

These two are mechanisms, not recipes. We have not shipped or tested a file for them. Whatever you build, run the three tests below before you rely on it.

**The agent's settings:**

- `HTTPS_PROXY` and `HTTP_PROXY`: `http://<agent id>:<secret>@<witness>:8791`.
- `NO_PROXY`: the gateway's host.
- Give each agent its own secret. Each agent's receipts then name that agent, and you can revoke one agent without the others.

**Test it.** Do not assume it works. From the agent's container or user:

- a direct connection that ignores the proxy must fail to connect;
- a connection through the witness to a destination the policy does not permit must get `403` and leave a receipt;
- a tool call through the gateway must still work.

## What the witness sees and does not see

| | seen | not seen |
| --- | --- | --- |
| a CONNECT tunnel (HTTPS) | the agent (by its proxy credential), the host and port, the address connected to, the times, the bytes each way | anything inside the tunnel: no TLS interception |
| a plain HTTP request | the same, plus the method and the status | the path, the headers, and the bodies |
| traffic when lockdown is off | nothing, if the agent ignores `HTTPS_PROXY` | everything |
| non-HTTP protocols | under lockdown, they cannot leave | without lockdown, everything |
| DNS | not relayed by the witness | queries to a resolver that forwards to the internet |

Each egress receipt is an observed bypass: it shows that the agent connected somewhere around the gateway. It is not a record of what the agent did there. For calls that need that record, put the tool behind the gateway.

[The egress witness](/receipts/egress) has the config, the policy model, and the receipt. [The threat model](/receipts/threat-model) has the row it changes.
