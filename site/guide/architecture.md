# Architecture

How agent-custody is put together, what runs on the customer's side, what runs on ours, and what changes in the agent. The diagrams are the maps; [Deployment](/guide/deployment) says what each setup proves, and [What each piece is for](/guide/pieces) says when to turn each one on.

## The split in one picture

Almost everything runs in the customer's environment. The one thing a customer cannot run for themselves is a log that is not theirs, so that is the only thing hosted. The hosted log holds hashes, not receipts.

```mermaid
flowchart LR
    subgraph CUST["Customer infrastructure"]
        direction TB
        AG["Agent host<br/>Claude Code, LangGraph,<br/>OpenAI Agents, own loop"]
        GW["Gateway<br/>agent-custody gateway"]
        TL["Tools<br/>Stripe, GitHub, memory server,<br/>REST APIs, other agents over A2A"]
        FS[("Receipts directory<br/>full receipts, arguments and results")]
        CFG["Grant, Cedar policy,<br/>revocation list, gateway config"]
        KEYS["Keys<br/>gateway key (private)<br/>principal key (signs grants)"]
        OBS["Optional export<br/>OpenTelemetry, Splunk"]
        AG -- "MCP, one line of host config changed" --> GW
        GW -- "MCP or REST, only on allow" --> TL
        GW --> FS
        CFG --> GW
        KEYS --> GW
        GW -.-> OBS
    end
    subgraph HOST["Hosted by us: log.agent-custody.dev"]
        direction TB
        LOG["Log server<br/>per-tenant Merkle log, hash-only"]
        SIG["Signer<br/>alone holds the log key"]
        CP[("Checkpoints<br/>second host, signed")]
        WIT["Witness<br/>countersigns checkpoints"]
        PORT["Tenant portal<br/>register, keys, usage, billing, export"]
        LOG --> SIG
        LOG --> CP
        CP --> WIT
        PORT --> LOG
    end
    GW -- "leaf hash over HTTPS, bearer token" --> LOG
    V["Verifier<br/>auditor, counterparty, CI job"]
    FS -. "receipt bundle" .-> V
    LOG -. "tree heads, checkpoints, public keys" .-> V
```

| runs on the customer's side | runs on ours |
| --- | --- |
| the gateway, in front of the tools | the log server for each tenant, at `/t/<tenant>/` |
| the gateway key, the principal key, the grant, the Cedar policy, the revocation list | the signer that holds the log's key, apart from the process facing the internet |
| the tool credentials (Stripe key and the like), held by the gateway, not the agent | signed checkpoints on a second host, and the outside monitor |
| the full receipts, with arguments and results, under the customer's capture rules | the tenant portal: registration, tokens, usage against the plan, billing, export |
| the optional memory server and its ledger | the witness software, which must run on a machine the log's operator does not control; no independent operator runs one for our log yet |

A customer who does not want a hosted log runs the same server from the container, the compose file, or the Kubernetes manifests in `deploy/`.

## The shared gateway service

For one agent session the host spawns the gateway on stdio and there is nothing to operate. For every agent on a host or cluster, run one shared gateway as a service (`ghcr.io/svayatta/agent-custody-gateway`, amd64 and arm64): each agent connects over HTTP and presents its own grant, and the tool credentials live in the gateway.

```mermaid
flowchart LR
    subgraph AGENTS["Agents, any framework"]
        A1["Agent A"]
        A2["Agent B"]
        A3["Agent C"]
    end
    TLS["TLS in front<br/>Caddy, ingress or mesh"]
    subgraph GWC["Gateway container, one replica"]
        GWS["agent-custody gateway --http<br/>one session per grant"]
        CFGV["/config, read-only<br/>gateway.json, policy.cedar,<br/>principals' public keys"]
        DATA[("/data<br/>gateway key, receipts,<br/>local log, revoked.json")]
        ENVV["environment<br/>tool credentials, log token"]
        CFGV --> GWS
        ENVV --> GWS
        GWS --> DATA
    end
    UP["Tools<br/>REST, MCP, A2A"]
    LOGH["Hosted log"]
    A1 -- "grant A" --> TLS
    A2 -- "grant B" --> TLS
    A3 -- "grant C" --> TLS
    TLS --> GWS
    GWS -- "only on allow" --> UP
    GWS -- "leaf hash" --> LOGH
```

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant TLS as TLS proxy
    participant GW as Shared gateway
    Agent->>TLS: initialize, Authorization: Bearer base64url(grant)
    TLS->>GW: the same request
    GW->>GW: verify the grant against trustedPrincipalKeys, window, revocation list
    alt grant missing, forged, expired or revoked
        GW-->>Agent: 403 with the reason, no session
    else grant valid
        GW-->>Agent: session id, tools limited to the grant's scopes
    end
    loop every call of the session
        Agent->>GW: tools/call with the session id
        GW->>GW: grant checked again, then the call path above
        GW-->>Agent: result or reason, receipt id
    end
    Note over GW: a revoked or expired grant ends its session on the next request
```

An admin console runs from the same image as a separate service, with a token of its own: it reads the gateway's config, receipts and revocation file, edits the policy file, and revokes grants. It holds no principal key and signs nothing, and the gateway does not serve any admin page. See [the console](/receipts/console).

[Running the gateway as a service](../../deploy/gateway/README.md) has the commands, the Kubernetes and systemd recipes, and what goes where. Its limits are part of the design:

- A grant is a bearer credential: whoever holds it can connect as that agent until it expires or is revoked. Short lifetimes, a private network or mutual TLS, and revocation are the controls.
- The transport is plain HTTP, so TLS comes from a proxy or mesh in front.
- One replica: sessions are held in memory and the local log has one writer.
- One policy and one gateway key apply to every agent on it; one gateway per team where that is not acceptable.
- One process holds every agent's tool credentials, which is the point and also the blast radius.

## What the agent has to change

| agent type | change | what you get |
| --- | --- | --- |
| uses MCP tool servers | name the gateway where the host named the tool server, and remove the direct route | enforcement: a denied call never reaches the tool, and the record is `observed` |
| calls a REST API | describe the endpoints as tools in the gateway config; the credential moves to the gateway | the same, for REST |
| plain function tools | wrap them with the framework adapter, or send them through the sidecar | a record only: every field is `claimed`, because the process describes itself |
| any agent | take tool credentials out of the agent's environment | the gateway cannot be bypassed |

The agent never calls agent-custody. If it holds a credential of its own, nothing here sees what it does with it.

## The pieces and how they depend on each other

```mermaid
flowchart TB
    subgraph REC["@agent-custody/receipts"]
        GWY["gateway.ts<br/>stdio, HTTP, A2A fronts"]
        DEL["delegation.ts<br/>grants and chains"]
        POL["policy.ts<br/>Cedar evaluation"]
        APP["approval.ts<br/>payload-bound human approvals"]
        OPS["operations.ts<br/>financial operations"]
        ISS["issue.ts<br/>sign, append, bundle"]
        UPS["upstream.ts, rest.ts, a2a.ts<br/>tool connectors"]
        SDK["sdk/<br/>framework adapters, sidecar"]
        LGS["log-sink.ts, log.ts<br/>local file or remote log client"]
        VER["verify.ts<br/>offline verifier"]
        LGSRV["log-store.ts, signer.ts, checkpoints.ts,<br/>witness.ts, portal.ts<br/>the hosted log's server side"]
        GWY --> DEL
        GWY --> POL
        GWY --> APP
        GWY --> OPS
        GWY --> UPS
        GWY --> ISS
        SDK --> ISS
        ISS --> LGS
        LGS -- "HTTP" --> LGSRV
        VER -. "reads receipts and log" .-> ISS
    end
    subgraph ST["@agent-custody/state"]
        LED["ledger.ts<br/>bitemporal fact ledger"]
        SRV["server.ts<br/>memory server, an upstream of the gateway"]
        BL["blast.ts<br/>what depended on a belief"]
        RV["review.ts, case-file.ts, explain.ts<br/>review console, case files"]
        SRV --> LED
        BL --> LED
        RV --> LED
    end
    PY["agent-custody on PyPI<br/>sidecar client and adapters"]
    PY -- "HTTP" --> SDK
    UPS -- "MCP" --> SRV
    BL -. "reads receipts" .-> ISS
    RV -. "verifies with" .-> VER
```

## The data model

```mermaid
classDiagram
    class Delegation {
        version
        principal
        agent
        scopes[]
        issuedAt
        expiresAt
        agentKey?
        parent?
    }
    class Envelope {
        payloadType
        payload
        signatures[]
    }
    class ReceiptBundle {
        envelope
        treeHead
        inclusion
    }
    class ReceiptStatement {
        subject
        predicateType
        predicate
    }
    class ReceiptPredicate {
        receiptId
        issuer
        principal
        agent
        delegation
        tool
        request
        facts
        policy
        execution
        authorization?
        approval?
        capture?
    }
    class Execution {
        status
        reason?
        result?
        provenance
    }
    class TreeHead {
        treeSize
        rootHash
        timestamp
        log?
    }
    class InclusionProof {
        leafIndex
        treeSize
        hashes[]
    }
    Delegation --> Envelope : signed as DSSE by the principal
    Delegation --> Delegation : parent, narrower sub-grant
    ReceiptBundle *-- Envelope : statement
    ReceiptBundle *-- Envelope : tree head
    ReceiptBundle *-- InclusionProof
    Envelope ..> ReceiptStatement : payload
    Envelope ..> TreeHead : payload
    ReceiptStatement *-- ReceiptPredicate
    ReceiptPredicate *-- Execution
    ReceiptPredicate --> Delegation : the grant chain travels inside
```

Every field of the predicate carries a provenance label: `attested` (signed by a key other than the issuer's), `observed` (the gateway obtained it itself), or `claimed` (the agent said so). [The receipts overview](/receipts/) has the full table.

## One tool call

The order is fixed. A denial at any step still produces a signed receipt, and a tool in `precommit` is authorized in the log before it is forwarded.

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant GW as Gateway (customer side)
    participant Up as Upstream tool
    participant Log as Hosted log
    Agent->>GW: tools/call stripe.refund {customer_id, amount}
    GW->>GW: grant in force? signature, window, not revoked
    GW->>GW: tool in the grant's scopes?
    GW->>GW: approval required and valid?
    GW->>Up: fact lookups, e.g. customer.lookup
    Up-->>GW: result, recorded as observed
    GW->>GW: Cedar policy on args, facts and grant
    alt denied at any step above
        Note over GW: nothing reaches the tool
    else allowed, tool is in precommit
        GW->>Log: append the signed authorization
        Log-->>GW: tree head and inclusion proof
        alt log refuses or is unreachable
            Note over GW: call is withheld, not forwarded
        else log accepted
            GW->>Up: forward the call
            Up-->>GW: result
        end
    else allowed, ordinary tool
        GW->>Up: forward the call
        Up-->>GW: result
    end
    GW->>GW: sign the receipt statement
    GW->>Log: append the leaf hash
    Log-->>GW: signed tree head and inclusion proof
    GW->>GW: write the bundle to receipts/
    GW-->>Agent: result or reason, receipt id in _meta
```

The status the receipt records is one of five:

```mermaid
stateDiagram-v2
    [*] --> Checked
    Checked --> denied : grant, scope, approval or Cedar says no
    Checked --> withheld : log would not take the authorization, or grant lapsed before forwarding
    Checked --> Forwarded : allowed
    Forwarded --> executed : upstream answered
    Forwarded --> failed : upstream answered with an error
    Forwarded --> error : upstream unreachable
    denied --> [*]
    withheld --> [*]
    executed --> [*]
    failed --> [*]
    error --> [*]
```

## Onboarding a new customer

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Customer admin
    participant CLI as agent-custody CLI
    participant Portal as Hosted portal
    participant GW as Customer gateway
    participant Log as Hosted log
    Admin->>CLI: keygen, gateway key and principal key
    Admin->>Portal: register, receive tenant and first token (shown once)
    Admin->>CLI: grant --key principal.key --agent --scopes --ttl-hours
    CLI-->>Admin: grant.json, signed by the principal
    Admin->>Admin: write policy.cedar and gateway.json (log url, hashOnly, precommit)
    Admin->>GW: start with the token in the environment
    GW->>Log: first append (log keys fetched and pinned)
    Note over Admin,GW: policy in observe mode first, then enforce
    Admin->>CLI: verify a receipt with the public keys
    CLI-->>Admin: all checks pass
```

## Revoking a grant mid-session

```mermaid
sequenceDiagram
    autonumber
    participant Agent as support-agent
    participant Sub as lookup-agent (delegated)
    participant GW as Gateway
    participant File as revoked.json
    actor Op as Operator
    Agent->>GW: stripe.refund
    GW-->>Agent: executed, signed receipt
    Sub->>GW: customer.lookup
    GW-->>Sub: executed, signed receipt
    Op->>File: agent-custody revoke --config --grant
    Note over File: digest of the grant's signed payload appended
    Agent->>GW: stripe.refund
    GW->>File: re-read when it changed
    GW-->>Agent: denied, delegation grant has been revoked, signed receipt
    Sub->>GW: customer.lookup
    GW-->>Sub: denied, the revocation covers every grant delegated from it
```

Revocation is per grant and takes effect on the next call, with no restart and no key rotation. The Cedar policy is re-read the same way: a changed `policy.cedar` applies from the next call, a policy that does not parse is refused and the one in force stays, and every change is recorded with both digests.

## Verifying a receipt without trusting the operator

```mermaid
sequenceDiagram
    autonumber
    actor Auditor
    participant V as Verifier (offline)
    participant Log as Hosted log
    participant W as Witness
    Auditor->>V: receipt bundle, gateway and principal public keys
    V->>V: signature, statement, grant chain, policy digest
    V->>V: inclusion proof places this leaf under the tree head
    Auditor->>Log: fetch the log's published keys
    V->>V: tree head signed by the log's key, expected log id
    opt audit against a kept earlier head
        Auditor->>Log: consistency proof and checkpoints
        V->>V: the log still extends the earlier head
        Auditor->>W: witness countersignature
        V->>V: checkpoint countersigned, no alarm raised
    end
    V-->>Auditor: verified, or the check that failed
```

## What this does and does not cover

- **Only calls through the gateway.** A credential in the agent's environment, a second direct route in the host config, or code that calls an API on its own is outside it. Taking those away is a deployment decision: [credential custody and lockdown](/guide/credential-custody) shows how, and the egress witness receipts the direct connections that remain.
- **The SDK and sidecar record, they do not prove.** They run in the process they describe, so their receipts are `claimed`.
- **The hosted log does not see grants or policy.** It sees leaf hashes. A receipt names the grant and carries the policy digest, and a verifier checks both against public keys.
- **The operator can rewrite a local log.** A remote log, published checkpoints, and a witness are what detect that. The witness ships in the package, but a second, independent operator for our log is still being sought, so today the checkpoints are published and the witness step is not yet independent.
- **There is no hosted control plane yet.** Grants, revocation and Cedar policy are managed on the customer's gateway; the portal manages the log, tokens, usage and billing.
- **Failure mode:** a `precommit` tool is withheld while the log is unreachable. That is deliberate and it is a denial of service on the agent.
- **Egress is witnessed only under lockdown, and never inspected.** The [egress witness](/receipts/egress) is a forward proxy. It receipts, and decides by policy, the connections an agent makes around the gateway. It records the destination, the times, and the byte counts. It never records the payload, because there is no TLS interception, so a receipt shows an observed bypass, not what was done. It sees only traffic sent to it: with no [lockdown](/guide/credential-custody), an agent can ignore `HTTPS_PROXY`, and a protocol other than HTTP never reaches it.

See [the threat model](/receipts/threat-model) for who could make a receipt false and what stops them, and [the hosted log reference](/reference/hosted) for the log's routes.
