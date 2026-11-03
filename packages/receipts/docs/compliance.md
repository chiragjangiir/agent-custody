# What the evidence satisfies

Auditors ask for controls by their names. This page maps the requirements they cite most to the artefacts agent-custody produces, so a security questionnaire can be answered with a file rather than a paragraph. It is a map, not a certificate: the artefacts are evidence that a control operated, and the control itself, the policy, the grant, the retention window, the person who reviews an alarm, is yours.

This page is dated. The SOC 2, ISO/IEC 27001, and UK GDPR sections below are not re-checked against primary text since they were first written. The section "Regulations and frameworks for AI agents" carries a primary source and an "as of" date for each framework. No part of this page says that the product makes you compliant.

Two rules keep the answers honest. First, say which producer made the receipt: a gateway receipt was enforced outside the agent's process, an SDK receipt is the agent's own report, and the receipt's `issuer.kind` says which. Second, say where the log runs: with the default local log the operator can rewrite history, with a log run by someone else they cannot, and with a witness neither operator can. The [proof table](../README.md#what-a-receipt-proves-and-what-it-does-not) has the full list of claims and against whom each holds.

## The artefacts

| artefact | what it is | how to produce it |
| --- | --- | --- |
| receipt | one signed record per tool call: who authorized it, what the agent saw, what it did, the policy decision, its position in the log | issued by the gateway or the SDK; `receipts/<id>.json` |
| authorization | the same, committed to the log before a consequential call was forwarded | `precommit` in the gateway config |
| verification report | the check list a third party gets from the receipt and public keys alone | `agent-custody verify` |
| audit | proof that the log at a later size extends its earlier state | `agent-custody audit` between any two tree heads or checkpoints |
| checkpoint | a signed tree head published on a schedule, countersigned by a witness where one runs | the log's checkpoints host, the witness's host |
| action pack | one receipt explained and packed with every downstream receipt, signed | `agent-custody-memory explain --out --sign` |
| custody pack | one fact's history, receipts, blast radius, holds, and forget certificate, signed | `agent-custody-memory pack` |
| forget certificate | the receipt of the call that erased a value from the ledger and the stores, with each store's answer | `memory.forget` through the gateway |
| eval report | scores for stale reads, contradictions, and blast radius after retraction, signed | `agent-custody-memory eval --sign` |
| usage | appends per tenant per month on the hosted log | `/admin/usage.csv` |

## SOC 2, Trust Services Criteria

| criterion | what it asks | what answers it |
| --- | --- | --- |
| CC6.1, logical access | access to systems is restricted to authorized users | the delegation grant: a human-signed statement of which agent may call which tools, for how long, embedded in every gateway receipt and re-checked by the verifier |
| CC6.3, authorization changes | access is granted, modified, and removed by authorized parties | grants have validity windows and are signed by a principal key the gateway is configured to trust; a new grant is a new signed file; `agent-custody revoke` revokes a grant, and every session under it or under a grant delegated from it refuses its next call |
| CC7.2, monitoring for anomalies | the entity monitors system components for anomalies | every call has a receipt, allowed or denied, and `explain` answers who, why, and what depended on it; the OpenTelemetry and Splunk exports carry each receipt into the existing SIEM |
| CC7.3, evaluation of security events | events are evaluated to determine whether they are incidents | the action pack: one receipt with every downstream receipt, verifiable by the evaluator without access to the system |
| CC7.4, incident response | incidents are contained and remediated | blast radius names every action and belief that depended on a wrong fact; retract and forget are receipted calls, so the remediation has its own evidence |
| CC8.1, change management | changes are authorized and tracked | the policy digest in every receipt identifies the exact policy that decided the call, so a policy change is visible in the receipts; for changes made by agents, the merge gate below gives per-change evidence of tier, approval, and authority on either side of it |

## ISO/IEC 27001:2022, Annex A

| control | what it asks | what answers it |
| --- | --- | --- |
| A.5.15, access control | rules for access based on business requirements | the grant and the Cedar policy, with the policy decision on facts the gateway fetched itself |
| A.5.28, collection of evidence | evidence is collected in a form that stands up | receipts are signed, hashed into a Merkle log, and verifiable offline; the audit proves nothing was rewritten between two points; the packs are single signed artefacts for a case file |
| A.8.10, information deletion | information is deleted when no longer required | forget erases a value from the ledger and the adapted stores and the receipt is the certificate, with each store's own answer; retention sweeps run as receipted calls; a legal hold refuses both |
| A.8.15, logging | logs are produced, stored, protected, and analysed | the transparency log, append-only and hashed, with a log run by someone else where the operator must not be trusted |
| A.8.16, monitoring activities | networks, systems, and applications are monitored | `log-check` from a machine that is not the log's, and the per-receipt spans in the SIEM |
| A.8.32, change management | changes are subject to change management | the policy digest, the grant's window, and the receipts either side of a change; for agent-made changes, the merge gate below |

## Regulations and frameworks for AI agents

This section was checked against primary sources on 2026-11-02. Each row links to the primary text. Each framework has its own "as of" date. A rule can change after that date. Open the link before you rely on a date or a quotation.

Read the last column of each table first. It states what a receipt does not supply. No row says that a receipt makes you compliant. Compliance depends on facts that no receipt records, and on how a regulator or an auditor reads the rule. This page is not legal advice.

| framework | kind | status on 2026-11-02 | applies from | as of |
| --- | --- | --- | --- | --- |
| [EU AI Act](#eu-ai-act), Regulation (EU) 2024/1689 | regulation | in force. The Digital Omnibus on AI, Regulation (EU) 2026/1744, is adopted law, not a proposal | high-risk duties in Chapter III, Sections 1 to 3: 2 December 2027 for Annex III systems, 2 August 2028 for Annex I systems | 2026-11-02 |
| [FINRA](#finra) | existing rules and a guidance report | no new rule for agents. The 2026 report is guidance | not applicable | 2026-11-02 |
| [MAS](#mas-singapore), Guidelines on Artificial Intelligence Risk Management | supervisory expectations | issued 7 October 2026 | 7 October 2027. Sections 5 and 6 may be met by 7 October 2028 | 2026-11-02 |
| [Colorado](#colorado), SB26-189 | state statute | signed into law | 1 January 2027, for consequential decisions made on or after that date | 2026-11-02 |
| [DORA](#dora), Regulation (EU) 2022/2554 | regulation | applies | 17 January 2025 | 2026-11-02 |
| [CSA AICM](#csa-ai-controls-matrix) | voluntary control framework | version 1.1 is published | not applicable | 2026-11-02 |
| [OWASP agentic guidance](#owasp-top-10-for-agentic-applications) | voluntary risk list | 2026 edition, December 2025 | not applicable | 2026-11-02 |
| [ISO/IEC 42001](#iso-iec-42001) | voluntary management system standard | edition 1, 2023 | not applicable | 2026-11-02 |

### EU AI Act

**Dates.** The regulation as first published sets the general date of application at 2 August 2026 ([Article 113](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)). Regulation [(EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj), the Digital Omnibus on AI, replaces point (c) of the third paragraph of Article 113. It is dated 8 July 2026. It appeared in the Official Journal on 24 July 2026. It enters into force on the third day after publication, which is 27 July 2026. It is adopted law. Chapter III, Sections 1, 2, and 3, now apply from:

- 2 December 2027, for AI systems classified as high-risk under Article 6(2) and Annex III;
- 2 August 2028, for AI systems classified as high-risk under Article 6(1) and Annex I.

Articles 12 and 14 are in Section 2. Articles 19 and 26 are in Section 3. So none of them applies to a high-risk system on 2026-11-02. The Omnibus does not amend Article 12, 14, 19, or 26, and it does not amend the list in Annex III. The Omnibus changes other dates too, for example for Article 50(2) and for new Article 5 prohibitions. This page covers the logging duties only. This page lists no later amending act. Check the Official Journal before you rely on a date.

**Scope.** Articles 12, 19, and 26(6) bind high-risk AI systems. Annex III lists eight areas: biometrics; critical infrastructure; education and vocational training; employment and workers' management; access to essential private and public services and benefits (including credit scoring and life and health insurance pricing); law enforcement; migration, asylum, and border control; and the administration of justice and democratic processes. A general agent that calls tools is not high-risk by that fact. It is in scope when its intended use sits in one of these areas, or when Article 6(1) and Annex I make it high-risk. Article 6(3) lets a provider show that an Annex III system is not high-risk. It never excludes a system that profiles natural persons.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [Article 12](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), record-keeping | High-risk systems "technically allow for the automatic recording of events (logs) over the lifetime of the system". The logs help to identify risk situations, to support post-market monitoring, and to monitor operation under Article 26(5). Systems in Annex III point 1(a) have more minimum items in Article 12(3). | One signed receipt for each tool call that goes through the gateway: the grant, the policy decision and its digest, digests of the arguments and the result, and the position in the log. `explain` traces an action to its causes and consequences. | Events that are not tool calls, for example what the model did inside one step. The items in Article 12(3), for example the reference database and the input data that matched. A decision on whether your system is high-risk. An SDK receipt is the agent's own report, so it is weaker evidence than a gateway receipt. |
| [Article 19](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), logs kept by providers | Providers keep the Article 12(1) logs "to the extent such logs are under their control". The period suits the intended purpose and is "at least six months", unless other Union or national law says otherwise, in particular data protection law. Providers that are financial institutions keep the logs with the documentation that financial services law requires. | Receipts and the log stay with the party that runs the gateway. The hosted log holds hashes only, so the receipts stay with you. `prune` keeps every proof valid after the content goes. In the memory server, retention windows apply by space and a legal hold overrides them. | The six-month minimum. `prune` takes any cutoff that you give it and has no minimum. You set the period, and you check it against data protection law. The hosted log is not a copy of the receipts. Logs outside the gateway. |
| [Article 26(6)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), logs kept by deployers | Deployers keep the logs that the high-risk system generates, "to the extent such logs are under their control", for at least six months, unless other law says otherwise. Deployers that are financial institutions keep them with their financial services documentation. | The same receipts and the same log. A tenant on the hosted log has its own log identifier and checkpoints, and an export that works with no server. | The same limits as Article 19. A receipt is a record of a tool call through the gateway. It may not be all the logs that the system generates. |
| [Article 26(5)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), monitoring by deployers | Deployers monitor the operation of the system on the basis of the instructions for use. They inform the provider, and in some cases the market surveillance authority. They suspend use when there is a risk. | The monitor, `log-check`, the OpenTelemetry and Splunk exports, and `agent-custody revoke`, which makes every session under a grant refuse its next call. | The decision that a risk exists. The duty to inform the provider or an authority. The instructions for use. |
| [Article 14](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), human oversight | Systems are designed so that natural persons can oversee them, understand their output, and stop them. | The grant is a human's signature over what the agent may do. A payload-bound approval records the human who approved one action. Retract and forget are receipted calls. | The human-machine interface. The training of the overseer. Evidence that the overseer understood the output. |

Source for this section: Regulation (EU) 2024/1689 and Regulation (EU) 2026/1744 in the Official Journal. As of 2026-11-02.

### FINRA

FINRA has no rule written for AI agents. Its rules are technology-neutral. Regulatory Notice 24-09 (27 June 2024) says that FINRA rules apply to the use of generative AI "just as they apply when member firms use any other technology or tool", and that it "does not create new legal or regulatory requirements". The 2026 Annual Regulatory Oversight Report (9 December 2025) adds a section on AI agents. It is guidance, not a rule.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| Rule 3110, supervision, as the [2026 report](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) cites it | A member firm has "a reasonably designed supervisory system tailored to its business". | Per-call evidence that a supervisor can sample: who authorized the call, the policy decision, and the result. | The supervisory system itself: the procedures, the reviews, and the person who reads the records. |
| [2026 report, AI agents](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) | Lists the risks of autonomy without human validation, of action beyond the intended scope and authority, and of outcomes that are "difficult to trace or explain". Says that firms may consider "how to track agent actions and decisions" and how to set guardrails. | A receipt for each call, allowed or denied. The grant states the scope, and the policy enforces it outside the agent's process. `explain` traces one action. | A record of the agent's reasoning. A guarantee that every action went through the gateway. A human check, unless you use approvals. |
| [2026 report, generative AI](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) | Says that generative AI "can implicate rules regarding supervision, communications, recordkeeping and fair dealing". Says that a firm may consider "storing prompt and output logs". The section names no recordkeeping rule. | Tool-call records in a signed, tamper-evident log. | Prompts and model outputs: a receipt has no prompt text. Customer communications. A finding that a record meets a books-and-records storage rule. This page did not check such a rule. |

Sources: the 2026 report, in the links above; [Regulatory Notice 24-09](https://www.finra.org/rules-guidance/notices/24-09). As of 2026-11-02.

### MAS, Singapore

The Monetary Authority of Singapore issued its Guidelines on Artificial Intelligence Risk Management on 7 October 2026. They set supervisory expectations. They apply to all financial institutions and all forms of AI, and paragraph 1.5 names AI agents. The guidelines take effect on 7 October 2027. Paragraph 1.8 says that firms may meet the expectations in Sections 3 and 4 from that date, and those in Sections 5 and 6 by 7 October 2028. The two paragraphs below are in Section 5.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [Paragraph 5.9(d)](https://www.mas.gov.sg/-/media/mas-media-library/regulation/guidelines/bd/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions/guidelines-on-artificial-intelligence-risk-management.pdf), human oversight: documentation and review | Processes "to document logs and other records generated through development, deployment, operation, monitoring and incident management", and a regular review of human oversight decisions and interventions. | Operation records: each call with its decision. The grant, approval, retract, and forget calls are receipts too, so they show when a human intervened. | Logs of development. The review process and its findings. |
| [Paragraph 5.23(d)](https://www.mas.gov.sg/-/media/mas-media-library/regulation/guidelines/bd/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions/guidelines-on-artificial-intelligence-risk-management.pdf), post-deployment monitoring: documentation | Records of monitoring, results, incidents, and remediation. Access to AI systems "should be strictly controlled and logged". For generative AI or AI agents, "enhanced documentation" such as "logging prompts and model responses, together with applicable model versions and reasoning processes" may be considered. | A tamper-evident record of tool calls and of the policy that decided each one. The receipt names the model, in a field marked `claimed`. | Prompts, model responses, and reasoning. A verified model version: no hosted provider signs the model identity. Records of the monitoring that people did. |

Source: the [MAS guidelines](https://www.mas.gov.sg/regulation/guidelines/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions), dated 7 October 2026. As of 2026-11-02.

### Colorado

Colorado Senate Bill 26-189 repeals and re-enacts part 17 of article 1 of title 6 of the Colorado Revised Statutes, which was the 2024 Colorado AI Act. It regulates "automated decision-making technology" (ADMT) that is used to materially influence a "consequential decision". The bill page shows that the Governor signed it on 14 May 2026. Section 5 of the act says that the act takes effect on 1 January 2027, except a few provisions that took effect on passage. It also says that the act applies to consequential decisions made on or after 1 January 2027. A consequential decision is one about a covered domain: education, employment, residential real estate, a financial or lending service, insurance, health-care services, or essential government services and public benefits. The Attorney General enforces the act. The act creates no new private right of action. The act tells the Attorney General to adopt rules on post-adverse-outcome disclosure on or before 1 January 2027. Read those rules, and check for any court order, before you rely on the date.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [Section 6-1-1703](https://leg.colorado.gov/bill_files/116489/download), deployer record keeping | A deployer retains, for not less than three years after the date of a consequential decision, "records reasonably necessary to demonstrate compliance" with part 17. The records may include ADMT version identifiers, changelogs, and documentation of material mitigation changes. | A signed record of each tool call. The policy digest identifies the exact policy that decided the call, so a change to the policy is visible. `prune` and the retention windows let you keep a record for the period that you choose. | The notices, the post-adverse-outcome disclosures, and the consumer rights that part 17 creates. A test of whether a decision is consequential. An ADMT version identifier: the model identity is `claimed`. A three-year minimum: `prune` has no minimum. The arguments of a call can hold personal data, so privacy law can ask you to delete what this law asks you to keep. |
| [Section 6-1-1702](https://leg.colorado.gov/bill_files/116489/download), developer documentation | From 1 January 2027, a developer of a covered ADMT makes documentation available to each deployer. A developer retains records for not less than three years after their creation. | Nothing here. A receipt records a call, not the documentation of a developer. | The developer documentation. |

Sources: the [bill page](https://leg.colorado.gov/bills/sb26-189) and the [enrolled act](https://leg.colorado.gov/bill_files/116489/download) of Senate Bill 26-189. As of 2026-11-02.

### DORA

Regulation (EU) 2022/2554 applies from 17 January 2025 (Article 64). It covers the financial entities listed in Article 2, for example credit institutions, payment institutions, investment firms, and insurance undertakings. It also covers ICT third-party service providers. The text of DORA and the text of the logging standard below do not use the term "artificial intelligence". Each firm decides whether it treats the tool calls of an agent as ICT operations.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [Article 17](https://eur-lex.europa.eu/eli/reg/2022/2554/oj), ICT-related incident management | Financial entities "record all ICT-related incidents and significant cyber threats". The process identifies, tracks, logs, categorises, and classifies incidents. | Evidence about what an agent did around an incident: the action pack, the blast radius of a wrong fact, and the receipts of denied calls. | The incident register. The classification under Article 18. The report to the authority. The root cause analysis. |
| [Delegated Regulation (EU) 2024/1774, Article 12](https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj), logging | Logging procedures, protocols, and tools. They log events about access control and identity management, change management, and ICT operations. They protect log systems "against tampering, deletion, and unauthorised access", and they synchronise clocks. The entity sets the retention period. | A signed, hashed, append-only log. The audit proves that nobody rewrote the log between two points. The grant records who may act. The policy digest records a change to the policy. | Logs of capacity management and network traffic. The retention period: you set it. Synchronised clocks: the timestamp in a receipt is the producer's own. |

Sources: Regulation (EU) 2022/2554 and Delegated Regulation (EU) 2024/1774 in the Official Journal. As of 2026-11-02.

### CSA AI Controls Matrix

The AI Controls Matrix (AICM) of the Cloud Security Alliance is a voluntary framework. Version 1.1 has 247 control objectives in 18 domains. It maps to ISO/IEC 42001, ISO/IEC 27001, the EU AI Act, NIST AI RMF and AI 600-1, BSI AIC4, and AIUC-1. Its questionnaire, the AI-CAIQ, has 320 questions. The CSA artifact page gives 22 June 2026 as the release date. The CSA announcement is dated 14 July 2026.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [AICM v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) as a whole | Control objectives that an organization assesses itself against, or that a third party assesses, through the AI-CAIQ. | Evidence for any control objective that asks for a record of what an AI system did: the artefacts in the table under "The artefacts". | A mapping to control identifiers. The control spreadsheet is a download that this update did not read, so this page names no AICM control. A receipt is evidence for a control. It is not the control. |

Sources: the [CSA artifact page](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) and the [CSA announcement](https://cloudsecurityalliance.org/blog/2026/07/14/ai-controls-matrix-v1-1-strengthening-the-foundation-for-trustworthy-ai). As of 2026-11-02.

### OWASP Top 10 for Agentic Applications

The OWASP Gen AI Security Project published the Top 10 for Agentic Applications for 2026 on 9 December 2025. It is a list of risks and mitigations. It is guidance, not law. Its mitigation lists ask for logs in several places. The rows below name five of them.

| item | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| ASI01, Agent Goal Hijack | "Comprehensive logging and continuous monitoring of agent activity", with a baseline of tool-use patterns. | A record of each tool call, the monitor, and the SIEM exports. | The baseline and the alerts. You build them. |
| ASI02, Tool Misuse and Exploitation | "Immutable logs of all tool invocations and parameter changes", and monitoring for anomalous tool chains. | A signed receipt in a Merkle log for each call through the gateway, with the digest of the arguments. | Calls that do not go through the gateway. Detection of an anomalous chain. |
| ASI08, Cascading Failures | Tamper-evident, time-stamped logs of inter-agent messages, policy decisions, and execution outcomes, with lineage for every propagated action. | Policy decisions and execution outcomes. `explain` and the blast radius give lineage. | Inter-agent messages that are not tool calls. |
| ASI09, Human-Agent Trust Exploitation | "Immutable logs" of user queries and agent actions. | The actions of the agent. | User queries. |
| ASI10, Rogue Agents | "Immutable and signed audit logs of all agent actions, tool calls, and inter-agent communication". | Signed receipts of tool calls. | Inter-agent communication. A kill switch: the document lists one as a separate mitigation. |

Source: the [OWASP document](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), version 2026, December 2025. As of 2026-11-02.

### ISO/IEC 42001

ISO/IEC 42001:2023 is the standard for an artificial intelligence management system. Edition 1 was published on 2023-12-18. It specifies requirements for establishing, implementing, and maintaining a management system in an organization that offers or uses AI-enabled products or services.

| provision | what it asks | what a receipt supplies | what a receipt does not supply |
| --- | --- | --- | --- |
| [ISO/IEC 42001:2023](https://webstore.iec.ch/publication/90574) as a whole | A management system for an organization: its policies, roles, risk processes, and controls. | Operating evidence that a control ran, in a form that an auditor verifies with public keys. | The management system. A certificate: an audit of the organization produces that. A mapping to clauses or Annex A controls. The standard is sold, and this update did not read the text, so this page names no clause. |

Source: the [IEC publication page](https://webstore.iec.ch/publication/90574). As of 2026-11-02.

## UK GDPR

| provision | what it asks | what answers it |
| --- | --- | --- |
| Article 5(2), accountability | the controller demonstrates compliance | signed receipts and packs demonstrate what was done and why, to a party who has no access to the controller's systems |
| Article 17, right to erasure | personal data is erased on request | the forget certificate, including `stillIndexed` when a store has not caught up, which is what an honest response to a data subject says |
| Article 30, records of processing | records of processing activities are kept | the receipts, and the memory ledger's history of every fact with its source receipt |
| Article 32, security of processing | appropriate technical measures | the hosted log holds hashes only, and receipts stay with the controller |

## Agent-made changes: the merge gate

Teams whose agents open pull requests hit two problems at once. Volume: SOC 2 and ISO 27001 ask that changes are authorized, tested, and approved under a defined process, and a human on every PR does not scale. Accountability: a pipeline's own audit trail, including an "evidence store" at the end of it, is written by the pipeline that made the decisions. Risk-tiered review solves the first only if the tier decision itself is evidence.

[Example 24](../examples/24-agentic-cicd-merge-gate.ts) is that gate. A release agent merges through the gateway; the risk tier is a Cedar policy over facts the gateway fetches from the git host itself, never from the agent: the diff size, whether sensitive paths are touched, the deterministic gate results, which humans approved. Low risk merges on the agent's own authority, medium needs a CODEOWNER's approval the gateway can see, high has no permit for any agent and goes to two humans in the host, and production promotion is refused. Every merge is pre-committed to the log before it is forwarded. The receipts give, per change: the tier, the decision, the approvers as the gateway saw them, the policy digest, the human whose signed grant authorized the agent, and the log positions showing authorization preceded execution, each line verifiable with public keys and no account with us. That is what the two controls above ask for, produced by a key the agent does not hold, instead of a trail the pipeline wrote about itself.

## What no artefact here claims

That the agent's arguments were correct, that the model named in a receipt produced the call, that the upstream executed the action unless it signed the result or a provider delivery is embedded, or that an SDK receipt was enforced outside the agent. The [proof table](../README.md#what-a-receipt-proves-and-what-it-does-not) says so, and a questionnaire answer that repeats it will survive the reviewer who checks.
