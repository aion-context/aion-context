# aion-context Product Positioning

This brief keeps aion-context understandable to product, security,
compliance, and platform audiences before the conversation drops into
file formats or cryptography.

## Primary message

**aion-context makes AI policy changes provable.**

It keeps critical rules outside the model, records every approved
change, and lets teams verify later that the policy history was not
silently edited.

## Best one-liners

- AI policy your team can prove, not just trust.
- Keep agent rules outside the model, with a signed trail for every change.
- A control layer for AI agents that auditors can verify.
- Signed policy history for regulated AI workflows.
- Change agent behavior without changing the model, prompt, or trust story.

## Elevator pitch

AI agents need rules: what they can access, when they should escalate,
which actions are blocked, and what limits apply in regulated workflows.
If those rules only live in prompts, config files, or tribal knowledge,
teams are left hoping nothing changed silently.

aion-context turns those rules into signed policy artifacts. Agents can
check the policy before acting, operators can update it through approved
versions, and auditors can verify what the policy said at any point in
time.

## Audience

| Audience | What they care about | Lead with |
|---|---|---|
| Product leaders | Shipping agents without losing control of behavior | Policy that changes safely without model changes |
| Security teams | Preventing silent tampering and prompt-only governance | Rules enforced outside the model |
| Compliance teams | Reconstructing what was approved and when | Signed, audit-ready policy history |
| Platform engineers | Integrating governance without a hosted dependency | Rust library, CLI, offline verification |

## Messaging pillars

### 1. Control outside the model

Do not ask the model to be the final authority on its own rules.
aion-context lets the model propose actions while a separate signed
policy decides what is allowed.

### 2. Proof for every change

Every policy version is signed. Teams can show who approved a change,
when it happened, and whether the file still matches that history.

### 3. Audits without archaeology

The policy artifact carries its own evidence. Reviewers do not need to
reconstruct the story from screenshots, Slack threads, or partial deploy
logs.

### 4. Local by default

aion-context works as a CLI and Rust library. It does not require a
network service to verify policy integrity.

## Say this, not that

| Avoid leading with | Lead with instead |
|---|---|
| Binary file format | Verifiable policy artifact |
| Hash-chained signature trail | Signed history of every policy change |
| Ed25519, BLAKE3, DSSE, SLSA | Independent proof for security and audit teams |
| O(log n) verification | Fast verification, even as policy history grows |
| Tamper-evident byte payload | A policy file that fails verification if edited outside the approved path |

Technical language is still valuable, but it should support the proof
story after the buyer understands the problem.

## Website or launch-page skeleton

### Hero

**AI policy you can prove.**

Keep critical agent rules outside the model, approve every change with
a signature, and give auditors a policy history they can verify.

Primary action: Try the demo

Secondary action: Read the quickstart

### Problem

AI agents are entering workflows where rules matter: money movement,
support escalation, regulated decisions, customer access, and internal
tool use. Prompts and ordinary config files are easy to change and hard
to defend later.

### Product

aion-context packages those rules as signed policy artifacts. Agents can
check them locally. Operators can update them safely. Reviewers can
verify the policy history without trusting the agent, the prompt, or the
person explaining what happened.

### Proof points

- Every policy version is signed.
- Tampering causes verification to fail.
- The current rules stay easy for agents and systems to consume.
- Verification works offline through a CLI or Rust library.
- The design fits into existing supply-chain and audit workflows.

## Objection handling

**Is this just Git for policy?**

Git tracks repository history. aion-context creates a signed policy
artifact that can travel with the system, be checked at runtime, and be
verified independently of the repo.

**Is this a prompt-injection defense?**

It is a governance boundary. Prompt-injection defenses try to keep the
model aligned. aion-context lets an external policy gate decide whether
the proposed action is allowed.

**Does it replace SLSA, in-toto, or sigstore?**

No. Those tools are strongest around software supply chain artifacts.
aion-context fills the policy and document gap: rules that evolve over
time and need their own signed history.

**Who needs this first?**

Teams putting AI agents into regulated, high-risk, or customer-impacting
workflows where policy changes must be reviewable after the fact.
