# hermes-gate — Developer Guide

A fail-closed spend gate for your Hermes agent. Cap how much it can pay per transaction, how much over any rolling 24 hours, and which rails it can use — so a malicious skill can't move your money outside the rules you set.

> **Status:** community (advisory) tier. Binding-on-chain enforcement is on the roadmap — see *What this protects against* below for exactly where the line is. We'd rather you know the boundary than discover it.

---

## What it is

`hermes-gate` sits between your agent and its wallet. Your agent asks to spend; the gate checks the request against a spend mandate **you** signed, and allows or denies — fail-closed, meaning anything it can't verify is denied, not waved through. The gate runs as an MCP server your Hermes agent calls. It installs in one command and works with the wallet you already have.

You are the principal. You anoint your own agent with your own key and issue your own spend mandate. No external service is in the loop, no account, no domain, no recurring anything. The gate verifies offline.

---

## Install

```
npx @observer-protocol/hermes-gate bootstrap generate
```

To also set a rolling 24-hour cumulative cap, add the daily-cap flags:

```
npx @observer-protocol/hermes-gate bootstrap generate \
  --daily-cap-amount 500 --daily-cap-currency USDT
```

The bootstrap does these things:

1. Generates your **principal** key (a `did:key` — self-contained, no domain needed), your agent's identity key, and a separate wallet key — three distinct keys, each written locked to you (mode 600).
2. Issues a **WalletBindingCredential** — your agent's controller signs "this wallet address is mine," so the gate knows which wallet the mandate applies to.
3. Issues your **SpendMandate** — your spending rules, signed by your principal key. The mandate *is* how you establish the agent as yours: it's signed by you (the principal) with the agent as its subject, so anointing and authorization are the same signed act.

**Move your principal key offline.** The bootstrap writes `principal-key.json` locally and warns you to move it to offline custody (an encrypted drive, a password manager) — it's the key that anoints your agent, and it shouldn't live on the same machine as the gate or anywhere near a git repo. Do this before you commit anything.

Then start the gate and point your Hermes agent at it. The bootstrap prints a "start the gate" block with the exact commands; you add the gate's MCP server to `~/.hermes/config.yaml` yourself (the README shows the exact block) and restart your gateway. The gate finds your `wbc.json` automatically and comes up **bound** — running the full BIND→LINK→AUTHORIZE check by default. You don't have to configure anything extra to be protected; that's the default, not an opt-in.

---

## The two-user boundary (why bootstrap sets up two users)

The bootstrap provisions **two system users**, and this is the security model — not optional ceremony:

- The **agent user** holds only your agent's identity key. It carries no spend authority and **cannot read the wallet key.**
- The **wallet-service user** holds the wallet seed and runs the gate. It is the only path to the signing key.

Your agent reaches spend authorization only through the gate's narrow MCP interface. It cannot read the wallet seed directly. This is what makes the guarantee real: a hostile skill running as your agent has no path to the key — it has to go through the gate, and the gate fails closed.

Run the acceptance test any time to confirm your install is correct:

```
npx @observer-protocol/hermes-gate bootstrap verify --agent-user <user> --wallet-user <user>
```

It checks the boundary in both directions and tells you exactly which boundary broke if one does.

---

## Your spend mandate

A `SpendMandate` is a small signed document with the rules the gate enforces:

- `per_transaction_ceiling` (amount + currency) — a hard ceiling on any single spend.
- `cumulative_budget` (amount + currency, rolling `24h`) — a rolling 24-hour cap across transactions, so a skill can't drain the wallet in many small spends that each clear the per-transaction ceiling. Set via the `--daily-cap-amount` / `--daily-cap-currency` flags at bootstrap. Optional — leave it off for no cumulative ceiling.
- `allowed_rails` — the rails your agent may transact on; anything else is denied.
- Everything else is denied by default.

You sign it with your principal key. Your agent operates under it and **cannot rewrite it** — a mandate signed by your agent's own key is rejected by the gate. (That's the point: if a skill could mint its own mandate, the gate would be pointless.)

> **Not yet enforced:** counterparty allow/block lists (restricting *who* your agent can pay) are on the roadmap — the lite gate does not filter by counterparty today. It limits amount (per-transaction and rolling-24h) and rail. We'd rather name the boundary than imply a control that isn't there.

---

## What this protects against — and what it doesn't

Be clear-eyed about the boundary; it's the honest version and it's the one a serious operator wants.

**It protects against the malicious-skill threat.** A hostile skill, a prompt injection, a poisoned MCP server — anything trying to make your agent act outside your mandate is stopped at the gate, fail-closed. This is the threat the agent community has actually been burned by, and the community tier closes it.

**The current limit: the gate enforces against your agent's *stated intent*.** Your agent tells the gate what it's about to do, and the gate checks that against your mandate. This trusts your agent to report its own actions honestly. It is complete protection against *external* manipulation of an honest agent.

**What it does not yet catch: a compromised or erratic agent that misreports.** If your own agent is itself compromised, hallucinating, or manipulated into building a transaction whose actual bytes differ from what it declares, the advisory tier checks the declaration, not the wire. Closing that gap — enforcing against the decoded on-chain transaction itself — is the **binding tier**, on the roadmap. It protects you not just from hostile skills but from your own agent going off-script.

**Rails:** binding enforcement is live for EVM stablecoins (USDT, USDC) via WDK. Lightning support is **advisory** in this tier — the gate surfaces a decision but does not yet hard-enforce the Lightning payment. Binding Lightning enforcement lands with the binding tier. If you need a hard deny on Lightning today, that rail isn't there yet — we'd rather say so.

**About the rolling 24-hour cap:** the cap is tracked in a local spend ledger the gate writes to (mode 600, beside your mandate). A malicious skill can't reach it — it can only call the gate, which controls the ledger. The boundary to be honest about: a *fully compromised gate process* could in principle delete the ledger and reset the cap. That's the same agent-itself threat the binding tier addresses, and it's out of scope for the lite gate — the cap secures you against malicious skills, not against a compromised gate.

---

## Roadmap: the binding tier

The same gate, wired one level deeper — into your wallet's signing path instead of beside it — so it enforces against the **actual transaction**, not your agent's description of it. That upgrade protects against the agent-itself threat (rogue, hallucinating, or simply spending past where you wanted), and brings binding Lightning enforcement. It's the same product at a deeper integration depth, not a different one — you don't switch, you deepen the gate you already run.

---

## Honest summary

`hermes-gate` (community tier): a fail-closed spend gate that a malicious skill cannot bypass, enforcing per-transaction and rolling-24-hour spending limits and a rail allowlist against your agent's intended spends — binding on EVM stablecoins, advisory on Lightning, installed in one command with the wallet you already have. Counterparty filtering and the binding tier (enforcement against decoded on-chain transactions, protecting against your own agent, with binding Lightning) are the roadmap. Apache-2.0.
