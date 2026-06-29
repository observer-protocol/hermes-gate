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

Your agent reaches spend authorization only through the gate's narrow MCP interface, and it cannot read the wallet seed directly. So a hostile skill running as your agent has no path to the key of its own — the only way to a signed payment is one the gate has approved, as long as the agent routes the payment through the gate (see *What this protects against* for that boundary).

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

**It protects against the malicious-skill threat.** A hostile skill, a prompt injection, a poisoned MCP server trying to push your agent past your mandate through its normal payment flow — checked against your mandate and denied, fail-closed. This is the threat the agent community has actually been burned by, and the community tier closes it.

**How it works, precisely:** the gate is a check your agent calls before each spend (via MCP), against a mandate the agent can't rewrite. The wallet key lives in a separate user the agent can't read, so the only path to a signed payment is one the gate has approved — *as long as the agent routes the payment through the gate.* That last clause is the boundary, and it's worth being clear-eyed about.

**What it does not catch — the bypass case.** Because the gate is something the agent *calls*, it protects against skills trying to manipulate an honest agent, but it trusts the agent to consult the gate in the first place. An agent compromised deeply enough to call a payment path directly, skipping the gate, isn't stopped by this tier. Making the check *unbypassable* — enforced in the call path itself, so every payment is intercepted whether or not the agent cooperates — is the enforcement tier on the roadmap (see below).

**What it does not yet catch: a compromised or erratic agent that misreports.** If your own agent is itself compromised, hallucinating, or manipulated into building a transaction whose actual bytes differ from what it declares, the advisory tier checks the declaration, not the wire. Closing that gap — enforcing against the decoded on-chain transaction itself — is the **binding tier**, on the roadmap. It protects you not just from hostile skills but from your own agent going off-script.

**Rails:** binding enforcement is live for EVM stablecoins (USDT, USDC) via WDK. Lightning support is **advisory** in this tier — the gate surfaces a decision but does not yet hard-enforce the Lightning payment. Binding Lightning enforcement lands with the binding tier. If you need a hard deny on Lightning today, that rail isn't there yet — we'd rather say so.

**About the rolling 24-hour cap:** the cap is tracked in a local spend ledger the gate writes to (mode 600, beside your mandate). A malicious skill can't reach it — it can only call the gate, which controls the ledger. The boundary to be honest about: a *fully compromised gate process* could in principle delete the ledger and reset the cap. That's the same agent-itself threat the binding tier addresses, and it's out of scope for the lite gate — the cap secures you against malicious skills, not against a compromised gate.

---

## The binding tier (available now)

The binding tier wires the gate into Hermes's `pre_tool_call` hook — which fires before every tool call and can deny outright. This means payment commands are intercepted *before they execute*, whether or not the agent calls `gate_evaluate` first.

**How it works.** When a payment CLI command appears in a `terminal` tool call (mppx, tempo wallet pay, agentcash pay, privy-agent-wallets pay), the plugin:

1. Extracts the target URL from the command.
2. Probes the URL to discover amount and currency from the `402 WWW-Authenticate` header (MPP format) or a BOLT11 invoice (L402).
3. Calls the gate over HTTP (not MCP — no recursion risk) against your SpendMandate.
4. Blocks the terminal call if the gate returns deny, or if the gate is unreachable (fail closed).

**Install:**

```
npx @observer-protocol/hermes-gate plugin install
```

Then add to `~/.hermes/.env`:

```
HERMES_GATE_HTTP_PORT=8472
```

Restart hermes-gate with that env var set (the gate logs `HTTP endpoint listening on 127.0.0.1:8472 (binding tier)`), then restart your Hermes gateway. Payment commands are now intercepted before execution.

**What this closes.** The community tier stopped malicious skills from pushing an *honest* agent past your mandate — but trusted the agent to call the gate first. The binding tier removes that trust: payment commands are blocked at the `pre_tool_call` layer regardless of whether the agent cooperated. An agent that tries to skip `gate_evaluate` and run `mppx` directly is stopped here.

**What it does not yet close: the misreporting case.** The binding tier checks the payment command the agent *declares* (the mppx CLI call), not the signed on-chain transaction. An agent that could construct a payment outside the supported CLIs — calling a wallet API directly, for example — is out of scope for this tier. Closing that gap (enforcing against decoded on-chain bytes) is the next milestone.

**MPP and the binding tier.** The MPP Agent skill auto-pays on HTTP 402 responses — the agent doesn't pause to call `gate_evaluate`, it just fires `mppx`. The `pre_tool_call` hook catches these exactly. This is the primary use case for the binding tier.

---

## The canonical MPP payment path: gate_pay

`gate_pay` is the one tool your agent should call for any payment behind an HTTP 402. It collapses two problems the interceptor tier still has: detection surface (you have to enumerate CLIs to intercept) and the evaluate-then-execute gap (the interceptor blocks or allows, but the gate never runs the payment itself, so a divergence between the declared amount and the actual payment is possible).

With `gate_pay`, the gate is the payment path — not a guard around someone else's path:

1. **Probe** — the gate fetches the 402 URL and reads amount and currency from `WWW-Authenticate`. If the header is missing or unparseable, the call returns `allowed: false` — fail closed.
2. **Evaluate** — same full BIND→LINK→AUTHORIZE mandate check as `gate_evaluate`. If denied, nothing executes.
3. **Reserve** — on approval, the amount is reserved against the rolling 24h cap immediately, before `mppx` runs. A concurrent `gate_pay` call sees the headroom already spoken for.
4. **Execute** — the gate calls `mppx` directly. If mppx fails (non-zero exit), the reserve is released and the call returns `allowed: false`. Cap is restored.
5. **Commit** — on successful mppx output, the reserve is converted to a permanent ledger entry.

One case to know: if mppx exits 0 but the output does not parse (no payment hash, no success keyword), the gate treats it as "money likely moved" and commits at the probed amount with `reconciliation_required: true`. It never under-counts the cap.

**Install gate_pay:**

Copy the skill into your Hermes skills directory:

```
cp -r node_modules/@observer-protocol/hermes-gate/skills/hermes-gate-pay \
      ~/.hermes/skills/hermes-gate-pay
```

Then set `HERMES_GATE_MPPX_PATH` if mppx is not on PATH, or omit it if `mppx` is globally installed.

**Result shape:**

| field | type | meaning |
|---|---|---|
| `allowed` | bool | Whether mandate approved and payment executed |
| `amount` | string | Amount paid (confirmed if parsed, probed if `reconciliation_required`) |
| `currency` | string | Currency |
| `rail` | string | `lightning` |
| `tx_ref` | string \| null | Payment hash from mppx; null if unparseable |
| `reasons` | object[] | Denial reasons when `allowed: false` |
| `reconciliation_required` | bool | `true` if mppx exited 0 but output did not parse |

**What gate_pay closes vs what it does not.** gate_pay + the Hermes skill is **soft-binding**: the agent is routed through the gate by instruction. An adversarial agent that constructs a payment call outside the MCP interface still spends. "Bypass impossible" is not earned until the transacting key lives in a separate user the agent can't read (the binding tier on the roadmap). gate_pay is: one canonical path, fail-closed, the gate runs the payment and sees the real amount. That is the honest claim.

The `pre_tool_call` interceptor from 0.2.0 remains active alongside gate_pay — they compose without double-debit. A cooperating agent calls `gate_pay` via MCP; the gate's internal `mppx` subprocess is invisible to Hermes's dispatcher, so `pre_tool_call` never fires on it. A non-cooperating agent that calls `mppx` directly still hits the interceptor.

---

## Honest summary

`hermes-gate` (community + binding + payment-path tiers): a fail-closed spend gate enforcing per-transaction and rolling-24-hour spending limits and a rail allowlist against a mandate the agent can't rewrite. The community tier (MCP `gate_evaluate`) requires the agent to call the gate first. The binding tier (Hermes `pre_tool_call` plugin) intercepts payment CLI commands before execution, including MPP auto-payments, regardless of agent cooperation. The payment-path tier (`gate_pay` MCP tool) makes the gate the canonical MPP payment path: probe-then-evaluate-then-execute, with a reserve/commit/release lifecycle against the rolling cap so the ledger always reflects confirmed payments. All three layers compose without double-debit. What is not yet closed: agents calling wallet APIs directly outside the gate (requires custody of the transacting key), and counterparty filtering and decoded on-chain enforcement. Apache-2.0.
