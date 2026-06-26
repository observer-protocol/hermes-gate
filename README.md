# @observer-protocol/hermes-gate

A fail-closed spend gate for Hermes agents. Set what your agent can pay and how much; enforced below the skill layer so a hostile skill cannot move money outside the rules you set.

> **Status: community tier.** Binding-on-chain enforcement is on the roadmap. See *What this protects against* for exactly where the line is. We would rather you know the boundary than discover it.

---

## What it is

`hermes-gate` sits between your agent and its wallet. Your agent asks to spend; the gate checks the request against a spend mandate you signed, and allows or denies. Fail-closed: anything it cannot verify is denied, not waved through. The gate runs as an MCP server your Hermes agent calls.

You are the principal. You anoint your own agent with your own key and issue your own spend mandate. No external service is in the loop, no account, no domain. The gate verifies offline.

---

## Prerequisites

- Node 20 or later
- npm
- For `provision` and `verify`: a Linux server, root access, and two dedicated system users (agent user and wallet-service user)

---

## Install and generate

```
npx @observer-protocol/hermes-gate bootstrap generate
```

After a global install (`npm install -g @observer-protocol/hermes-gate`), the same command is:

```
hermes-gate bootstrap generate
```

`generate` creates three keys, one mandate, and one wallet-binding credential:

1. **Principal key** (`principal-key.json`): a `did:key`, self-contained, no domain required. You sign your mandate with this key. It is written at mode 600 and must be moved offline immediately after generate runs.
2. **Agent identity key** (`agent-identity-key.json`): the key the agent user holds on the server. It carries no spend authority; mode 600.
3. **Wallet identity key** (`wallet-identity-key.json`) and **wallet seed** (`wallet-seed.json`): held by the wallet-service user. The wallet-binding credential ties this key to your mandate. Both written at mode 600.
4. **SpendMandate** (`spend-mandate.json`): your spending rules, signed by your principal key; mode 644.
5. **WalletBindingCredential** (`wbc.json`): your principal signs that this wallet address is bound to the mandate; mode 644.

All six files go to `./output/` by default.

---

## Move the principal key offline

This step is not optional.

`./output/principal-key.json` contains the key material that signed your mandate. The gate does not need it at runtime. Move it off the server before the gate starts:

```
cp output/principal-key.json /path/to/offline/storage
rm output/principal-key.json
```

An attacker with the principal key can re-issue credentials. An attacker with only the agent key or wallet key cannot rewrite your mandate.

---

## The two-user boundary

The bootstrap provisions two system users, and this is the security model, not optional ceremony.

The **agent user** holds the agent identity key. It carries no spend authority and cannot read the wallet seed.

The **wallet-service user** holds the wallet seed. It is the only path to signing.

Your agent reaches spend authorization only through the gate's narrow MCP interface. A hostile skill running as the agent has no path to the wallet seed: it has to go through the gate, and the gate fails closed.

---

## Wire up the gate

After `generate`, `./output/` contains `spend-mandate.json` and `wbc.json` in the same directory. The gate auto-discovers `wbc.json` when it sits alongside the mandate; no `HERMES_WBC_PATH` is needed.

`generate` prints the exact start command for your agent DID:

```
HERMES_MANDATE_PATH=/home/<agent-user>/spend-mandate.json \
  HERMES_AGENT_DID=did:key:z6Mk... \
  node /path/to/hermes-gate/src/mcp-server.js
```

With `wbc.json` alongside the mandate, the gate comes up in bound mode with no additional configuration.

If neither `HERMES_WBC_PATH` nor an adjacent `wbc.json` is found at startup, the gate logs this to stderr and enters passthrough mode:

```
WARNING: No WalletBindingCredential configured.
  HERMES_WBC_PATH is unset and wbc.json was not found alongside the mandate.
  Gate is in pe-042 PASSTHROUGH mode — wallet identity is NOT verified.
  ...
```

Passthrough means the wallet-binding check is skipped; a wrong wallet ID returns `allow:true`. This is not a valid community install. Never ignore the warning.

**For Hermes** (`~/.hermes/config.yaml`), add the gate manually:

```yaml
mcp_servers:
  hermes-gate:
    command: node
    args:
      - /path/to/hermes-gate/src/mcp-server.js
    env:
      HERMES_MANDATE_PATH: /home/atlas/spend-mandate.json
      HERMES_AGENT_DID: "did:key:z6Mk..."
    timeout: 30
```

`wbc.json` alongside the mandate is auto-discovered. Set `HERMES_WBC_PATH` explicitly only if it lives at a different path.

**For Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "hermes-gate": {
      "command": "node",
      "args": ["/path/to/hermes-gate/src/mcp-server.js"],
      "env": {
        "HERMES_MANDATE_PATH": "/home/atlas/spend-mandate.json",
        "HERMES_AGENT_DID": "did:key:z6Mk..."
      }
    }
  }
}
```

---

## Runtime env vars

| Variable | Default | Notes |
|----------|---------|-------|
| `HERMES_MANDATE_PATH` | `~/spend-mandate.json` | Path to the signed SpendMandate |
| `HERMES_AGENT_DID` | read from `HERMES_IDENTITY_PATH` | Agent DID; set explicitly to skip the identity file |
| `HERMES_IDENTITY_PATH` | `~/identity/did-key.json` | Agent identity key file; ignored when `HERMES_AGENT_DID` is set |
| `HERMES_WBC_PATH` | auto-discovered | Path to wbc.json; auto-discovered from mandate directory if unset |

---

## Customize your mandate

Set your limits at generate time with flags:

```
npx @observer-protocol/hermes-gate bootstrap generate \
  --ceiling-amount 250 \
  --ceil-currency USDT \
  --allowed-rails ethereum-mainnet,lightning
```

| Flag | Default | Notes |
|------|---------|-------|
| `--output-dir` | `./output` | Where to write generated files |
| `--ceiling-amount` | `100` | Per-transaction ceiling |
| `--ceil-currency` | `USDT` | Currency for the ceiling |
| `--allowed-rails` | `ethereum-mainnet,lightning` | Comma-separated list of allowed rails |

The ceiling applies to each individual transaction. There is no daily-cap field in the generated mandate; per-transaction ceiling is the enforced constraint. A spend on a rail not in `allowed-rails` is denied.

---

## Production: provision and verify

For OS-level key isolation, run `provision` as root after `generate`:

```
sudo npx @observer-protocol/hermes-gate bootstrap provision \
  --agent-user atlas \
  --wallet-user atlas-wallet
```

Flags:

| Flag | Required | Notes |
|------|----------|-------|
| `--agent-user` | yes | System user that runs the agent |
| `--wallet-user` | yes | System user that runs the wallet service |
| `--output-dir` | no | Source directory; defaults to `./output` |

`provision` copies files and sets permissions:

| File | Destination | Mode |
|------|-------------|------|
| `agent-identity-key.json` | `/home/<agent-user>/identity/did-key.json` | 600 |
| `spend-mandate.json` | `/home/<agent-user>/spend-mandate.json` | 644 |
| `wbc.json` | `/home/<agent-user>/wbc.json` | 644 |
| `wallet-seed.json` | `/home/<wallet-user>/secrets/wallet-seed.json` | 600 |
| `wallet-identity-key.json` | `/home/<wallet-user>/secrets/wallet-key.json` | 600 |

The wallet-service user's home directory and secrets directory are set to mode 700.

Then confirm the boundary is secure:

```
sudo npx @observer-protocol/hermes-gate bootstrap verify \
  --agent-user atlas \
  --wallet-user atlas-wallet
```

Flags: `--agent-user` and `--wallet-user` (required). No `--output-dir`.

`verify` runs three cross-boundary deny tests. PASS means access was correctly denied. INCONCLUSIVE means sudo is not configured for this user; run as root or configure passwordless sudo. The command exits non-zero if any boundary is broken.

---

## Gate tools

**`gate_evaluate`**: Check whether a proposed spend is within the mandate. Call this before any payment. Returns `allow: true/false` with reasons.

Required params: `rail` (string), `amount` (positive decimal string), `currency` (string).
Optional: `wallet_id` (string, required for the BIND wallet-address check when a WBC is configured), `category`, `note`.

**`gate_execute`**: Evaluate and, if allowed, signal the wallet service to submit. Returns the decision and a `tx_ref` placeholder (set by the wallet service after submission). The gate does not submit transactions itself.

**`gate_status`**: Return gate health and mandate metadata (agent DID, mandate issuer, valid-until). Does not re-verify the mandate signature.

---

## Secrets and output/

`generate` writes all four key files at mode 600. `output/` is in `.gitignore`.

After generate:
- Move `principal-key.json` offline immediately. Do not leave it on the server.
- Do not commit `output/` or any key file.
- `spend-mandate.json` and `wbc.json` are signed credentials readable by the gate (mode 644). They contain no key material.

---

## What this protects against, and what it does not

**It protects against the malicious-skill threat.** A hostile skill, a prompt injection, a poisoned MCP server: anything trying to make your agent act outside your mandate is stopped at the gate, fail-closed. This is the threat the agent community has been burned by, and this tier closes it.

**The current limit: the gate enforces against your agent's stated intent.** Your agent tells the gate what it is about to do, and the gate checks that against your mandate. This trusts your agent to report its own actions honestly. It is complete protection against external manipulation of an honest agent.

**What it does not yet catch: a compromised or erratic agent that misreports.** If your own agent is itself compromised, hallucinating, or manipulated into building a transaction whose actual bytes differ from what it declares, this tier checks the declaration, not the wire. Closing that gap is the binding tier, on the roadmap.

**Rails.** Binding enforcement is live for EVM stablecoins (USDT, USDC). Lightning support is advisory in this tier: the gate surfaces a decision but does not hard-enforce the Lightning payment. Binding Lightning enforcement lands with the binding tier. If you need a hard deny on Lightning today, that enforcement is not there yet.

---

## Roadmap: the binding tier

The same gate, wired one level deeper: into your wallet's signing path instead of beside it, so it enforces against the actual transaction rather than your agent's description of it. This protects against the agent-itself threat (a rogue, hallucinating, or out-of-scope agent), and brings binding Lightning enforcement. It is the same product at a deeper integration depth. You will not switch; you will deepen the gate you already run.

---

## Honest summary

`hermes-gate` (community tier): a fail-closed spend gate that a malicious skill cannot bypass, enforcing per-transaction ceilings and rail restrictions against your agent's intended spends, binding on EVM stablecoins, advisory on Lightning, installed in one command with the wallet you already have. The binding tier, which enforces against decoded on-chain transactions and protects against your own agent going off-script, is the roadmap.

---

## License

Apache-2.0
