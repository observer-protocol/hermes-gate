# @observer-protocol/hermes-gate

Fail-closed spend gate for Hermes agent operators. Enforces a signed SpendMandate and WalletBindingCredential (WBC) before any payment action, using the Observer Protocol BIND→LINK→AUTHORIZE pipeline.

The gate checks three things on every call:

1. **BIND** — `wallet_id` in the request matches the wallet address bound in the WBC
2. **LINK** — WBC issuer matches the mandate issuer (same principal)
3. **AUTHORIZE** — amount, rail, and currency are within the mandate's ceilings and allowed rails

Any step that fails returns `allow: false` and stops.

## Prerequisites

- Node 20 or later
- npm

## Install

```
npm install @observer-protocol/hermes-gate
```

## Quickstart

### 1. Generate key material

```
npx hermes-gate bootstrap generate
```

Writes six files to `./output/`:

| File | Placement | Mode |
|------|-----------|------|
| `principal-key.json` | **Move offline immediately** | 600 |
| `agent-identity-key.json` | `/home/<agent-user>/identity/did-key.json` | 600 |
| `wallet-seed.json` | `/home/<wallet-user>/secrets/wallet-seed.json` | 600 |
| `wallet-identity-key.json` | `/home/<wallet-user>/secrets/wallet-key.json` | 600 |
| `spend-mandate.json` | `/home/<agent-user>/spend-mandate.json` | 644 |
| `wbc.json` | `/home/<agent-user>/wbc.json` | 644 |

All four key files are written at mode 600 by generate.

### 2. Move the principal key offline

The principal key is only needed to re-issue credentials. It must not stay on the server:

```
cp output/principal-key.json /path/to/offline/storage
rm output/principal-key.json
```

### 3. Start the gate

```
HERMES_MANDATE_PATH=./output/spend-mandate.json \
  HERMES_AGENT_DID=<agent-did-from-generate-output> \
  node node_modules/@observer-protocol/hermes-gate/src/mcp-server.js
```

WBC auto-discovery: if `HERMES_WBC_PATH` is unset, the gate looks for `wbc.json` in the same directory as the mandate. Placing `wbc.json` alongside `spend-mandate.json` means no extra config is needed.

If neither `HERMES_WBC_PATH` nor an adjacent `wbc.json` is found, the gate starts in passthrough mode and logs a loud warning to stderr. This path is reserved for enterprise callers who explicitly opt out of wallet binding. Community installs should always have a WBC.

## Production: two-server G1 setup

For OS-level isolation between the agent identity (who the agent is) and the wallet seed (what it can spend), use provision and verify. Run these as root on the target server:

```
sudo npx hermes-gate bootstrap provision \
  --agent-user atlas \
  --wallet-user atlas-wallet
```

Then confirm the boundary is secure:

```
sudo npx hermes-gate bootstrap verify \
  --agent-user atlas \
  --wallet-user atlas-wallet
```

Provision places files at the paths and modes listed above and sets directory permissions (`chmod 700 /home/<wallet-user>/secrets`). Verify runs three cross-boundary deny tests and exits non-zero if any boundary is broken.

## Runtime configuration

| Variable | Default | Notes |
|----------|---------|-------|
| `HERMES_MANDATE_PATH` | `~/spend-mandate.json` | Path to the signed SpendMandate |
| `HERMES_AGENT_DID` | read from `HERMES_IDENTITY_PATH` | Agent DID (did:key:...) |
| `HERMES_IDENTITY_PATH` | `~/identity/did-key.json` | Agent identity key file; ignored when `HERMES_AGENT_DID` is set |
| `HERMES_WBC_PATH` | auto-discovered | Path to wbc.json; auto-discovered from mandate directory if unset |

## MCP config

Add to your Claude Desktop or Claude Code MCP settings:

```json
{
  "mcpServers": {
    "hermes-gate": {
      "command": "node",
      "args": ["/opt/hermes-gate/src/mcp-server.js"],
      "env": {
        "HERMES_MANDATE_PATH": "/home/atlas/spend-mandate.json",
        "HERMES_AGENT_DID": "did:key:z6Mk...",
        "HERMES_WBC_PATH": "/home/atlas/wbc.json"
      }
    }
  }
}
```

Point `args[0]` at the mcp-server.js from your installed or deployed copy of the package.

## Bootstrap flags

`generate` accepts optional flags to customize the mandate:

```
npx hermes-gate bootstrap generate \
  --output-dir ./output \
  --allowed-rails ethereum-mainnet,lightning \
  --ceiling-amount 500 \
  --ceil-currency USDT
```

`provision` requires `--agent-user` and `--wallet-user`. The optional `--output-dir` defaults to `./output`.

`verify` requires `--agent-user` and `--wallet-user`. Must be run as root or with passwordless sudo configured.

## Gate tools

**`gate_evaluate`** — Check whether a proposed spend is within the mandate. Returns `allow: true/false` with reasons. Call this before any payment action. Required params: `rail`, `amount` (positive decimal string), `currency`. Optional: `wallet_id` (required for BIND check when WBC is configured), `category`, `note`.

**`gate_execute`** — Evaluate and, if allowed, signal the wallet service to submit. Returns the decision plus `tx_ref` (set by the wallet service after submission). The gate does not submit the transaction itself.

**`gate_status`** — Return gate health and mandate metadata (agent DID, mandate issuer, valid-until). Does not re-verify the mandate signature.

## Threat model

This gate enforces against agent-declared intent: the action the agent states (`rail`, `amount`, `currency`, `wallet_id`) is what gets checked.

What this gate blocks:
- Spends above the mandate ceiling
- Spends on disallowed rails
- Calls where `wallet_id` does not match the bound wallet address
- Calls with expired mandates
- Any input that fails to parse (fail-closed)

What this gate does not block: an agent that correctly states intent but submits a malformed or mismatched transaction directly to the wallet service after gate approval. That boundary is the wallet service's responsibility.

For stricter enforcement, use the `RuntimeAdapter` in `@observer-protocol/wdk-protocol-trust`, which decodes actual WDK transaction proposals and applies spend rules at the proposal layer before signing.

## License

Apache-2.0
