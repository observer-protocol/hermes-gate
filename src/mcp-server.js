// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync, existsSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js'
import { SpendGate } from './gate.js'
import { SpendLedger } from './spend-ledger.js'
import { gatePay } from './gate-pay.js'

// ── Config from environment ───────────────────────────────────────────────

const MPPX_PATH = process.env.HERMES_GATE_MPPX_PATH || 'mppx'
const MANDATE_PATH = process.env.HERMES_MANDATE_PATH || `${process.env.HOME}/spend-mandate.json`
const IDENTITY_PATH = process.env.HERMES_IDENTITY_PATH || `${process.env.HOME}/identity/did-key.json`
const WBC_PATH = (() => {
  if (process.env.HERMES_WBC_PATH) return process.env.HERMES_WBC_PATH
  const candidate = join(dirname(resolve(MANDATE_PATH)), 'wbc.json')
  return existsSync(candidate) ? candidate : null
})()

if (!WBC_PATH) {
  console.error('WARNING: No WalletBindingCredential configured.')
  console.error('  HERMES_WBC_PATH is unset and wbc.json was not found alongside the mandate.')
  console.error('  Gate is in pe-042 PASSTHROUGH mode — wallet identity is NOT verified.')
  console.error('  This is only valid for enterprise callers explicitly opting out.')
  console.error('  Community installs: run `hermes-gate bootstrap generate` and either set')
  console.error('  HERMES_WBC_PATH=<path/to/wbc.json> or place wbc.json alongside the mandate.')
}

// Spend ledger for rolling 24h cumulative cap. Created only when the mandate
// declares cumulative_budget (or HERMES_LEDGER_PATH is set explicitly).
// Default path: alongside the mandate, on the agent-user side of the G1 boundary.
const LEDGER_PATH = process.env.HERMES_LEDGER_PATH || join(dirname(resolve(MANDATE_PATH)), 'spend-ledger.jsonl')

function loadSpendLedger () {
  if (process.env.HERMES_LEDGER_PATH) {
    return new SpendLedger(process.env.HERMES_LEDGER_PATH)
  }
  try {
    const m = JSON.parse(readFileSync(MANDATE_PATH, 'utf8'))
    if (m.credentialSubject?.actionScope?.cumulative_budget) {
      return new SpendLedger(LEDGER_PATH)
    }
  } catch {
    // mandate unreadable at startup — gate will surface this on first evaluate
  }
  return null
}

const spendLedger = loadSpendLedger()
if (spendLedger) {
  spendLedger.prune()
  console.error(`hermes-gate: rolling 24h cap active — ledger at ${LEDGER_PATH}`)
}

// Load agent DID from identity file (agent-user's key, not wallet seed)
function loadAgentDid () {
  if (process.env.HERMES_AGENT_DID) return process.env.HERMES_AGENT_DID
  try {
    const id = JSON.parse(readFileSync(IDENTITY_PATH, 'utf8'))
    return id.did || id.agent?.did
  } catch (err) {
    throw new Error(`Cannot load agent identity from ${IDENTITY_PATH}: ${err.message}`)
  }
}

function loadMandateIssuer () {
  try {
    const m = JSON.parse(readFileSync(MANDATE_PATH, 'utf8'))
    return typeof m.issuer === 'object' ? m.issuer?.id : m.issuer
  } catch {
    return null
  }
}

// ── Input parsing (fail-closed) ───────────────────────────────────────────

/**
 * Parse and validate gate_evaluate / gate_execute action input.
 * Throws on any malformed, missing, or out-of-range field.
 * Caller catches and returns { allow: false }.
 *
 * @param {unknown} params
 * @returns {{ rail: string, amount: string, currency: string, category?: string, note?: string }}
 */
function parseAction (params) {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) {
    throw new Error('params must be a non-null object')
  }
  const { rail, amount, currency, category, note, wallet_id } = params

  if (typeof rail !== 'string' || rail.trim().length === 0) {
    throw new Error('rail must be a non-empty string')
  }
  if (typeof amount !== 'string' || amount.trim().length === 0) {
    throw new Error('amount must be a non-empty string')
  }
  // Reject negative, zero, or non-numeric amounts
  if (!/^[0-9]+(\.[0-9]+)?$/.test(amount.trim()) || parseFloat(amount) <= 0) {
    throw new Error('amount must be a positive decimal string')
  }
  if (typeof currency !== 'string' || currency.trim().length === 0) {
    throw new Error('currency must be a non-empty string')
  }

  return {
    rail: rail.trim(),
    amount: amount.trim(),
    currency: currency.trim(),
    ...(typeof category === 'string' && category ? { category: category.trim() } : {}),
    ...(typeof note === 'string' && note ? { note: note.trim() } : {}),
    ...(typeof wallet_id === 'string' && wallet_id ? { wallet_id: wallet_id.trim() } : {})
  }
}

// ── Server setup ──────────────────────────────────────────────────────────

const agentDid = loadAgentDid()
const mandateIssuer = loadMandateIssuer()
const gate = new SpendGate({
  mandatePath: MANDATE_PATH,
  agentDid,
  trustedIssuers: mandateIssuer ? [mandateIssuer] : [],
  walletBindingCredentialPath: WBC_PATH || undefined,
  spendLedger: spendLedger || undefined
})

const server = new Server(
  { name: 'hermes-gate', version: '0.1.0' },
  { capabilities: { tools: {} } }
)

// ── Tool: gate_evaluate (fail-closed boundary) ────────────────────────────

async function handleGateEvaluate (params) {
  try {
    const action = parseAction(params)
    return await gate.evaluate(action)
  } catch (err) {
    return {
      allow: false,
      reasons: [{ ruleType: 'gate_error', ruleField: 'input', message: err.message }],
      advisories: [],
      mandateValidUntil: ''
    }
  }
}

// ── Tool: gate_pay (MPP payment path) ────────────────────────────────────

async function handleGatePay (params) {
  if (typeof params?.url !== 'string' || !params.url.trim()) {
    return {
      allowed: false,
      amount: null,
      currency: null,
      rail: null,
      tx_ref: null,
      reasons: [{ ruleType: 'gate_error', ruleField: 'url', message: 'url is required' }],
      advisories: []
    }
  }
  return gatePay(params.url.trim(), {
    gate,
    mppxPath: MPPX_PATH,
    walletId: typeof params.wallet_id === 'string' ? params.wallet_id.trim() : undefined
  })
}

// ── Tool: gate_execute ────────────────────────────────────────────────────

async function handleGateExecute (params) {
  const decision = await handleGateEvaluate(params)
  if (!decision.allow) {
    return {
      allowed: false,
      reasons: decision.reasons,
      advisories: decision.advisories,
      pec: null,
      tx_ref: null
    }
  }
  // Actual wallet signing is the wallet-service's responsibility.
  // This stub returns the decision and signals to the caller to proceed.
  // The wallet-service integration replaces this stub with actual WDK submission.
  return {
    allowed: true,
    reasons: [],
    advisories: decision.advisories,
    pec: null,       // PolicyEvaluationCredential — emitted by buildSettlementAttestation
    tx_ref: null,    // set by wallet-service after submission
    _note: 'Submission stub — integrate with WDK wallet client for live execution'
  }
}

// ── Tool: gate_status (informational, no re-verify) ──────────────────────

function handleGateStatus () {
  let mandateValidUntil = null
  let mandateIssuerOut = null
  try {
    const m = JSON.parse(readFileSync(MANDATE_PATH, 'utf8'))
    mandateValidUntil = m.validUntil || null
    mandateIssuerOut = typeof m.issuer === 'object' ? m.issuer?.id : m.issuer || null
  } catch {
    // status is informational
  }
  return {
    gate_up: true,
    agent_did: agentDid,
    mandate_valid_until: mandateValidUntil,
    mandate_issuer: mandateIssuerOut,
    mandate_path: MANDATE_PATH
  }
}

// ── MCP tool definitions ──────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'gate_evaluate',
    description: 'Evaluate whether a proposed spend is within the agent\'s SpendMandate. Returns allow/deny with reasons.',
    inputSchema: {
      type: 'object',
      properties: {
        rail: { type: 'string', description: 'Payment rail (e.g. ethereum-mainnet, lightning)' },
        amount: { type: 'string', description: 'Proposed amount as a positive decimal string' },
        currency: { type: 'string', description: 'Currency or token symbol (e.g. USDT, sats)' },
        category: { type: 'string', description: 'Transaction category (e.g. payment)' },
        wallet_id: { type: 'string', description: 'Wallet DID or address — required for BIND address verification when WBC is configured' },
        note: { type: 'string', description: 'Optional human-readable note' }
      },
      required: ['rail', 'amount', 'currency']
    }
  },
  {
    name: 'gate_execute',
    description: 'Evaluate and, if allowed, signal wallet-service to submit spend. Returns decision + tx_ref when allowed.',
    inputSchema: {
      type: 'object',
      properties: {
        rail: { type: 'string' },
        amount: { type: 'string' },
        currency: { type: 'string' },
        category: { type: 'string' },
        wallet_id: { type: 'string', description: 'Wallet DID or address — triggers BIND address verification' },
        tx_details: { type: 'object', description: 'Rail-specific transaction parameters' }
      },
      required: ['rail', 'amount', 'currency']
    }
  },
  {
    name: 'gate_pay',
    description: 'Pay a 402-gated URL via mppx after evaluating against the SpendMandate. Use this instead of calling mppx directly — the gate checks your mandate (per-transaction ceiling, 24h rolling cap, rail allowlist), executes the payment, and records the spend atomically.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The 402-protected URL to pay and access' },
        wallet_id: { type: 'string', description: 'Wallet DID for BIND check when WalletBindingCredential is configured' }
      },
      required: ['url']
    }
  },
  {
    name: 'gate_status',
    description: 'Return gate health and mandate metadata. Does not re-verify the mandate.',
    inputSchema: { type: 'object', properties: {} }
  }
]

// ── Request handlers ──────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params

  let result
  switch (name) {
    case 'gate_evaluate':
      result = await handleGateEvaluate(args)
      break
    case 'gate_execute':
      result = await handleGateExecute(args)
      break
    case 'gate_pay':
      result = await handleGatePay(args)
      break
    case 'gate_status':
      result = handleGateStatus()
      break
    default:
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${name}` }) }],
        isError: true
      }
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
  }
})

// ── HTTP endpoint for Hermes binding-tier plugin ──────────────────────────
// Enabled when HERMES_GATE_HTTP_PORT is set. Exposes POST /gate/evaluate on
// 127.0.0.1 only, sharing the same SpendGate instance (and thus the same
// ledger) as the MCP server. The Python pre_tool_call plugin calls this to
// intercept payment CLI commands (mppx, tempo wallet pay, etc.) before they
// execute, without going through MCP (which would cause infinite recursion).

const HTTP_PORT = process.env.HERMES_GATE_HTTP_PORT
  ? parseInt(process.env.HERMES_GATE_HTTP_PORT, 10)
  : null

if (HTTP_PORT) {
  const httpServer = createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/gate/evaluate') {
      let body = ''
      req.on('data', d => { body += d.toString() })
      req.on('end', async () => {
        let result
        try {
          const action = parseAction(JSON.parse(body))
          result = await gate.evaluate(action)
        } catch (err) {
          result = {
            allow: false,
            reasons: [{ ruleType: 'gate_error', ruleField: 'input', message: err.message }],
            advisories: [],
            mandateValidUntil: ''
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(result))
      })
    } else {
      res.writeHead(404)
      res.end()
    }
  })

  await new Promise((resolve, reject) => {
    httpServer.listen(HTTP_PORT, '127.0.0.1', resolve)
    httpServer.on('error', reject)
  })
  console.error(`hermes-gate: HTTP endpoint listening on 127.0.0.1:${HTTP_PORT} (binding tier)`)
}

// ── Start ─────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport()
await server.connect(transport)
console.error(`hermes-gate MCP server running (agent: ${agentDid})`)
