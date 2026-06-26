// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync } from 'node:fs'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js'
import { SpendGate } from './gate.js'

// ── Config from environment ───────────────────────────────────────────────

const MANDATE_PATH = process.env.HERMES_MANDATE_PATH || `${process.env.HOME}/spend-mandate.json`
const IDENTITY_PATH = process.env.HERMES_IDENTITY_PATH || `${process.env.HOME}/identity/did-key.json`
const WBC_PATH = process.env.HERMES_WBC_PATH || null

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
  walletBindingCredentialPath: WBC_PATH || undefined
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

// ── Start ─────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport()
await server.connect(transport)
console.error(`hermes-gate MCP server running (agent: ${agentDid})`)
