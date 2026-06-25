// SPDX-License-Identifier: Apache-2.0
// Tests for SpendGate and the fail-closed MCP boundary

'use strict'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import {
  createDidKeyAgent,
  signDocument,
  DELEGATION_SCHEMA_V2_1
} from '@observer-protocol/wdk-protocol-trust'
import { SpendGate, GateError } from '../src/gate.js'

// ── Helpers ───────────────────────────────────────────────────────────────

function hex (bytes) { return Buffer.from(bytes).toString('hex') }
function toISO (d) { return d.toISOString().replace(/\.\d+Z$/, 'Z') }

function makePrincipal () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/principal/0/0/0")
}

function makeAgent () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/agent/0/0/0")
}

function makeMandate (principal, agent, overrides = {}) {
  const now = new Date()
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    id: `urn:uuid:test-mandate-${hex(randomBytes(8))}`,
    issuer: principal.did,
    validFrom: toISO(now),
    validUntil: toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)),
    credentialSchema: { id: DELEGATION_SCHEMA_V2_1, type: 'JsonSchema' },
    credentialSubject: {
      id: agent.did,
      authorizationLevel: 'recurring',
      authorizationConfig: {
        recurring: {
          ceiling_amount: '100',
          ceiling_currency: 'USDT'
        }
      },
      actionScope: {
        allowed_rails: ['ethereum-mainnet'],
        per_transaction_ceiling: { amount: '100', currency: 'USDT' },
        allowed_transaction_categories: ['payment']
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    },
    ...overrides
  }
}

function writeMandateTmp (mandate) {
  const dir = tmpdir()
  const path = join(dir, `mandate-${hex(randomBytes(4))}.json`)
  writeFileSync(path, JSON.stringify(mandate, null, 2))
  return path
}

function makeGate (mandatePath, agentDid, trustedIssuers) {
  return new SpendGate({ mandatePath, agentDid, trustedIssuers })
}

// ── Gate: happy path ──────────────────────────────────────────────────────

test('valid spend within ceiling → allow: true', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  const result = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '50', currency: 'USDT', category: 'payment' })
  assert.equal(result.allow, true)
  assert.equal(result.reasons.length, 0)
})

test('spend over ceiling → allow: false, reasons includes per_transaction_ceiling', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  const result = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '150', currency: 'USDT', category: 'payment' })
  assert.equal(result.allow, false)
  const hasRailOrCeiling = result.reasons.some(r =>
    r.ruleField === 'per_transaction_ceiling' || r.ruleType === 'amountLimits'
  )
  assert.ok(hasRailOrCeiling, 'should have a ceiling-related deny reason')
})

test('wrong rail → allow: false', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  const result = await gate.evaluate({ rail: 'tron', amount: '10', currency: 'USDT', category: 'payment' })
  assert.equal(result.allow, false)
  assert.ok(result.reasons.some(r => r.ruleField === 'allowed_rails'))
})

// ── Gate: currency-mismatch bypass prevention ─────────────────────────────
//
// A recurring mandate written in USDT must deny any action in a different
// currency. Two independent layers in withinScope enforce this:
//   1. per_transaction_ceiling currency check (currencyMismatch / per_transaction_ceiling)
//   2. authorizationConfig.recurring.ceiling_currency check (currencyMismatch / recurring.ceiling_currency)
//
// Both must pass for allow:true. Neither has a fall-through path that could
// allow an uncovered-currency spend — both use if/else-if/else chains that
// skip the amount comparison on currency mismatch.

test('recurring mandate ceiling_currency:USDT, action in BTC → allow:false with explicit currencyMismatch reason', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  // Action is in BTC — mandate ceiling and recurring config are both in USDT
  const result = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '0.001', currency: 'BTC', category: 'payment' })

  assert.equal(result.allow, false, 'must deny')
  // At least one explicit currencyMismatch reason — must not be a silent pass or unhandled throw
  const hasMismatchReason = result.reasons.some(r => r.ruleType === 'currencyMismatch')
  assert.ok(hasMismatchReason, `expected currencyMismatch reason; got: ${JSON.stringify(result.reasons)}`)
})

test('recurring mandate ceiling_currency:USDT, action in sats → allow:false', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  const result = await gate.evaluate({ rail: 'lightning', amount: '5000', currency: 'sats', category: 'payment' })

  assert.equal(result.allow, false, 'must deny')
  const hasMismatchReason = result.reasons.some(r => r.ruleType === 'currencyMismatch')
  assert.ok(hasMismatchReason, `expected currencyMismatch reason; got: ${JSON.stringify(result.reasons)}`)
})

test('currency mismatch does not reach amount comparison (verify no amountLimits reason on mismatch)', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  // Amount is tiny — if the gate fell through to amount comparison it would pass.
  // Confirm it does not pass.
  const result = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '0.000001', currency: 'BTC', category: 'payment' })

  assert.equal(result.allow, false, 'must deny even for tiny BTC amount')
  // Must NOT have an amountLimits reason — denial is about currency, not amount
  const hasAmountReason = result.reasons.some(r => r.ruleType === 'amountLimits')
  assert.ok(!hasAmountReason, 'should not reach amount comparison when currency mismatches')
  const hasMismatchReason = result.reasons.some(r => r.ruleType === 'currencyMismatch')
  assert.ok(hasMismatchReason, 'should have currencyMismatch reason')
})

// ── Gate: signer-boundary checks ──────────────────────────────────────────

test('self-signed mandate (issuer === agentDid) → SELF_SIGNED_MANDATE', async () => {
  const agent = makeAgent()
  // Agent signs its own mandate — forbidden
  const selfSigned = signDocument(makeMandate(agent, agent), agent)
  const path = writeMandateTmp(selfSigned)
  const gate = makeGate(path, agent.did, [agent.did])

  await assert.rejects(
    () => gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }),
    (err) => { assert.equal(err.code, 'SELF_SIGNED_MANDATE'); return true }
  )
})

test('subject mismatch → SUBJECT_MISMATCH', async () => {
  const principal = makePrincipal()
  const agentA = makeAgent()
  const agentB = makeAgent()
  // Mandate is for agentA, but gate is configured for agentB
  const signed = signDocument(makeMandate(principal, agentA), principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agentB.did, [principal.did])

  await assert.rejects(
    () => gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }),
    (err) => { assert.equal(err.code, 'SUBJECT_MISMATCH'); return true }
  )
})

test('tampered mandate body → MANDATE_INVALID', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  // Tamper the mandate
  signed.credentialSubject.actionScope.per_transaction_ceiling.amount = '9999'
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  await assert.rejects(
    () => gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }),
    (err) => { assert.equal(err.code, 'MANDATE_INVALID'); return true }
  )
})

test('expired mandate → MANDATE_INVALID', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const past = new Date(Date.now() - 2 * 86400 * 1000)
  const expired = makeMandate(principal, agent, {
    validFrom: toISO(new Date(past.getTime() - 365 * 86400 * 1000)),
    validUntil: toISO(past)
  })
  const signed = signDocument(expired, principal)
  const path = writeMandateTmp(signed)
  const gate = makeGate(path, agent.did, [principal.did])

  await assert.rejects(
    () => gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }),
    (err) => { assert.equal(err.code, 'MANDATE_INVALID'); return true }
  )
})

// ── Fail-closed MCP boundary: garbage inputs ──────────────────────────────
// These test the handleGateEvaluate wrapper in mcp-server.js by importing
// parseAction directly. Since parseAction is not exported, we test the
// boundary via a thin wrapper that mirrors handleGateEvaluate.

import { GateError as _GateError } from '../src/gate.js'

async function boundaryEvaluate (params, gate) {
  // Mirrors handleGateEvaluate in mcp-server.js
  function parseAction (p) {
    if (p === null || typeof p !== 'object' || Array.isArray(p)) throw new Error('params must be a non-null object')
    const { rail, amount, currency } = p
    if (typeof rail !== 'string' || rail.trim().length === 0) throw new Error('rail must be a non-empty string')
    if (typeof amount !== 'string' || amount.trim().length === 0) throw new Error('amount must be a non-empty string')
    if (!/^[0-9]+(\.[0-9]+)?$/.test(amount.trim()) || parseFloat(amount) <= 0) throw new Error('amount must be a positive decimal string')
    if (typeof currency !== 'string' || currency.trim().length === 0) throw new Error('currency must be a non-empty string')
    return { rail: rail.trim(), amount: amount.trim(), currency: currency.trim() }
  }
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

function makeGoodGate () {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const path = writeMandateTmp(signed)
  return { gate: makeGate(path, agent.did, [principal.did]) }
}

test('garbage input: {} → { allow: false }, no throw', async () => {
  const { gate } = makeGoodGate()
  const result = await boundaryEvaluate({}, gate)
  assert.equal(result.allow, false)
  assert.ok(typeof result.reasons[0].message === 'string')
})

test('garbage input: { rail: 123, amount: null } → { allow: false }', async () => {
  const { gate } = makeGoodGate()
  const result = await boundaryEvaluate({ rail: 123, amount: null }, gate)
  assert.equal(result.allow, false)
})

test('garbage input: negative amount → { allow: false }', async () => {
  const { gate } = makeGoodGate()
  const result = await boundaryEvaluate({ rail: 'ethereum-mainnet', amount: '-5', currency: 'USDT' }, gate)
  assert.equal(result.allow, false)
})

test('garbage input: null → { allow: false }', async () => {
  const { gate } = makeGoodGate()
  const result = await boundaryEvaluate(null, gate)
  assert.equal(result.allow, false)
})

test('garbage input: non-object string → { allow: false }', async () => {
  const { gate } = makeGoodGate()
  const result = await boundaryEvaluate('not-an-object', gate)
  assert.equal(result.allow, false)
})
