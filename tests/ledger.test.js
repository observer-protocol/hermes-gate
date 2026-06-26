// SPDX-License-Identifier: Apache-2.0
// Tests for rolling 24h cumulative cap enforcement via SpendLedger + SpendGate

'use strict'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import {
  createDidKeyAgent,
  signDocument,
  DELEGATION_SCHEMA_V2_1
} from '@observer-protocol/wdk-protocol-trust'
import { SpendGate } from '../src/gate.js'
import { SpendLedger } from '../src/spend-ledger.js'

// ── Helpers ───────────────────────────────────────────────────────────────

function hex (b) { return Buffer.from(b).toString('hex') }
function toISO (d) { return d.toISOString().replace(/\.\d+Z$/, 'Z') }
function makeTmpDir () { return mkdtempSync(join(tmpdir(), 'hermes-ledger-')) }

function makePrincipal () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/principal/0/0/0")
}

function makeAgent () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/agent/0/0/0")
}

function makeMandateWithCap (principal, agent, {
  perTx = '10',
  daily = '30',
  currency = 'USDT',
  rails = ['ethereum-mainnet']
} = {}) {
  const now = new Date()
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    id: `urn:uuid:test-cap-${hex(randomBytes(8))}`,
    issuer: principal.did,
    validFrom: toISO(now),
    validUntil: toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)),
    credentialSchema: { id: DELEGATION_SCHEMA_V2_1, type: 'JsonSchema' },
    credentialSubject: {
      id: agent.did,
      authorizationLevel: 'recurring',
      authorizationConfig: { recurring: { ceiling_amount: perTx, ceiling_currency: currency } },
      actionScope: {
        allowed_rails: rails,
        per_transaction_ceiling: { amount: perTx, currency },
        cumulative_budget: { amount: daily, currency, period: '24h' }
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    }
  }
}

function writeTmp (obj, dir) {
  const path = join(dir, `mandate-${hex(randomBytes(4))}.json`)
  writeFileSync(path, JSON.stringify(obj, null, 2))
  return path
}

// ── Test 1: 4-call sequential — calls #1-3 ALLOW, call #4 DENY ───────────
//
// per_transaction_ceiling = 10 USDT, cumulative_budget = 30 USDT / 24h
// Call #1: sum=0,  0+10 > 30? No  → ALLOW, record. Sum=10.
// Call #2: sum=10, 10+10 > 30? No → ALLOW, record. Sum=20.
// Call #3: sum=20, 20+10 > 30? No → ALLOW, record. Sum=30.
// Call #4: sum=30, 30+10 > 30? Yes → DENY with ruleType: 'cumulativeCap'.

test('rolling 24h cap: calls #1-3 ALLOW, call #4 DENY (cumulative 40 > 30 USDT)', async () => {
  const dir = makeTmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandateWithCap(principal, agent), principal)
  const mandatePath = writeTmp(signed, dir)
  const ledger = new SpendLedger(join(dir, 'spend-ledger.jsonl'))

  const gate = new SpendGate({
    mandatePath,
    agentDid: agent.did,
    trustedIssuers: [principal.did],
    spendLedger: ledger
  })

  const action = { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }

  const r1 = await gate.evaluate(action)
  assert.equal(r1.allow, true, 'call #1 (cumulative 10 USDT): should ALLOW')

  const r2 = await gate.evaluate(action)
  assert.equal(r2.allow, true, 'call #2 (cumulative 20 USDT): should ALLOW')

  const r3 = await gate.evaluate(action)
  assert.equal(r3.allow, true, 'call #3 (cumulative 30 USDT = cap, not over): should ALLOW')

  const r4 = await gate.evaluate(action)
  assert.equal(r4.allow, false, 'call #4 (cumulative would be 40 USDT > 30): must DENY')
  assert.ok(
    r4.reasons.some(r => r.ruleType === 'cumulativeCap'),
    `expected ruleType 'cumulativeCap'; got: ${JSON.stringify(r4.reasons)}`
  )
  assert.ok(
    r4.reasons.some(r => r.ruleField === 'cumulative_budget'),
    `expected ruleField 'cumulative_budget'; got: ${JSON.stringify(r4.reasons)}`
  )
})

// ── Test 2: restart durability ────────────────────────────────────────────
//
// Record spends via a first SpendLedger instance. Re-instantiate with the
// same path (simulating gate restart). Confirm the window sum is preserved
// and the cap still holds via a fresh SpendGate.

test('restart durability: rolling sum survives SpendLedger re-instantiation', async () => {
  const dir = makeTmpDir()
  const ledgerPath = join(dir, 'spend-ledger.jsonl')

  // Record two 10 USDT spends in the first ledger instance
  const ledger1 = new SpendLedger(ledgerPath)
  ledger1.record({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' })
  ledger1.record({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' })
  assert.equal(ledger1.sumWindow('ethereum-mainnet', 'USDT'), 20, 'pre-restart sum should be 20')

  // Simulate restart: create new SpendLedger from same file
  const ledger2 = new SpendLedger(ledgerPath)
  assert.equal(ledger2.sumWindow('ethereum-mainnet', 'USDT'), 20, 'post-restart sum should still be 20')

  // Wire up a fresh gate using the reloaded ledger
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandateWithCap(principal, agent), principal)
  const mandatePath = writeTmp(signed, dir)

  const gate = new SpendGate({
    mandatePath,
    agentDid: agent.did,
    trustedIssuers: [principal.did],
    spendLedger: ledger2
  })

  // 20 already recorded. One more 10 is allowed (20+10=30, exactly at cap).
  const r1 = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' })
  assert.equal(r1.allow, true, 'one more 10 USDT allowed (30 total = cap, not over)')

  // Now at 30. Any further spend is denied.
  const r2 = await gate.evaluate({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' })
  assert.equal(r2.allow, false, 'next 10 USDT denied (40 total > 30 cap)')
  assert.ok(r2.reasons.some(r => r.ruleType === 'cumulativeCap'), 'denial reason must be cumulativeCap')
})

// ── Test 3: window boundary ───────────────────────────────────────────────
//
// Entry at 23h ago: inside the 24h rolling window → counted.
// Entry at 25h ago: outside the window → excluded.
// Sum must equal 10 (the inside entry only).

test('window boundary: 23h-old entry counted, 25h-old entry excluded', () => {
  const dir = makeTmpDir()
  const ledgerPath = join(dir, 'spend-ledger.jsonl')
  const now = Date.now()

  const inside = { ts: now - 23 * 60 * 60 * 1000, rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }
  const outside = { ts: now - 25 * 60 * 60 * 1000, rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' }

  // Write directly with controlled timestamps (before constructing ledger so
  // the constructor's existsSync check leaves the file alone)
  writeFileSync(ledgerPath, JSON.stringify(inside) + '\n' + JSON.stringify(outside) + '\n', { mode: 0o600 })

  const ledger = new SpendLedger(ledgerPath)
  const sum = ledger.sumWindow('ethereum-mainnet', 'USDT')
  assert.equal(sum, 10, 'only the 23h-old entry should fall inside the 24h window; 25h-old is excluded')
})
