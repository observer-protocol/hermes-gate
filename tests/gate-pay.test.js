// SPDX-License-Identifier: Apache-2.0
// Tests for gate_pay: probe-402, reserve/commit/release lifecycle, and the
// full allow/deny/fail/reconcile paths.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, chmodSync, mkdtempSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
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
import { gatePay } from '../src/gate-pay.js'
import { probe402 } from '../src/probe-402.js'

// ── Helpers ───────────────────────────────────────────────────────────────

function hex (b) { return Buffer.from(b).toString('hex') }
function toISO (d) { return d.toISOString().replace(/\.\d+Z$/, 'Z') }
function tmpDir () { return mkdtempSync(join(tmpdir(), 'hermes-gate-pay-')) }

function makePrincipal () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/principal/0/0/0")
}
function makeAgent () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/agent/0/0/0")
}

function makeLightningMandate (principal, agent, { perTx = '1000', daily = '5000', currency = 'sat' } = {}) {
  const now = new Date()
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    id: `urn:uuid:test-ln-${hex(randomBytes(8))}`,
    issuer: principal.did,
    validFrom: toISO(now),
    validUntil: toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)),
    credentialSchema: { id: DELEGATION_SCHEMA_V2_1, type: 'JsonSchema' },
    credentialSubject: {
      id: agent.did,
      authorizationLevel: 'recurring',
      authorizationConfig: { recurring: { ceiling_amount: perTx, ceiling_currency: currency } },
      actionScope: {
        allowed_rails: ['lightning'],
        per_transaction_ceiling: { amount: perTx, currency },
        cumulative_budget: { amount: daily, currency, period: '24h' }
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    }
  }
}

function writeMandate (obj, dir) {
  const path = join(dir, `mandate-${hex(randomBytes(4))}.json`)
  writeFileSync(path, JSON.stringify(obj, null, 2))
  return path
}

function makeGate (mandatePath, agentDid, trustedIssuers, ledger) {
  return new SpendGate({ mandatePath, agentDid, trustedIssuers, spendLedger: ledger })
}

// Mock mppx script — reads MOCK_MPPX_MODE env var
let mockMppxPath
before(() => {
  const dir = tmpDir()
  mockMppxPath = join(dir, 'mock-mppx.sh')
  writeFileSync(mockMppxPath, `#!/bin/sh
mode=\${MOCK_MPPX_MODE:-success}
case "\$mode" in
  success) printf '{"status":"paid","payment_hash":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","amount":100}\\n'; exit 0;;
  unparseable) printf 'unknown output line\\n'; exit 0;;
  fail) printf 'Error: connection refused\\n' >&2; exit 1;;
  *) printf '{"status":"paid","payment_hash":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}\\n'; exit 0;;
esac
`)
  chmodSync(mockMppxPath, 0o755)
})

// Local 402 probe server — returns WWW-Authenticate: MPP amount="100", currency="sat"
let probeServer
let probePort
let probeUrl
before(async () => {
  probeServer = createServer((req, res) => {
    res.writeHead(402, {
      'WWW-Authenticate': 'MPP amount="100", currency="sat", methods="mppx"'
    })
    res.end()
  })
  await new Promise((resolve, reject) => {
    probeServer.listen(0, '127.0.0.1', () => {
      probePort = probeServer.address().port
      probeUrl = `http://127.0.0.1:${probePort}/resource`
      resolve()
    })
    probeServer.on('error', reject)
  })
})

after(() => {
  probeServer?.close()
})

// ── probe-402 unit tests ───────────────────────────────────────────────────

test('probe402 — parses MPP amount/currency from local 402 server', async () => {
  const r = await probe402(probeUrl)
  assert.equal(r.amount, '100')
  assert.equal(r.currency, 'sat')
})

test('probe402 — returns null for 200 response', async () => {
  const okServer = createServer((req, res) => { res.writeHead(200); res.end('ok') })
  const port = await new Promise((resolve, reject) => {
    okServer.listen(0, '127.0.0.1', () => { resolve(okServer.address().port) })
    okServer.on('error', reject)
  })
  try {
    const r = await probe402(`http://127.0.0.1:${port}/`)
    assert.equal(r.amount, null)
    assert.equal(r.currency, null)
  } finally {
    okServer.close()
  }
})

test('probe402 — returns null for invalid URL', async () => {
  const r = await probe402('not-a-url')
  assert.equal(r.amount, null)
  assert.equal(r.currency, null)
})

test('probe402 — decodes BOLT11 L402 invoice (lnbc1u → 100 sat)', async () => {
  const l402Server = createServer((req, res) => {
    res.writeHead(402, {
      'WWW-Authenticate': 'L402 macaroon="abc", invoice="lnbc1u1ptest"'
    })
    res.end()
  })
  const port = await new Promise((resolve, reject) => {
    l402Server.listen(0, '127.0.0.1', () => { resolve(l402Server.address().port) })
    l402Server.on('error', reject)
  })
  try {
    const r = await probe402(`http://127.0.0.1:${port}/`)
    assert.equal(r.amount, '100')
    assert.equal(r.currency, 'sat')
  } finally {
    l402Server.close()
  }
})

// ── SpendLedger reserve/commit/release ────────────────────────────────────

test('SpendLedger — reserve counted by sumWindow', () => {
  const dir = tmpDir()
  const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
  assert.equal(ledger.sumWindow('lightning', 'sat'), 0)

  const id = ledger.reserve({ rail: 'lightning', amount: '100', currency: 'sat' })
  assert.ok(typeof id === 'string' && id.length > 0)
  assert.equal(ledger.sumWindow('lightning', 'sat'), 100)
})

test('SpendLedger — commit converts reservation, still counted', () => {
  const dir = tmpDir()
  const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
  const id = ledger.reserve({ rail: 'lightning', amount: '200', currency: 'sat' })
  ledger.commit(id)
  assert.equal(ledger.sumWindow('lightning', 'sat'), 200)
  // Confirm the entry no longer has state:reserved
  const raw = readFileSync(join(dir, 'ledger.jsonl'), 'utf8')
  const entries = raw.trim().split('\n').map(l => JSON.parse(l))
  assert.ok(entries.every(e => e.state !== 'reserved'), 'committed entry must not have state:reserved')
  assert.ok(entries.some(e => e.state === 'committed'), 'committed entry must have state:committed')
})

test('SpendLedger — release removes reservation, cap restored', () => {
  const dir = tmpDir()
  const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
  const id = ledger.reserve({ rail: 'lightning', amount: '500', currency: 'sat' })
  assert.equal(ledger.sumWindow('lightning', 'sat'), 500)
  ledger.release(id)
  assert.equal(ledger.sumWindow('lightning', 'sat'), 0)
})

test('SpendLedger — commit with meta stores reconciliation flag', () => {
  const dir = tmpDir()
  const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
  const id = ledger.reserve({ rail: 'lightning', amount: '100', currency: 'sat' })
  ledger.commit(id, { reconciliation_needed: true })
  const raw = readFileSync(join(dir, 'ledger.jsonl'), 'utf8')
  const entry = JSON.parse(raw.trim())
  assert.equal(entry.reconciliation_needed, true)
  assert.equal(entry.state, 'committed')
})

test('SpendLedger — reserve + release does not affect committed entries', () => {
  const dir = tmpDir()
  const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
  ledger.record({ rail: 'lightning', amount: '50', currency: 'sat' })
  const id = ledger.reserve({ rail: 'lightning', amount: '50', currency: 'sat' })
  assert.equal(ledger.sumWindow('lightning', 'sat'), 100)
  ledger.release(id)
  assert.equal(ledger.sumWindow('lightning', 'sat'), 50)  // committed entry still there
})

// ── gate_pay full paths ────────────────────────────────────────────────────

test('gate_pay — allow: probes 402, evaluates, commits, returns tx_ref', async () => {
  const dir = tmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeLightningMandate(principal, agent), principal)
  const mandatePath = writeMandate(signed, dir)
  const ledgerPath = join(dir, 'ledger.jsonl')
  const ledger = new SpendLedger(ledgerPath)
  const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

  process.env.MOCK_MPPX_MODE = 'success'
  const r = await gatePay(probeUrl, { gate, mppxPath: mockMppxPath })
  delete process.env.MOCK_MPPX_MODE

  assert.equal(r.allowed, true, `expected allowed:true, got ${JSON.stringify(r)}`)
  assert.equal(r.currency, 'sat')
  assert.equal(r.rail, 'lightning')
  assert.ok(typeof r.tx_ref === 'string' && r.tx_ref.length === 64, 'expected 64-char payment hash')

  // Ledger must have exactly one committed entry
  const raw = readFileSync(ledgerPath, 'utf8').trim().split('\n').filter(Boolean)
  assert.equal(raw.length, 1)
  const entry = JSON.parse(raw[0])
  assert.equal(entry.state, 'committed')
  assert.equal(entry.rail, 'lightning')
  assert.equal(entry.currency, 'sat')
})

test('gate_pay — deny: ceiling exceeded, no ledger entry', async () => {
  const dir = tmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  // perTx ceiling is 50 sat; probe returns 100 sat → ceiling exceeded
  const signed = signDocument(
    makeLightningMandate(principal, agent, { perTx: '50', daily: '5000', currency: 'sat' }),
    principal
  )
  const mandatePath = writeMandate(signed, dir)
  const ledgerPath = join(dir, 'ledger.jsonl')
  const ledger = new SpendLedger(ledgerPath)
  const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

  const r = await gatePay(probeUrl, { gate, mppxPath: mockMppxPath })

  assert.equal(r.allowed, false, `expected allowed:false, got ${JSON.stringify(r)}`)
  assert.ok(r.reasons?.length > 0, 'expected denial reasons')
  // No ledger entry
  const raw = readFileSync(ledgerPath, 'utf8').trim()
  assert.equal(raw, '', 'ledger must be empty after ceiling denial')
})

test('gate_pay — deny: cumulative cap exceeded by reserve, no ledger entry', async () => {
  const dir = tmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  // daily cap 150 sat; reserve 100 already; probe 100 more → 200 > 150 → denied
  const signed = signDocument(
    makeLightningMandate(principal, agent, { perTx: '200', daily: '150', currency: 'sat' }),
    principal
  )
  const mandatePath = writeMandate(signed, dir)
  const ledgerPath = join(dir, 'ledger.jsonl')
  const ledger = new SpendLedger(ledgerPath)
  // Pre-fill 100 sat reserved
  ledger.reserve({ rail: 'lightning', amount: '100', currency: 'sat' })
  const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

  const r = await gatePay(probeUrl, { gate, mppxPath: mockMppxPath })

  assert.equal(r.allowed, false, `expected denied, got ${JSON.stringify(r)}`)
  assert.ok(
    (r.reasons || []).some(x => x.ruleType === 'cumulativeCap'),
    `expected cumulativeCap, got ${JSON.stringify(r.reasons)}`
  )
  // No new committed entry added
  const raw = readFileSync(ledgerPath, 'utf8').trim().split('\n').filter(Boolean)
  assert.ok(raw.every(l => JSON.parse(l).state === 'reserved'), 'no new committed entry')
})

test('gate_pay — mppx failure: reserve released, returns allowed:false', async () => {
  const dir = tmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeLightningMandate(principal, agent), principal)
  const mandatePath = writeMandate(signed, dir)
  const ledgerPath = join(dir, 'ledger.jsonl')
  const ledger = new SpendLedger(ledgerPath)
  const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

  process.env.MOCK_MPPX_MODE = 'fail'
  const r = await gatePay(probeUrl, { gate, mppxPath: mockMppxPath })
  delete process.env.MOCK_MPPX_MODE

  assert.equal(r.allowed, false, `expected allowed:false after mppx failure`)
  assert.ok(
    (r.reasons || []).some(x => x.ruleType === 'payment_failed'),
    `expected payment_failed reason, got ${JSON.stringify(r.reasons)}`
  )
  // Reserve must be released — ledger empty
  const sum = ledger.sumWindow('lightning', 'sat')
  assert.equal(sum, 0, 'reserve must be released on mppx failure; ledger sum must be 0')
})

test('gate_pay — unparseable mppx output: commits at probed amount, reconciliation_required', async () => {
  const dir = tmpDir()
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeLightningMandate(principal, agent), principal)
  const mandatePath = writeMandate(signed, dir)
  const ledgerPath = join(dir, 'ledger.jsonl')
  const ledger = new SpendLedger(ledgerPath)
  const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

  process.env.MOCK_MPPX_MODE = 'unparseable'
  const r = await gatePay(probeUrl, { gate, mppxPath: mockMppxPath })
  delete process.env.MOCK_MPPX_MODE

  assert.equal(r.allowed, true, 'allowed must be true (mppx exited 0)')
  assert.equal(r.tx_ref, null, 'tx_ref must be null when output unparseable')
  assert.equal(r.reconciliation_required, true, 'reconciliation_required must be true')
  assert.equal(r.amount, '100', 'amount must be probed amount')

  // Ledger must have a committed entry with reconciliation_needed flag
  const raw = readFileSync(ledgerPath, 'utf8').trim().split('\n').filter(Boolean)
  assert.equal(raw.length, 1)
  const entry = JSON.parse(raw[0])
  assert.equal(entry.state, 'committed')
  assert.equal(entry.reconciliation_needed, true)
  // Cap must count this spend (fail toward over-counting)
  const sum = ledger.sumWindow('lightning', 'sat')
  assert.equal(sum, 100)
})

test('gate_pay — fail closed when url has no 402 header amount', async () => {
  // 402 server with no parseable WWW-Authenticate
  const badServer = createServer((req, res) => {
    res.writeHead(402, { 'WWW-Authenticate': 'Bearer realm="no-mpp"' })
    res.end()
  })
  const port = await new Promise((resolve, reject) => {
    badServer.listen(0, '127.0.0.1', () => { resolve(badServer.address().port) })
    badServer.on('error', reject)
  })
  try {
    const dir = tmpDir()
    const principal = makePrincipal()
    const agent = makeAgent()
    const signed = signDocument(makeLightningMandate(principal, agent), principal)
    const mandatePath = writeMandate(signed, dir)
    const ledger = new SpendLedger(join(dir, 'ledger.jsonl'))
    const gate = makeGate(mandatePath, agent.did, [principal.did], ledger)

    const r = await gatePay(`http://127.0.0.1:${port}/`, { gate, mppxPath: mockMppxPath })

    assert.equal(r.allowed, false)
    assert.ok(
      (r.reasons || []).some(x => x.ruleType === 'probe_error'),
      `expected probe_error, got ${JSON.stringify(r.reasons)}`
    )
  } finally {
    badServer.close()
  }
})
