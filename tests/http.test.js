// SPDX-License-Identifier: Apache-2.0
// Tests for the hermes-gate HTTP endpoint (binding-tier plugin interface).
// Spawns the MCP server with HERMES_GATE_HTTP_PORT set, then makes real
// HTTP calls to verify the endpoint behaves identically to the MCP gate tools.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'

// ── Test mandate setup ─────────────────────────────────────────────────────

const WORK_DIR = mkdtempSync(join(tmpdir(), 'hermes-gate-http-'))
const OUTPUT = join(WORK_DIR, 'output')

execSync(
  `node bin/hermes-gate.js bootstrap generate --output-dir ${OUTPUT} --ceiling-amount 10 --ceil-currency USDT --daily-cap-amount 30 --daily-cap-currency USDT`,
  { stdio: 'pipe' }
)

const mandatePath = join(OUTPUT, 'spend-mandate.json')
const wbcPath = join(OUTPUT, 'wbc.json')
const agentKey = JSON.parse(
  (await import('node:fs')).readFileSync(join(OUTPUT, 'agent-identity-key.json'), 'utf8')
)
const wbc = JSON.parse(
  (await import('node:fs')).readFileSync(wbcPath, 'utf8')
)
const AGENT_DID = agentKey.did
const WALLET_DID = wbc.credentialSubject.walletAddress
const HTTP_PORT = 18472  // dedicated test port

// ── Gate process lifecycle ─────────────────────────────────────────────────

let gateProc

before(async () => {
  gateProc = spawn('node', ['src/mcp-server.js'], {
    env: {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
      HERMES_MANDATE_PATH: mandatePath,
      HERMES_WBC_PATH: wbcPath,
      HERMES_AGENT_DID: AGENT_DID,
      HERMES_GATE_HTTP_PORT: String(HTTP_PORT)
    },
    stdio: ['pipe', 'pipe', 'pipe']
  })

  // Wait for the HTTP port to be ready
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('gate HTTP endpoint did not start in time')), 5000)
    let stderr = ''
    gateProc.stderr.on('data', d => {
      stderr += d.toString()
      if (stderr.includes('HTTP endpoint listening')) {
        clearTimeout(timeout)
        resolve()
      }
    })
    gateProc.on('exit', (code) => {
      clearTimeout(timeout)
      reject(new Error(`gate exited early with code ${code}`))
    })
  })
})

after(() => {
  if (gateProc) gateProc.kill()
})

// ── Helpers ────────────────────────────────────────────────────────────────

async function gateEvaluate (body) {
  const resp = await fetch(`http://127.0.0.1:${HTTP_PORT}/gate/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  return resp.json()
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('HTTP — allow within ceiling', async () => {
  const r = await gateEvaluate({
    rail: 'ethereum-mainnet', amount: '5', currency: 'USDT', wallet_id: WALLET_DID
  })
  assert.equal(r.allow, true, `expected allow:true, got ${JSON.stringify(r)}`)
})

test('HTTP — deny per-transaction ceiling exceeded', async () => {
  const r = await gateEvaluate({
    rail: 'ethereum-mainnet', amount: '15', currency: 'USDT', wallet_id: WALLET_DID
  })
  assert.equal(r.allow, false)
  assert.ok(
    (r.reasons || []).some(x =>
      x.ruleType === 'amountLimits' ||
      (x.ruleField && x.ruleField.includes('ceiling'))
    ),
    `expected ceiling rule, got ${JSON.stringify(r.reasons)}`
  )
})

test('HTTP — deny wrong wallet_id', async () => {
  const r = await gateEvaluate({
    rail: 'ethereum-mainnet', amount: '5', currency: 'USDT', wallet_id: 'did:key:zFAKE'
  })
  assert.equal(r.allow, false)
  assert.ok(
    JSON.stringify(r.reasons).includes('[bind]'),
    `expected [bind] reason, got ${JSON.stringify(r.reasons)}`
  )
})

test('HTTP — deny invalid rail', async () => {
  const r = await gateEvaluate({
    rail: 'tron', amount: '5', currency: 'USDT', wallet_id: WALLET_DID
  })
  assert.equal(r.allow, false)
})

test('HTTP — fail closed on malformed input', async () => {
  const r = await gateEvaluate({ rail: '', amount: 'not-a-number', currency: 'USDT' })
  assert.equal(r.allow, false)
  assert.ok(r.reasons?.length > 0)
})

test('HTTP — cumulative cap enforced across calls', async () => {
  // Fresh ledger path for isolation
  const ledgerPath = join(WORK_DIR, 'http-cap-ledger.jsonl')

  const proc1 = spawn('node', ['src/mcp-server.js'], {
    env: {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
      HERMES_MANDATE_PATH: mandatePath,
      HERMES_WBC_PATH: wbcPath,
      HERMES_AGENT_DID: AGENT_DID,
      HERMES_GATE_HTTP_PORT: String(HTTP_PORT + 1),
      HERMES_LEDGER_PATH: ledgerPath
    },
    stdio: ['pipe', 'pipe', 'pipe']
  })

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('cap test gate did not start')), 5000)
    let stderr = ''
    proc1.stderr.on('data', d => {
      stderr += d.toString()
      if (stderr.includes('HTTP endpoint listening')) { clearTimeout(timeout); resolve() }
    })
    proc1.on('exit', (code) => { clearTimeout(timeout); reject(new Error(`exit ${code}`)) })
  })

  const call = (amount) => fetch(`http://127.0.0.1:${HTTP_PORT + 1}/gate/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rail: 'ethereum-mainnet', amount, currency: 'USDT', wallet_id: WALLET_DID })
  }).then(r => r.json())

  const r1 = await call('10')
  const r2 = await call('10')
  const r3 = await call('10')

  assert.equal(r1.allow, true, '#1 should allow')
  assert.equal(r2.allow, true, '#2 should allow')
  assert.equal(r3.allow, true, '#3 should allow (sum=30=cap)')

  proc1.kill()

  // Restart with same ledger — call #4 must deny (cumulative 40 > 30)
  const proc2 = spawn('node', ['src/mcp-server.js'], {
    env: {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
      HERMES_MANDATE_PATH: mandatePath,
      HERMES_WBC_PATH: wbcPath,
      HERMES_AGENT_DID: AGENT_DID,
      HERMES_GATE_HTTP_PORT: String(HTTP_PORT + 2),
      HERMES_LEDGER_PATH: ledgerPath
    },
    stdio: ['pipe', 'pipe', 'pipe']
  })

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('cap restart gate did not start')), 5000)
    let stderr = ''
    proc2.stderr.on('data', d => {
      stderr += d.toString()
      if (stderr.includes('HTTP endpoint listening')) { clearTimeout(timeout); resolve() }
    })
    proc2.on('exit', (code) => { clearTimeout(timeout); reject(new Error(`exit ${code}`)) })
  })

  const r4 = await fetch(`http://127.0.0.1:${HTTP_PORT + 2}/gate/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rail: 'ethereum-mainnet', amount: '10', currency: 'USDT', wallet_id: WALLET_DID })
  }).then(r => r.json())

  proc2.kill()

  assert.equal(r4.allow, false, '#4 after restart should deny (cumulative cap)')
  assert.ok(
    (r4.reasons || []).some(r => r.ruleType === 'cumulativeCap'),
    `expected cumulativeCap, got ${JSON.stringify(r4.reasons)}`
  )
})
