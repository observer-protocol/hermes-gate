// SPDX-License-Identifier: Apache-2.0
// Tests for the Python plugin's payment detection logic, exercised via a
// small Python subprocess. No mocking — real Python, real regex.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execSync } from 'node:child_process'

function py (code) {
  return execSync(`python3 -c "${code.replace(/"/g, '\\"')}"`, { encoding: 'utf8' }).trim()
}

function pyDetect (toolName, args) {
  const script = `
import sys, json
sys.path.insert(0, 'plugin')
from _payment_detector import detect_payment
result = detect_payment(${JSON.stringify(toolName)}, ${JSON.stringify(args)})
print(json.dumps(result))
`
  const out = execSync(`python3 -c '${script.replace(/'/g, "'\\''")}'`, { encoding: 'utf8' }).trim()
  return JSON.parse(out)
}

function pyParse402 (auth) {
  const script = `
import sys, json
sys.path.insert(0, 'plugin')
from _payment_detector import _parse_402_headers
result = _parse_402_headers({"WWW-Authenticate": ${JSON.stringify(auth)}})
print(json.dumps(result))
`
  const out = execSync(`python3 -c '${script.replace(/'/g, "'\\''")}'`, { encoding: 'utf8' }).trim()
  return JSON.parse(out)
}

// ── Payment detection ──────────────────────────────────────────────────────

test('plugin — detects mppx command', async () => {
  const r = pyDetect('terminal', { command: 'mppx https://api.example.com/resource' })
  assert.equal(r.rail, 'lightning')
  assert.equal(r.url, 'https://api.example.com/resource')
})

test('plugin — detects tempo wallet pay', async () => {
  const r = pyDetect('terminal', { command: 'tempo wallet pay https://api.example.com/v1/data' })
  assert.equal(r.rail, 'ethereum-mainnet')
  assert.equal(r.url, 'https://api.example.com/v1/data')
})

test('plugin — detects agentcash pay', async () => {
  const r = pyDetect('terminal', { command: 'agentcash pay https://api.example.com' })
  assert.equal(r.rail, 'ethereum-mainnet')
})

test('plugin — ignores non-terminal tools', async () => {
  const r = pyDetect('web_search', { query: 'mppx https://example.com' })
  assert.equal(r, null)
})

test('plugin — ignores non-payment terminal commands', async () => {
  const r = pyDetect('terminal', { command: 'ls -la /home/atlas' })
  assert.equal(r, null)
})

test('plugin — ignores partial matches (mppx in a path)', async () => {
  const r = pyDetect('terminal', { command: 'cat /home/atlas/mppx.log' })
  assert.equal(r, null)
})

// ── 402 header parsing ─────────────────────────────────────────────────────

test('plugin — parses MPP amount/currency headers', async () => {
  const r = pyParse402('MPP realm="Test", amount="12.50", currency="USDT", methods="mppx"')
  assert.equal(r.amount, '12.50')
  assert.equal(r.currency, 'USDT')
})

test('plugin — parses L402 BOLT11 invoice sats', async () => {
  // lnbc1u = 1 micro-BTC = 100 sats (1 μBTC × 100 sat/μBTC)
  const r = pyParse402('L402 macaroon="abc", invoice="lnbc1u1ptest"')
  assert.equal(r.amount, '100')
  assert.equal(r.currency, 'sat')
})

test('plugin — returns null amount for unrecognized 402 format', async () => {
  const r = pyParse402('Bearer realm="payment required"')
  assert.equal(r.amount, null)
  assert.equal(r.currency, null)
})
