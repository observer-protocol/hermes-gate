// SPDX-License-Identifier: Apache-2.0
// Tests for bootstrap.generate()

'use strict'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import {
  createDidKeyAgent,
  signDocument,
  verifyDocument,
  DELEGATION_SCHEMA_V2_1
} from '@observer-protocol/wdk-protocol-trust'
import { generate } from '../src/bootstrap.js'

function hex (bytes) { return Buffer.from(bytes).toString('hex') }

test('generate produces three distinct seeds', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const principal = JSON.parse(readFileSync(join(outputDir, 'principal-key.json'), 'utf8'))
  const agent = JSON.parse(readFileSync(join(outputDir, 'agent-identity-key.json'), 'utf8'))
  const wallet = JSON.parse(readFileSync(join(outputDir, 'wallet-seed.json'), 'utf8'))

  assert.ok(principal.seed_hex, 'principal seed present')
  assert.ok(agent.seed_hex, 'agent seed present')
  assert.ok(wallet.seed_hex, 'wallet seed present')

  // All three seeds must be distinct
  assert.notEqual(principal.seed_hex, agent.seed_hex, 'principal seed ≠ agent seed')
  assert.notEqual(principal.seed_hex, wallet.seed_hex, 'principal seed ≠ wallet seed')
  assert.notEqual(agent.seed_hex, wallet.seed_hex, 'agent seed ≠ wallet seed')
})

test('mandate subject === agent did:key', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const agent = JSON.parse(readFileSync(join(outputDir, 'agent-identity-key.json'), 'utf8'))
  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))

  assert.equal(mandate.credentialSubject.id, agent.did, 'mandate subject matches agent DID')
})

test('mandate issuer === principal did:key', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const principal = JSON.parse(readFileSync(join(outputDir, 'principal-key.json'), 'utf8'))
  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))

  assert.equal(mandate.issuer, principal.did, 'mandate issuer matches principal DID')
})

test('signDocument + verifyDocument round-trip passes', () => {
  const seed = randomBytes(32)
  const agent = createDidKeyAgent(seed, "m/observer-protocol'/principal/0/0/0")
  const doc = { id: 'test', payload: 'hello', issuer: agent.did }
  const signed = signDocument(doc, agent)

  assert.ok(signed.proof, 'proof attached')
  assert.equal(signed.proof.type, 'Ed25519Signature2026')
  assert.equal(signed.proof.verificationMethod, agent.keyId)

  const valid = verifyDocument(signed, agent.didDocument)
  assert.equal(valid, true, 'verifyDocument returns true for valid signature')
})

test('verifyDocument returns false for tampered document', () => {
  const seed = randomBytes(32)
  const agent = createDidKeyAgent(seed, "m/observer-protocol'/principal/0/0/0")
  const doc = { id: 'test', payload: 'hello', issuer: agent.did }
  const signed = signDocument(doc, agent)

  signed.payload = 'tampered'
  const valid = verifyDocument(signed, agent.didDocument)
  assert.equal(valid, false, 'verifyDocument returns false for tampered body')
})

test('mandate type includes ObserverDelegationCredential', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))
  assert.ok(Array.isArray(mandate.type), 'type is array')
  assert.ok(mandate.type.includes('ObserverDelegationCredential'), 'type includes ObserverDelegationCredential')
})

test('mandate schema is DELEGATION_SCHEMA_V2_1', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))
  assert.equal(mandate.credentialSchema.id, DELEGATION_SCHEMA_V2_1)
})
