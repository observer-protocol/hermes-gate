// SPDX-License-Identifier: Apache-2.0
// Tests for bootstrap.generate()

'use strict'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdirSync, existsSync } from 'node:fs'
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
  assert.equal(signed.proof.type, 'DataIntegrityProof')
  assert.equal(signed.proof.cryptosuite, 'eddsa-jcs-2022')
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

// ── Bootstrap invariant: no-WBC community install is impossible ───────────────
//
// The inverse of pe-042. pe-042 proves the runtime adapter correctly handles
// a deliberate no-WBC enterprise caller. The tests below prove the community
// bootstrap can NEVER produce a no-WBC install — the walletBindingCredentialPath
// is always populated, so every default install enters BIND→LINK→AUTHORIZE.

test('default install always generates wbc.json (no-WBC-community-install impossible)', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  // wbc.json must exist — no conditional, no opt-in, no flag
  assert.ok(existsSync(join(outputDir, 'wbc.json')), 'wbc.json always written by generate()')

  // wallet-identity-key.json must exist so the wallet service can derive its DID
  assert.ok(existsSync(join(outputDir, 'wallet-identity-key.json')), 'wallet-identity-key.json always written')

  const wbc = JSON.parse(readFileSync(join(outputDir, 'wbc.json'), 'utf8'))
  const principal = JSON.parse(readFileSync(join(outputDir, 'principal-key.json'), 'utf8'))
  const walletKey = JSON.parse(readFileSync(join(outputDir, 'wallet-identity-key.json'), 'utf8'))

  // Type
  assert.ok(Array.isArray(wbc.type), 'wbc.type is array')
  assert.ok(wbc.type.includes('WalletBindingCredential'), 'wbc type includes WalletBindingCredential')

  // Proof suite — must be eddsa-jcs-2022, not Ed25519Signature2026
  assert.ok(wbc.proof, 'wbc has proof')
  assert.equal(wbc.proof.type, 'DataIntegrityProof', 'wbc proof type is DataIntegrityProof')
  assert.equal(wbc.proof.cryptosuite, 'eddsa-jcs-2022', 'wbc proof cryptosuite is eddsa-jcs-2022')
  assert.ok(wbc.proof.proofValue?.startsWith('z'), 'proofValue has multibase z prefix')

  // Issuer is the principal
  assert.equal(wbc.issuer, principal.did, 'wbc.issuer === principal.did')

  // walletAddress is the derived wallet DID — this is what ctx.wallet_id must match at runtime
  assert.equal(wbc.credentialSubject.walletAddress, walletKey.did, 'wbc.credentialSubject.walletAddress === wallet.did')
})

test('mandate actionScope has no allowed_transaction_categories', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))

  // Enforcement of allowed_transaction_categories requires config.transactionCategory
  // to be set at runtime. In the default Hermes install it is not set, so including
  // this field would cause every transaction to DENY silently (fail-closed).
  assert.ok(
    !('allowed_transaction_categories' in (mandate.credentialSubject?.actionScope ?? {})),
    'actionScope must not include allowed_transaction_categories in bootstrap manifest'
  )
})

test('wbc.issuer === mandate.issuer satisfies dev-mode LINK invariant', () => {
  const outputDir = join(tmpdir(), `hermes-gate-test-${hex(randomBytes(4))}`)
  mkdirSync(outputDir, { recursive: true })

  generate({ outputDir })

  const wbc = JSON.parse(readFileSync(join(outputDir, 'wbc.json'), 'utf8'))
  const mandate = JSON.parse(readFileSync(join(outputDir, 'spend-mandate.json'), 'utf8'))

  // The LINK step in runRuntimeAdapter (dev mode) checks: wbc.issuer === mandate.issuer.
  // Both must be the same principal DID — this is what ensures the WBC and the
  // SpendMandate were issued by the same operator, closing the cross-principal pairing
  // attack. If this assertion fails, the gate will DENY [issuer-linkage] on every call.
  assert.equal(wbc.issuer, mandate.issuer, 'wbc.issuer === mandate.issuer (LINK invariant)')
})
