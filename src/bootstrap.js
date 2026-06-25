// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { randomBytes, createHash } from 'node:crypto'
import { writeFileSync, mkdirSync, cpSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import {
  createDidKeyAgent,
  signDocument,
  DELEGATION_SCHEMA_V2_1
} from '@observer-protocol/wdk-protocol-trust'

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function toISO (d) {
  return d.toISOString().replace(/\.\d+Z$/, 'Z')
}

// ── eddsa-jcs-2022 signer ─────────────────────────────────────────────────────
//
// Produces a DataIntegrityProof / eddsa-jcs-2022 credential, which is the
// only proof suite accepted by @observer-protocol/policy-engine's verifyWbc.
//
// The signing algorithm (W3C VC Data Integrity EdDSA Cryptosuites §3.4):
//   hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
//
// where proofConfig is the proof block without proofValue, and JCS is RFC 8785
// sorted-key JSON canonicalization. The signature is Ed25519(hashData).
//
// Note: this is NOT the same as the legacy Ed25519Signature2026 suite used by
// signDocument() in wdk-protocol-trust. Do not use signDocument() for WBCs.

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Encode (buf) {
  let zeros = 0
  while (zeros < buf.length && buf[zeros] === 0) zeros++
  let n = 0n
  for (const b of buf) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n }
  return '1'.repeat(zeros) + out
}

function jcs (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(v => jcs(v ?? null)).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.filter(k => value[k] !== undefined).map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}'
}

function sha256 (data) {
  return createHash('sha256').update(data).digest()
}

/**
 * Sign a document using DataIntegrityProof / eddsa-jcs-2022.
 *
 * @param {Record<string, unknown>} doc - Unsigned document.
 * @param {{ keyId: string, sign: (bytes: Buffer) => string }} agent -
 *   A createDidKeyAgent() result. agent.sign(bytes) calls ed25519.sign(bytes, sk)
 *   via @noble/curves and returns a 64-byte signature as a hex string.
 * @returns {Record<string, unknown>} The signed document.
 */
function signEddsaJcs2022 (doc, agent) {
  const docNoProof = {}
  for (const [k, v] of Object.entries(doc)) if (k !== 'proof') docNoProof[k] = v

  const proofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: toISO(new Date()),
    verificationMethod: agent.keyId,
    proofPurpose: 'assertionMethod'
  }
  // Context binding per W3C spec §3.4: copy @context from document to proof.
  if ('@context' in docNoProof) proofOptions['@context'] = docNoProof['@context']

  const hashData = Buffer.concat([
    sha256(Buffer.from(jcs(proofOptions))),
    sha256(Buffer.from(jcs(docNoProof)))
  ])

  // agent.sign calls signChallenge(hashData, privateKey) → ed25519.sign(hashData, sk)
  // Returns 64-byte signature as hex string.
  const sigHex = agent.sign(hashData)
  const proofValue = 'z' + base58Encode(Buffer.from(sigHex, 'hex'))

  return { ...docNoProof, proof: { ...proofOptions, proofValue } }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate all key material, a signed SpendMandate, and a WalletBindingCredential
 * locally. No network required. Writes to `./output/`.
 *
 * The WBC is ALWAYS produced so every default community install is protected by
 * the BIND→LINK→AUTHORIZE gate. The passthrough (no-WBC) path in runRuntimeAdapter
 * is reserved for deliberate enterprise callers who explicitly opt out — it is
 * never the default.
 *
 * @param {object} [opts]
 * @param {string} [opts.outputDir] - Output directory (default: ./output)
 * @param {string} [opts.agentLabel] - Label for the agent (default: agent)
 * @param {string[]} [opts.allowedRails] - Rails to permit (default: ethereum-mainnet + lightning)
 * @param {string} [opts.ceilingAmount] - Per-tx ceiling amount (default: 100)
 * @param {string} [opts.ceilCurrency] - Ceiling currency (default: USDT)
 * @returns {{ principalDid: string, agentDid: string, walletDid: string, mandateId: string }}
 */
export function generate (opts = {}) {
  const {
    outputDir = './output',
    agentLabel = 'agent',
    allowedRails = ['ethereum-mainnet', 'lightning'],
    ceilingAmount = '100',
    ceilCurrency = 'USDT'
  } = opts

  mkdirSync(outputDir, { recursive: true })

  // 1. Principal key (operator — store offline)
  const principalSeed = randomBytes(32)
  const principal = createDidKeyAgent(principalSeed, "m/observer-protocol'/principal/0/0/0")

  // 2. Agent identity key (agent user — carries no spend authority)
  const agentSeed = randomBytes(32)
  const agent = createDidKeyAgent(agentSeed, "m/observer-protocol'/agent/0/0/0")

  // 3. Wallet identity key (wallet-service user — the wallet the WBC binds to)
  // The wallet DID is derived deterministically from the wallet seed. The same seed
  // always produces the same wallet DID, so the WBC is stable across restarts.
  const walletSeed = randomBytes(32)
  const wallet = createDidKeyAgent(walletSeed, "m/observer-protocol'/wallet/0/0/0")

  // 4. Issue SpendMandate: principal → agent
  // Note: allowed_transaction_categories is NOT included. Its enforcement depends on
  // config.transactionCategory being set at runtime; in the default community install
  // that field is not provided, so including it would cause every transaction to DENY
  // silently (the category check fires fail-closed). The ceiling + rail constraints
  // are the enforceable guards. Category-gating is a full-mode feature that requires
  // runtime config to back it — never a silent no-op field in the manifest.
  const now = new Date()
  const validFrom = toISO(now)
  const validUntil = toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000))

  const mandate = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://observerprotocol.org/contexts/delegation/v1'
    ],
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    id: `urn:uuid:hermes-spend-mandate-${hex(randomBytes(8))}`,
    issuer: principal.did,
    validFrom,
    validUntil,
    credentialSchema: {
      id: DELEGATION_SCHEMA_V2_1,
      type: 'JsonSchema'
    },
    credentialSubject: {
      id: agent.did,
      authorizationLevel: 'recurring',
      authorizationConfig: {
        recurring: {
          ceiling_amount: ceilingAmount,
          ceiling_currency: ceilCurrency
        }
      },
      actionScope: {
        allowed_rails: allowedRails,
        per_transaction_ceiling: {
          amount: ceilingAmount,
          currency: ceilCurrency
        }
      }
    }
  }

  const signedMandate = signDocument(mandate, principal)

  // 5. Issue WalletBindingCredential: principal binds wallet.did to itself.
  //
  // The WBC is signed by the principal using eddsa-jcs-2022 (DataIntegrityProof),
  // which is the only proof suite accepted by policy-engine's verifyWbc.
  //
  // The LINK step (dev mode) checks: wbc.issuer === mandate.issuer.
  // Both are principal.did, so the LINK check passes for every default install.
  //
  // At runtime, ctx.wallet_id must equal wbc.credentialSubject.walletAddress
  // (the BIND address check). The wallet service uses wallet.did as its identifier
  // and passes it as ctx.wallet_id to the gate.
  const wbc = signEddsaJcs2022({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:hermes-wbc-${hex(randomBytes(8))}`,
    type: ['VerifiableCredential', 'WalletBindingCredential'],
    issuer: principal.did,
    validFrom,
    validUntil,
    credentialSubject: {
      id: principal.did,
      walletAddress: wallet.did,
      rail: allowedRails[0],
      issuanceMode: 'dev'
    }
  }, principal)

  // 6. Write output files
  writeFileSync(
    join(outputDir, 'principal-key.json'),
    JSON.stringify({
      _note: 'PRINCIPAL KEY — store offline, never on server',
      seed_hex: hex(principalSeed),
      did: principal.did,
      public_key_hex: hex(principal.publicKey)
    }, null, 2)
  )

  writeFileSync(
    join(outputDir, 'agent-identity-key.json'),
    JSON.stringify({
      _note: 'AGENT IDENTITY KEY — agent user only, mode 600',
      seed_hex: hex(agentSeed),
      did: agent.did,
      public_key_hex: hex(agent.publicKey),
      label: agentLabel
    }, null, 2)
  )

  writeFileSync(
    join(outputDir, 'wallet-seed.json'),
    JSON.stringify({
      _note: 'WALLET SEED — wallet-service user only, mode 600',
      seed_hex: hex(walletSeed)
    }, null, 2)
  )

  writeFileSync(
    join(outputDir, 'wallet-identity-key.json'),
    JSON.stringify({
      _note: 'WALLET IDENTITY KEY — wallet-service user only, mode 600',
      seed_hex: hex(walletSeed),
      did: wallet.did,
      public_key_hex: hex(wallet.publicKey)
    }, null, 2)
  )

  writeFileSync(
    join(outputDir, 'spend-mandate.json'),
    JSON.stringify(signedMandate, null, 2)
  )

  writeFileSync(
    join(outputDir, 'wbc.json'),
    JSON.stringify(wbc, null, 2)
  )

  console.log('Generated key material in', outputDir)
  console.log()
  console.log('  Principal DID:', principal.did)
  console.log('  Agent DID:    ', agent.did)
  console.log('  Wallet DID:   ', wallet.did)
  console.log('  Mandate ID:   ', signedMandate.id)
  console.log('  Valid:        ', validFrom, '→', validUntil)
  console.log()
  console.log('PLACEMENT INSTRUCTIONS:')
  console.log()
  console.log('  principal-key.json      → store OFFLINE (e.g. encrypted drive). Never on server.')
  console.log('  agent-identity-key.json → /home/<agent-user>/identity/did-key.json  (mode 600, chown <agent-user>)')
  console.log('  wallet-seed.json        → /home/<wallet-user>/secrets/wallet-seed.json  (mode 600, chown <wallet-user>)')
  console.log('  wallet-identity-key.json → /home/<wallet-user>/secrets/wallet-key.json  (mode 600, chown <wallet-user>)')
  console.log('  spend-mandate.json      → /home/<agent-user>/spend-mandate.json  (mode 644)')
  console.log('  wbc.json                → /home/<agent-user>/wbc.json  (mode 644)  [walletBindingCredentialPath in engine config]')
  console.log()
  console.log('Runtime engine config: set walletBindingCredentialPath = /home/<agent-user>/wbc.json')
  console.log('Run `hermes-gate bootstrap provision` to copy files to the correct locations.')

  return { principalDid: principal.did, agentDid: agent.did, walletDid: wallet.did, mandateId: signedMandate.id }
}

/**
 * Provision key material from ./output/ to the correct system paths.
 *
 * @param {{ agentUser: string, walletUser: string, outputDir?: string }} opts
 */
export function provision ({ agentUser, walletUser, outputDir = './output' }) {
  if (!agentUser || !walletUser) throw new Error('--agent-user and --wallet-user required')

  const agentHome = `/home/${agentUser}`
  const walletHome = `/home/${walletUser}`

  // Create directories
  execSync(`mkdir -p ${agentHome}/identity ${walletHome}/secrets`)

  // Copy files
  cpSync(join(outputDir, 'agent-identity-key.json'), `${agentHome}/identity/did-key.json`)
  cpSync(join(outputDir, 'wallet-seed.json'), `${walletHome}/secrets/wallet-seed.json`)
  cpSync(join(outputDir, 'wallet-identity-key.json'), `${walletHome}/secrets/wallet-key.json`)
  cpSync(join(outputDir, 'spend-mandate.json'), `${agentHome}/spend-mandate.json`)
  cpSync(join(outputDir, 'wbc.json'), `${agentHome}/wbc.json`)

  // Set permissions
  execSync(`chown -R ${agentUser}:${agentUser} ${agentHome}/identity ${agentHome}/spend-mandate.json ${agentHome}/wbc.json`)
  execSync(`chmod 600 ${agentHome}/identity/did-key.json`)
  execSync(`chmod 644 ${agentHome}/spend-mandate.json`)
  execSync(`chmod 644 ${agentHome}/wbc.json`)

  execSync(`chown -R ${walletUser}:${walletUser} ${walletHome}/secrets`)
  execSync(`chmod 700 ${walletHome}`)
  execSync(`chmod 700 ${walletHome}/secrets`)
  execSync(`chmod 600 ${walletHome}/secrets/wallet-seed.json`)
  execSync(`chmod 600 ${walletHome}/secrets/wallet-key.json`)

  console.log('Provisioned:')
  console.log(' ', `${agentHome}/identity/did-key.json  (600)`)
  console.log(' ', `${agentHome}/spend-mandate.json  (644)`)
  console.log(' ', `${agentHome}/wbc.json  (644)`)
  console.log(' ', `${walletHome}/secrets/wallet-seed.json  (600)`)
  console.log(' ', `${walletHome}/secrets/wallet-key.json  (600)`)
  console.log()
  console.log('Run `hermes-gate bootstrap verify` to confirm G1 boundary.')
}

/**
 * G1 boundary verification. Runs the three cross-boundary deny tests.
 * Exits non-zero if any boundary check passes (meaning it should have been denied).
 *
 * @param {{ agentUser: string, walletUser: string }} opts
 */
export function verify ({ agentUser, walletUser }) {
  if (!agentUser || !walletUser) throw new Error('--agent-user and --wallet-user required')

  const agentHome = `/home/${agentUser}`
  const walletHome = `/home/${walletUser}`

  const checks = [
    {
      label: `${agentUser} cannot read ${walletUser}'s wallet seed`,
      cmd: `sudo -u ${agentUser} cat ${walletHome}/secrets/wallet-seed.json`
    },
    {
      label: `${agentUser} cannot list ${walletUser}'s secrets dir`,
      cmd: `sudo -u ${agentUser} ls ${walletHome}/secrets/`
    },
    {
      label: `${walletUser} cannot read ${agentUser}'s identity key`,
      cmd: `sudo -u ${walletUser} cat ${agentHome}/identity/did-key.json`
    }
  ]

  let passed = 0
  let failed = 0

  for (const { label, cmd } of checks) {
    try {
      execSync(cmd, { stdio: 'pipe' })
      // If command succeeds, the boundary is BROKEN
      console.error(`FAIL [boundary broken]: ${label}`)
      failed++
    } catch {
      // Non-zero exit = access denied = boundary holds
      console.log(`PASS [access denied]:   ${label}`)
      passed++
    }
  }

  console.log()
  console.log(`G1 boundary: ${passed}/${checks.length} checks passed`)

  if (failed > 0) {
    console.error(`${failed} boundary check(s) failed — G1 boundary is NOT secure.`)
    process.exit(1)
  } else {
    console.log('G1 boundary verified.')
  }
}
