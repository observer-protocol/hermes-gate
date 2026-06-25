// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, chownSync, chmodSync, cpSync } from 'node:fs'
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

/**
 * Generate all key material and a signed SpendMandate locally.
 * No network required. Writes to `./output/`.
 *
 * @param {object} [opts]
 * @param {string} [opts.outputDir] - Output directory (default: ./output)
 * @param {string} [opts.agentLabel] - Label for the agent (default: agent)
 * @param {string[]} [opts.allowedRails] - Rails to permit (default: ethereum-mainnet + lightning)
 * @param {string} [opts.ceilingAmount] - Per-tx ceiling amount (default: 100)
 * @param {string} [opts.ceilCurrency] - Ceiling currency (default: USDT)
 * @returns {{ principalDid: string, agentDid: string, mandateId: string }}
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

  // 3. Wallet seed (wallet-service user — never passed to createDidKeyAgent)
  const walletSeed = randomBytes(32)

  // 4. Issue SpendMandate: principal → agent
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
        },
        allowed_transaction_categories: ['payment']
      }
    }
  }

  const signedMandate = signDocument(mandate, principal)

  // 5. Write output files
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
    join(outputDir, 'spend-mandate.json'),
    JSON.stringify(signedMandate, null, 2)
  )

  console.log('Generated key material in', outputDir)
  console.log()
  console.log('  Principal DID:', principal.did)
  console.log('  Agent DID:    ', agent.did)
  console.log('  Mandate ID:   ', signedMandate.id)
  console.log('  Valid:        ', validFrom, '→', validUntil)
  console.log()
  console.log('PLACEMENT INSTRUCTIONS:')
  console.log()
  console.log('  principal-key.json   → store OFFLINE (e.g. encrypted drive). Never on server.')
  console.log('  agent-identity-key.json → /home/<agent-user>/identity/did-key.json  (mode 600, chown <agent-user>)')
  console.log('  wallet-seed.json     → /home/<wallet-user>/secrets/wallet-seed.json  (mode 600, chown <wallet-user>)')
  console.log('  spend-mandate.json   → /home/<agent-user>/spend-mandate.json  (mode 644)')
  console.log()
  console.log('Run `hermes-gate bootstrap provision` to copy files to the correct locations.')

  return { principalDid: principal.did, agentDid: agent.did, mandateId: signedMandate.id }
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
  cpSync(join(outputDir, 'spend-mandate.json'), `${agentHome}/spend-mandate.json`)

  // Set permissions
  execSync(`chown -R ${agentUser}:${agentUser} ${agentHome}/identity ${agentHome}/spend-mandate.json`)
  execSync(`chmod 600 ${agentHome}/identity/did-key.json`)
  execSync(`chmod 644 ${agentHome}/spend-mandate.json`)

  execSync(`chown -R ${walletUser}:${walletUser} ${walletHome}/secrets`)
  execSync(`chmod 700 ${walletHome}`)
  execSync(`chmod 700 ${walletHome}/secrets`)
  execSync(`chmod 600 ${walletHome}/secrets/wallet-seed.json`)

  console.log('Provisioned:')
  console.log(' ', `${agentHome}/identity/did-key.json  (600)`)
  console.log(' ', `${agentHome}/spend-mandate.json  (644)`)
  console.log(' ', `${walletHome}/secrets/wallet-seed.json  (600)`)
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
