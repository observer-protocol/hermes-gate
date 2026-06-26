// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { randomBytes } from 'node:crypto'
import { writeFileSync, mkdirSync, cpSync, chmodSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import {
  createDidKeyAgent,
  signDocument,
  DELEGATION_SCHEMA_V2_1,
  BOOTSTRAP_PATH_PRINCIPAL,
  BOOTSTRAP_PATH_AGENT,
  BOOTSTRAP_PATH_WALLET
} from '@observer-protocol/wdk-protocol-trust'

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function toISO (d) {
  return d.toISOString().replace(/\.\d+Z$/, 'Z')
}

/**
 * Generate all key material, a signed SpendMandate, and a WalletBindingCredential
 * locally. No network required. Writes to `./output/`.
 *
 * The WBC is ALWAYS produced so every default community install is protected by
 * the BIND→LINK→AUTHORIZE gate. The passthrough (no-WBC) path in runRuntimeAdapter
 * is reserved for deliberate enterprise callers who explicitly opt out — it is
 * never the community default.
 *
 * Both credentials are signed with DataIntegrityProof / eddsa-jcs-2022 via
 * signDocument(), which is the only proof suite accepted by the policy engine.
 *
 * @param {object} [opts]
 * @param {string} [opts.outputDir] - Output directory (default: ./output)
 * @param {string} [opts.agentLabel] - Label for the agent (default: agent)
 * @param {string[]} [opts.allowedRails] - Rails to permit (default: ethereum-mainnet + lightning)
 * @param {string} [opts.ceilingAmount] - Per-tx ceiling amount (default: 100)
 * @param {string} [opts.ceilCurrency] - Ceiling currency (default: USDT)
 * @param {string} [opts.dailyCapAmount] - Rolling 24h cumulative cap; if set, adds cumulative_budget to mandate
 * @param {string} [opts.dailyCapCurrency] - Currency for daily cap (defaults to ceilCurrency)
 * @returns {{ principalDid: string, agentDid: string, walletDid: string, mandateId: string }}
 */
export function generate (opts = {}) {
  const {
    outputDir = './output',
    agentLabel = 'agent',
    allowedRails = ['ethereum-mainnet', 'lightning'],
    ceilingAmount = '100',
    ceilCurrency = 'USDT',
    dailyCapAmount = null,
    dailyCapCurrency = null
  } = opts

  mkdirSync(outputDir, { recursive: true })

  // 1. Principal key (operator — store offline)
  const principalSeed = randomBytes(32)
  const principal = createDidKeyAgent(principalSeed, BOOTSTRAP_PATH_PRINCIPAL)

  // 2. Agent identity key (agent user — carries no spend authority)
  const agentSeed = randomBytes(32)
  const agent = createDidKeyAgent(agentSeed, BOOTSTRAP_PATH_AGENT)

  // 3. Wallet identity key (wallet-service user — the wallet the WBC binds to)
  // BOOTSTRAP_PATH_WALLET is the canonical path. The WBC binds the DID derived
  // from this path; if wallet-service derives its DID with a different path, the
  // BIND step DENYs every call. Both sides must import this constant.
  const walletSeed = randomBytes(32)
  const wallet = createDidKeyAgent(walletSeed, BOOTSTRAP_PATH_WALLET)

  const now = new Date()
  const validFrom = toISO(now)
  const validUntil = toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000))

  // 4. Issue SpendMandate: principal → agent
  //
  // allowed_transaction_categories is NOT included. Its enforcement depends on
  // config.transactionCategory being set at runtime; in the default community
  // install that field is not provided, so including it would silently DENY
  // every transaction (category check fires fail-closed). The ceiling + rail
  // constraints are the enforceable guards. Category-gating requires runtime
  // config to back it.
  const mandate = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
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
        ...(dailyCapAmount ? {
          cumulative_budget: {
            amount: dailyCapAmount,
            currency: dailyCapCurrency || ceilCurrency,
            period: '24h'
          }
        } : {})
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    }
  }

  const signedMandate = signDocument(mandate, principal)

  // 5. Issue WalletBindingCredential: principal binds wallet.did to itself.
  //
  // The LINK step (dev mode) checks: wbc.issuer === mandate.issuer.
  // Both are principal.did, so the LINK check passes for every default install.
  //
  // At runtime, ctx.wallet_id must equal wbc.credentialSubject.walletAddress
  // (the BIND address check). The wallet service uses wallet.did as its
  // identifier and passes it as ctx.wallet_id to the gate.
  const wbc = signDocument({
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
  const principalKeyPath = join(outputDir, 'principal-key.json')
  writeFileSync(principalKeyPath, JSON.stringify({
    _note: 'PRINCIPAL KEY — store offline, never on server',
    seed_hex: hex(principalSeed),
    did: principal.did,
    public_key_hex: hex(principal.publicKey)
  }, null, 2))
  chmodSync(principalKeyPath, 0o600)

  const agentKeyPath = join(outputDir, 'agent-identity-key.json')
  writeFileSync(agentKeyPath, JSON.stringify({
    _note: 'AGENT IDENTITY KEY — agent user only, mode 600',
    seed_hex: hex(agentSeed),
    did: agent.did,
    public_key_hex: hex(agent.publicKey),
    label: agentLabel
  }, null, 2))
  chmodSync(agentKeyPath, 0o600)

  const walletSeedPath = join(outputDir, 'wallet-seed.json')
  writeFileSync(walletSeedPath, JSON.stringify({
    _note: 'WALLET SEED — wallet-service user only, mode 600',
    seed_hex: hex(walletSeed)
  }, null, 2))
  chmodSync(walletSeedPath, 0o600)

  const walletKeyPath = join(outputDir, 'wallet-identity-key.json')
  writeFileSync(walletKeyPath, JSON.stringify({
    _note: 'WALLET IDENTITY KEY — wallet-service user only, mode 600',
    seed_hex: hex(walletSeed),
    did: wallet.did,
    public_key_hex: hex(wallet.publicKey)
  }, null, 2))
  chmodSync(walletKeyPath, 0o600)

  writeFileSync(join(outputDir, 'spend-mandate.json'), JSON.stringify(signedMandate, null, 2))
  writeFileSync(join(outputDir, 'wbc.json'), JSON.stringify(wbc, null, 2))

  console.log('Generated key material in', outputDir)
  console.log()
  console.log('  Principal DID:', principal.did)
  console.log('  Agent DID:    ', agent.did)
  console.log('  Wallet DID:   ', wallet.did)
  console.log('  Mandate ID:   ', signedMandate.id)
  console.log('  Valid:        ', validFrom, '→', validUntil)
  if (dailyCapAmount) {
    console.log('  Daily cap:    ', dailyCapAmount, (dailyCapCurrency || ceilCurrency), '/ 24h rolling window (enforced via ledger)')
  }
  console.log()
  console.log('PLACEMENT INSTRUCTIONS:')
  console.log()
  console.log('  principal-key.json       → store OFFLINE (e.g. encrypted drive). Never on server.')
  console.log('  agent-identity-key.json  → /home/<agent-user>/identity/did-key.json  (mode 600, chown <agent-user>)')
  console.log('  wallet-seed.json         → /home/<wallet-user>/secrets/wallet-seed.json  (mode 600, chown <wallet-user>)')
  console.log('  wallet-identity-key.json → /home/<wallet-user>/secrets/wallet-key.json  (mode 600, chown <wallet-user>)')
  console.log('  spend-mandate.json       → /home/<agent-user>/spend-mandate.json  (mode 644)')
  console.log('  wbc.json                 → /home/<agent-user>/wbc.json  (mode 644)')
  console.log()
  console.log('START THE GATE:')
  console.log()
  console.log('  HERMES_MANDATE_PATH=/home/<agent-user>/spend-mandate.json \\')
  console.log('  HERMES_AGENT_DID=' + agent.did + ' \\')
  console.log('  node /path/to/hermes-gate/src/mcp-server.js')
  console.log()
  console.log('  WBC auto-discovery: the gate looks for wbc.json in the same directory as the mandate.')
  console.log('  No HERMES_WBC_PATH needed when wbc.json is placed alongside spend-mandate.json.')
  console.log('  Set HERMES_WBC_PATH explicitly to load wbc.json from a different path.')
  console.log()
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

  execSync(`mkdir -p ${agentHome}/identity ${walletHome}/secrets`)

  cpSync(join(outputDir, 'agent-identity-key.json'), `${agentHome}/identity/did-key.json`)
  cpSync(join(outputDir, 'wallet-seed.json'), `${walletHome}/secrets/wallet-seed.json`)
  cpSync(join(outputDir, 'wallet-identity-key.json'), `${walletHome}/secrets/wallet-key.json`)
  cpSync(join(outputDir, 'spend-mandate.json'), `${agentHome}/spend-mandate.json`)
  cpSync(join(outputDir, 'wbc.json'), `${agentHome}/wbc.json`)

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
      console.error(`FAIL [boundary broken]: ${label}`)
      failed++
    } catch (e) {
      const out = ((e.stderr || '') + (e.stdout || '')).toString()
      if (/[Pp]ermission denied|cannot open|[Nn]o such file/.test(out)) {
        console.log(`PASS [access denied]:   ${label}`)
        passed++
      } else if (/sudo:/.test(out)) {
        console.error(`INCONCLUSIVE [sudo not configured]: ${label}`)
        console.error('  Run as root or configure passwordless sudo for this user')
        failed++
      } else {
        console.error(`INCONCLUSIVE [unexpected error]: ${label}`)
        console.error(`  ${out.trim().split('\n')[0] || '(no stderr)'}`)
        failed++
      }
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
