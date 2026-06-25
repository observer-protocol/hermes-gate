// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync } from 'node:fs'
import {
  withinScope,
  verifyMandate,
  buildDidKeyDocument
} from '@observer-protocol/wdk-protocol-trust'

export class GateError extends Error {
  constructor (code, detail) {
    super(detail || code)
    this.code = code
  }
}

/**
 * Resolve a did:key by deriving its DID document from the multibase fragment.
 * No network calls required — the public key is encoded in the DID itself.
 *
 * @param {string} did
 * @returns {Promise<object>}
 */
async function resolveDidKey (did) {
  if (!did.startsWith('did:key:')) {
    throw new GateError('DID_METHOD_UNSUPPORTED', `Expected did:key, got: ${did}`)
  }
  const multibase = did.slice('did:key:'.length)
  return buildDidKeyDocument(did, multibase)
}

/**
 * Fail-closed spend gate backed by a signed SpendMandate.
 *
 * Instantiated by the wallet-service user (atlas-wallet). Holds no wallet seed.
 *
 * Every evaluate() call re-reads and re-verifies the mandate from disk.
 * Mandate integrity comes from the DataIntegrityProof / eddsa-jcs-2022 Ed25519
 * proof, not filesystem secrecy (the file is 644). Re-verification catches key
 * rotation on the issuer side without a gate restart.
 *
 * COMMUNITY GATE SECURITY CAVEAT — action-input is agent-stated intent, not
 * decoded on-chain bytes. A skill that declares amount: 5 but builds a
 * transaction for 500 is caught by the enterprise RuntimeAdapter (which decodes
 * actual on-chain bytes via ResolvedTransfer) and NOT by this gate. This is the
 * headline v1 limitation: SpendGate enforces against what the agent declares,
 * not what the transaction executes. The enterprise path (wdk-op-policy +
 * runRuntimeAdapter) closes this gap via ProposalBinding.
 */
export class SpendGate {
  /**
   * @param {object} opts
   * @param {string} opts.mandatePath     - Path to the signed spend-mandate.json (644)
   * @param {string} opts.agentDid        - The agent's did:key (public)
   * @param {string[]} [opts.trustedIssuers] - Issuer DIDs the gate trusts
   */
  constructor ({ mandatePath, agentDid, trustedIssuers }) {
    if (!mandatePath || typeof mandatePath !== 'string') throw new GateError('CONFIG', 'mandatePath required')
    if (!agentDid || typeof agentDid !== 'string') throw new GateError('CONFIG', 'agentDid required')
    this.mandatePath = mandatePath
    this.agentDid = agentDid
    this.trustedIssuers = trustedIssuers || []
  }

  /**
   * Evaluate a proposed spend action. Re-reads and re-verifies the mandate
   * on every call.
   *
   * @param {{ rail: string, amount: string, currency: string, category?: string, note?: string }} action
   *   Flat MCP surface — amount is a decimal string, currency is ISO/token symbol.
   * @returns {Promise<{ allow: boolean, reasons: object[], advisories: object[], mandateValidUntil: string }>}
   */
  async evaluate (action) {
    const raw = this._readMandate()
    const mandate = await this._verifyMandate(raw)
    this._assertSignerBoundary(mandate)

    // withinScope expects action.amount as { amount, currency }
    const scopeAction = {
      rail: action.rail,
      amount: { amount: action.amount, currency: action.currency },
      ...(action.category ? { category: action.category } : {})
    }

    const result = withinScope(scopeAction, mandate)
    return {
      allow: result.allow,
      reasons: result.reasons || [],
      advisories: result.advisories || [],
      mandateValidUntil: mandate.validUntil || ''
    }
  }

  // ── private ──────────────────────────────────────────────────────────────

  _readMandate () {
    try {
      return JSON.parse(readFileSync(this.mandatePath, 'utf8'))
    } catch (err) {
      throw new GateError('MANDATE_READ', `Cannot read mandate: ${err.message}`)
    }
  }

  _assertSignerBoundary (mandate) {
    // Extract the signing DID from the cryptographically-verified proof, not
    // the raw issuer field. This ensures the check is on the key that actually
    // signed, not a potentially spoofed issuer claim.
    const vm = mandate.raw?.proof?.verificationMethod ?? ''
    const signingDid = vm.includes('#') ? vm.split('#')[0] : vm

    if (signingDid === this.agentDid) {
      throw new GateError('SELF_SIGNED_MANDATE', 'Mandate signing key belongs to agent DID — self-authorization denied')
    }
    if (mandate.subjectDid !== this.agentDid) {
      throw new GateError('SUBJECT_MISMATCH', `Mandate subject ${mandate.subjectDid} does not match agent DID ${this.agentDid}`)
    }
    // Belt-and-suspenders: verifyMandate already checked raw.issuer; this
    // confirms the verified signing DID is also in the trusted set.
    if (this.trustedIssuers.length > 0 && !this.trustedIssuers.includes(signingDid)) {
      throw new GateError('UNTRUSTED_ISSUER', `Signing DID ${signingDid} is not in the trusted-issuer set`)
    }
  }

  async _verifyMandate (raw) {
    // Use a custom resolver that handles both did:key (dev-mode) and did:web (prod)
    const resolveDid = raw.issuer?.startsWith?.('did:key:')
      ? resolveDidKey
      : undefined  // falls back to resolveDidWeb

    try {
      return await verifyMandate(raw, {
        trustedIssuers: this.trustedIssuers.length > 0 ? this.trustedIssuers : [raw.issuer],
        resolveDid
      })
    } catch (err) {
      throw new GateError('MANDATE_INVALID', err.message)
    }
  }
}
