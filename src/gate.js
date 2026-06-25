// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { runRuntimeAdapter } from '@observer-protocol/wdk-protocol-trust'

export class GateError extends Error {
  constructor (code, detail) {
    super(detail || code)
    this.code = code
  }
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
   * @param {string} opts.mandatePath                  - Path to the signed spend-mandate.json (644)
   * @param {string} opts.agentDid                     - The agent's did:key (public)
   * @param {string[]} [opts.trustedIssuers]           - Issuer DIDs the gate trusts
   * @param {string} [opts.walletBindingCredentialPath] - Path to wbc.json; when set, enforces BIND+LINK
   * @param {'dev'|'full'} [opts.issuanceMode]         - Governs LINK check; defaults to 'dev'
   */
  constructor ({ mandatePath, agentDid, trustedIssuers, walletBindingCredentialPath, issuanceMode }) {
    if (!mandatePath || typeof mandatePath !== 'string') throw new GateError('CONFIG', 'mandatePath required')
    if (!agentDid || typeof agentDid !== 'string') throw new GateError('CONFIG', 'agentDid required')
    this._config = {
      mandatePath,
      agentDid,
      trustedIssuers: trustedIssuers || [],
      walletBindingCredentialPath,
      issuanceMode
    }
  }

  /**
   * Evaluate a proposed spend action. Re-reads and re-verifies the mandate on
   * every call. Optionally enforces BIND+LINK when walletBindingCredentialPath
   * is configured.
   *
   * @param {{
   *   rail: string,
   *   amount: string,
   *   currency: string,
   *   category?: string,
   *   wallet_id?: string
   * }} action - Flat MCP surface. wallet_id is the signing wallet DID/address;
   *   required only when BIND address verification is desired.
   * @returns {Promise<{ allow: boolean, reasons: object[], advisories: object[], mandateValidUntil: string }>}
   */
  async evaluate (action) {
    const result = await runRuntimeAdapter(action, this._config)
    // Surface GateError on gate-internal failures so callers can distinguish
    // mandate/config issues from policy denials.
    if (!result.allow && result.reasons.some(r => r.ruleField === 'mandate_read')) {
      throw new GateError('MANDATE_READ', result.reasons[0].message)
    }
    if (!result.allow && result.reasons.some(r => r.ruleField === 'mandate_invalid')) {
      throw new GateError('MANDATE_INVALID', result.reasons[0].message)
    }
    if (!result.allow && result.reasons.some(r => r.ruleField === 'self_signed_mandate')) {
      throw new GateError('SELF_SIGNED_MANDATE', result.reasons[0].message)
    }
    if (!result.allow && result.reasons.some(r => r.ruleField === 'subject_mismatch')) {
      throw new GateError('SUBJECT_MISMATCH', result.reasons[0].message)
    }
    if (!result.allow && result.reasons.some(r => r.ruleField === 'untrusted_issuer')) {
      throw new GateError('UNTRUSTED_ISSUER', result.reasons[0].message)
    }
    return {
      allow: result.allow,
      reasons: result.reasons,
      advisories: result.advisories,
      mandateValidUntil: result.mandateValidUntil
    }
  }
}
