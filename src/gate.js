// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync } from 'node:fs'
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
   * @param {import('./spend-ledger.js').SpendLedger} [opts.spendLedger] - Ledger for rolling 24h cap; required when mandate declares cumulative_budget
   */
  constructor ({ mandatePath, agentDid, trustedIssuers, walletBindingCredentialPath, issuanceMode, spendLedger }) {
    if (!mandatePath || typeof mandatePath !== 'string') throw new GateError('CONFIG', 'mandatePath required')
    if (!agentDid || typeof agentDid !== 'string') throw new GateError('CONFIG', 'agentDid required')
    this._config = {
      mandatePath,
      agentDid,
      trustedIssuers: trustedIssuers || [],
      walletBindingCredentialPath,
      issuanceMode
    }
    this._spendLedger = spendLedger || null
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
    // Read cumulative_budget from mandate before calling runRuntimeAdapter so
    // we have cap metadata ready if allow:true. Re-read matches runRuntimeAdapter's
    // own re-read on every call, picking up key rotation without a gate restart.
    let dailyCap = null
    if (this._spendLedger) {
      try {
        const raw = JSON.parse(readFileSync(this._config.mandatePath, 'utf8'))
        const budget = raw.credentialSubject?.actionScope?.cumulative_budget
        if (budget?.amount && budget?.currency) {
          dailyCap = { amount: parseFloat(budget.amount), currency: budget.currency }
        }
      } catch {
        // mandate read failure is surfaced below by runRuntimeAdapter
      }
    }

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

    // Cumulative cap enforcement — runs after the full BIND→LINK→AUTHORIZE gate
    // passes. The check lives here (stateful orchestration layer), not inside
    // withinScope, preserving withinScope's I/O-free evaluator invariant.
    if (result.allow && this._spendLedger && dailyCap && dailyCap.currency === action.currency) {
      const windowSum = this._spendLedger.sumWindow(action.rail, action.currency)
      const proposed = parseFloat(action.amount)
      if (windowSum + proposed > dailyCap.amount) {
        return {
          allow: false,
          reasons: [{
            ruleType: 'cumulativeCap',
            ruleField: 'cumulative_budget',
            message: `Rolling 24h cap exceeded: ${windowSum.toFixed(2)} + ${proposed} > ${dailyCap.amount} ${dailyCap.currency} on rail ${action.rail}`
          }],
          advisories: result.advisories,
          mandateValidUntil: result.mandateValidUntil
        }
      }
      this._spendLedger.record({ rail: action.rail, amount: action.amount, currency: action.currency })
    }

    return {
      allow: result.allow,
      reasons: result.reasons,
      advisories: result.advisories,
      mandateValidUntil: result.mandateValidUntil
    }
  }
}
