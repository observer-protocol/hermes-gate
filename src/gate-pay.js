// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { probe402 } from './probe-402.js'

const execFileAsync = promisify(execFile)

/**
 * Probe a 402-gated URL, evaluate against the spend mandate, and execute the
 * payment via mppx if approved. Implements a reserve/commit/release lifecycle
 * against the rolling 24h cap.
 *
 * Debit discipline:
 *   reserve   on evaluate  — counted immediately by sumWindow; prevents concurrent overspend
 *   commit    on confirmed mppx output (parsed successfully)
 *   release   if mppx execFile throws (exit non-zero or timeout); money did not move
 *   commit    if mppx exits 0 but output is unparseable; money likely moved;
 *             records at probed amount + reconciliation_needed flag. Never under-counts cap.
 *
 * @param {string} url  402-protected URL to pay
 * @param {{
 *   gate: import('./gate.js').SpendGate,
 *   mppxPath?: string,
 *   walletId?: string
 * }} opts
 * @returns {Promise<{
 *   allowed: boolean,
 *   amount: string|null,
 *   currency: string|null,
 *   rail: string|null,
 *   tx_ref: string|null,
 *   reasons: object[],
 *   advisories?: object[],
 *   reconciliation_required?: boolean
 * }>}
 */
export async function gatePay (url, { gate, mppxPath = 'mppx', walletId } = {}) {
  const fail = (reasons, extra = {}) => ({
    allowed: false,
    amount: null,
    currency: null,
    rail: null,
    tx_ref: null,
    reasons,
    advisories: [],
    ...extra
  })

  // Validate URL
  try { new URL(url) } catch {
    return fail([{ ruleType: 'gate_error', ruleField: 'url', message: 'Invalid URL' }])
  }

  // 1. Probe 402 — discover amount, currency, and resource preview from WWW-Authenticate + body
  const { amount, currency, resourcePreview } = await probe402(url)
  if (amount === null || currency === null) {
    return fail([{
      ruleType: 'probe_error',
      ruleField: 'www_authenticate',
      message:
        'Cannot determine amount/currency from 402 response. ' +
        'Payment service must return MPP amount= and currency= in WWW-Authenticate.'
    }], { rail: 'lightning' })
  }

  // 2. Evaluate against mandate and reserve against the rolling 24h cap
  const rail = 'lightning'
  const action = { rail, amount, currency, ...(walletId ? { wallet_id: walletId } : {}) }

  let evalResult
  try {
    evalResult = await gate.evaluateWithReserve(action)
  } catch (err) {
    return fail([{ ruleType: 'gate_error', ruleField: 'evaluate', message: err.message }],
      { amount, currency, rail })
  }

  if (!evalResult.allow) {
    return {
      allowed: false,
      amount,
      currency,
      rail,
      tx_ref: null,
      reasons: evalResult.reasons,
      advisories: evalResult.advisories || []
    }
  }

  const { reserveId, advisories = [], mandateValidUntil } = evalResult

  // 3. Execute mppx — the only point where money moves
  let stdout
  try {
    const result = await execFileAsync(mppxPath, [url], { timeout: 30_000 })
    stdout = result.stdout
  } catch (execErr) {
    // mppx failed (non-zero exit or timeout): money did not move; release the reserve
    gate.releaseReserve(reserveId)
    return {
      allowed: false,
      amount,
      currency,
      rail,
      tx_ref: null,
      reasons: [{ ruleType: 'payment_failed', ruleField: 'mppx', message: execErr.message }],
      advisories,
      mandateValidUntil
    }
  }

  // 4. Parse mppx confirmation output
  const parsed = _parseMppxOutput(stdout)

  if (parsed.success) {
    gate.commitReserve(reserveId)
    return {
      allowed: true,
      amount: parsed.amount || amount,
      currency,
      rail,
      tx_ref: parsed.txRef,
      reasons: [],
      advisories,
      mandateValidUntil,
      ...(resourcePreview != null ? { resource: resourcePreview } : {})
    }
  }

  // mppx exited 0 but output did not parse: money likely moved.
  // Record at probed amount + flag for reconciliation. Never under-count.
  gate.commitReserve(reserveId, { reconciliation_needed: true, note: 'mppx output did not parse' })
  return {
    allowed: true,
    amount,
    currency,
    rail,
    tx_ref: null,
    reconciliation_required: true,
    reasons: [],
    advisories,
    mandateValidUntil
  }
}

/**
 * Best-effort parser for mppx stdout.
 * success:false means "could not confirm" — triggers the reconciliation path.
 */
function _parseMppxOutput (stdout) {
  const text = (stdout || '').trim()

  // JSON first
  try {
    const j = JSON.parse(text)
    if (j.payment_hash || j.hash || j.preimage || j.status === 'paid' || j.paid === true) {
      return {
        success: true,
        txRef: j.payment_hash || j.hash || j.preimage || null,
        amount: j.amount != null ? String(j.amount) : null
      }
    }
  } catch {}

  // 64-char hex payment hash
  const hashMatch = text.match(/\b([0-9a-fA-F]{64})\b/)
  if (hashMatch) return { success: true, txRef: hashMatch[1], amount: null }

  // Keyword fallback
  if (/\b(paid|success|confirmed|complete)\b/i.test(text)) {
    return { success: true, txRef: null, amount: null }
  }

  return { success: false, txRef: null, amount: null }
}
