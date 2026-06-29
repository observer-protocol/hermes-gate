// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, renameSync } from 'node:fs'
import { dirname } from 'node:path'

const WINDOW_MS = 24 * 60 * 60 * 1000       // 24h rolling window
const PRUNE_AFTER_MS = 25 * 60 * 60 * 1000   // prune entries older than this
const RESERVE_TTL_MS = 5 * 60 * 1000         // abandoned reservation TTL

/**
 * Append-only JSONL spend ledger for rolling 24h cumulative cap enforcement.
 *
 * Entries carry a `state` field: 'committed' (permanent) or 'reserved' (pending).
 * Legacy entries without `state` are treated as committed for backward compat.
 * Both states count against sumWindow, preventing concurrent evaluate calls from
 * each passing the same remaining headroom. Reservations expire after 5 minutes
 * so an abandoned reserve (gate crash between evaluate and payment) cannot block
 * the cap indefinitely.
 *
 * Lifecycle:
 *   record()   — immediate committed write (interceptor path)
 *   reserve()  — reserved write, counted by sumWindow; returns reserveId
 *   commit()   — converts reserved → committed (call on confirmed payment)
 *   release()  — removes reserved entry (call if payment failed; cap restored)
 *
 * Security boundary: the ledger secures against the malicious-skill threat
 * (lite tier). A malicious skill can only call gate_evaluate; it cannot reach
 * the filesystem. A fully-compromised gate process that deletes the ledger
 * resets the cap — that is the binding-tier threat, out of scope for lite.
 *
 * The ledger file must be:
 *   - Mode 600, owned by the gate process user (agent-user side of G1 boundary)
 *   - Not readable by the wallet-service user
 */
export class SpendLedger {
  /**
   * @param {string} path - Absolute path to the .jsonl ledger file
   */
  constructor (path) {
    if (!path || typeof path !== 'string') throw new Error('SpendLedger: path required')
    this._path = path
    mkdirSync(dirname(path), { recursive: true })
    if (!existsSync(path)) {
      writeFileSync(path, '', { encoding: 'utf8', mode: 0o600 })
    }
  }

  /**
   * Record an authorized spend as committed immediately.
   * Used by the interceptor path (gate.evaluate) where the CLI executes after.
   * @param {{ rail: string, amount: string, currency: string }} entry
   */
  record ({ rail, amount, currency }) {
    const line = JSON.stringify({ ts: Date.now(), rail, amount, currency, state: 'committed' })
    appendFileSync(this._path, line + '\n', { encoding: 'utf8' })
  }

  /**
   * Reserve capacity against the rolling cap without committing.
   * Counted by sumWindow immediately. Call commit() on confirmed payment,
   * or release() if the payment failed.
   *
   * Reservations expire after RESERVE_TTL_MS (5 min) — an abandoned reservation
   * (e.g. gate crash) will eventually fall out of sumWindow and prune().
   *
   * @param {{ rail: string, amount: string, currency: string }} entry
   * @returns {string} reserveId — pass to commit() or release()
   */
  reserve ({ rail, amount, currency }) {
    const reserveId = Date.now().toString(36) + Math.random().toString(36).slice(2)
    const expiresAt = Date.now() + RESERVE_TTL_MS
    const line = JSON.stringify({ ts: Date.now(), rail, amount, currency, state: 'reserved', reserveId, expiresAt })
    appendFileSync(this._path, line + '\n', { encoding: 'utf8' })
    return reserveId
  }

  /**
   * Convert a reservation to a committed entry.
   * Safe to call with a null reserveId (no-op) for the no-cap-configured path.
   *
   * @param {string|null} reserveId
   * @param {object} [meta]  optional extra fields merged into the committed entry
   *                         (e.g. { reconciliation_needed: true })
   */
  commit (reserveId, meta = {}) {
    if (!reserveId) return
    this._rewriteWhere(
      e => e.reserveId === reserveId && e.state === 'reserved',
      e => {
        const { expiresAt: _exp, reserveId: _id, state: _s, ...rest } = e
        return { ...rest, state: 'committed', ...meta }
      }
    )
  }

  /**
   * Remove a reservation, restoring the cap headroom.
   * Use when the payment failed (mppx exited non-zero or timed out).
   * Safe to call with a null reserveId (no-op).
   *
   * @param {string|null} reserveId
   */
  release (reserveId) {
    if (!reserveId) return
    this._rewriteWhere(
      e => e.reserveId === reserveId && e.state === 'reserved',
      () => null  // null = drop the line
    )
  }

  /**
   * Sum authorized spends in the last 24h for a given rail+currency pair.
   * Counts committed entries (including legacy entries without state) and
   * non-expired reservations.
   *
   * @param {string} rail
   * @param {string} currency
   * @returns {number}
   */
  sumWindow (rail, currency) {
    const cutoff = Date.now() - WINDOW_MS
    const now = Date.now()
    let total = 0
    try {
      const lines = readFileSync(this._path, 'utf8').split('\n')
      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const e = JSON.parse(line)
          if (e.ts < cutoff) continue
          if (e.rail !== rail || e.currency !== currency) continue
          // Unknown state guard (future-compat): skip unrecognized states
          if (e.state && e.state !== 'committed' && e.state !== 'reserved') continue
          // Skip expired reservations
          if (e.state === 'reserved' && e.expiresAt && e.expiresAt < now) continue
          total += parseFloat(e.amount) || 0
        } catch {
          // malformed line — skip
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
    }
    return total
  }

  /**
   * Prune entries older than 25h and expired reservations.
   * Atomic rewrite via temp file + rename. Safe to call at startup.
   */
  prune () {
    const cutoff = Date.now() - PRUNE_AFTER_MS
    const now = Date.now()
    try {
      const lines = readFileSync(this._path, 'utf8').split('\n')
      const kept = []
      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const e = JSON.parse(line)
          if (e.ts < cutoff) continue
          if (e.state === 'reserved' && e.expiresAt && e.expiresAt < now) continue
          kept.push(line)
        } catch {
          // drop malformed lines on prune
        }
      }
      const tmp = this._path + '.tmp'
      writeFileSync(tmp, kept.join('\n') + (kept.length ? '\n' : ''), { encoding: 'utf8', mode: 0o600 })
      renameSync(tmp, this._path)
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
    }
  }

  /**
   * Read all lines, apply predicate+transform, atomic rewrite.
   * transform() returns the replacement object, or null to drop the line.
   */
  _rewriteWhere (predicate, transform) {
    let raw
    try { raw = readFileSync(this._path, 'utf8') } catch (err) {
      if (err.code === 'ENOENT') return
      throw err
    }
    const updated = []
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue
      try {
        const e = JSON.parse(line)
        if (predicate(e)) {
          const replacement = transform(e)
          if (replacement !== null) updated.push(JSON.stringify(replacement))
        } else {
          updated.push(line)
        }
      } catch {
        updated.push(line)
      }
    }
    const tmp = this._path + '.tmp'
    writeFileSync(tmp, updated.join('\n') + (updated.length ? '\n' : ''), { encoding: 'utf8', mode: 0o600 })
    renameSync(tmp, this._path)
  }
}
