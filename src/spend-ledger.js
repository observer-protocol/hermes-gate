// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, renameSync } from 'node:fs'
import { dirname } from 'node:path'

const WINDOW_MS = 24 * 60 * 60 * 1000       // 24h rolling window
const PRUNE_AFTER_MS = 25 * 60 * 60 * 1000   // prune entries older than this

/**
 * Append-only JSONL spend ledger for rolling 24h cumulative cap enforcement.
 *
 * Written on each authorized spend — when the full BIND→LINK→AUTHORIZE gate
 * returns allow:true. Single writer (one gate process); no concurrent access.
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
   * Record an authorized spend. Call when the full gate returns allow:true.
   * @param {{ rail: string, amount: string, currency: string }} entry
   */
  record ({ rail, amount, currency }) {
    const line = JSON.stringify({ ts: Date.now(), rail, amount, currency })
    appendFileSync(this._path, line + '\n', { encoding: 'utf8' })
  }

  /**
   * Sum authorized spends in the last 24h for a given rail+currency pair.
   * Rolling window: entries where ts >= (now - 24h). Timezone-agnostic.
   * @param {string} rail
   * @param {string} currency
   * @returns {number}
   */
  sumWindow (rail, currency) {
    const cutoff = Date.now() - WINDOW_MS
    let total = 0
    try {
      const lines = readFileSync(this._path, 'utf8').split('\n')
      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const e = JSON.parse(line)
          if (e.ts >= cutoff && e.rail === rail && e.currency === currency) {
            total += parseFloat(e.amount) || 0
          }
        } catch {
          // malformed line — skip
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
      // file not found = no prior spends; return 0
    }
    return total
  }

  /**
   * Prune entries older than 25h. Atomic rewrite via temp file + rename.
   * Safe to call at startup to bound file growth across restarts.
   */
  prune () {
    const cutoff = Date.now() - PRUNE_AFTER_MS
    try {
      const lines = readFileSync(this._path, 'utf8').split('\n')
      const kept = []
      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const e = JSON.parse(line)
          if (e.ts >= cutoff) kept.push(line)
        } catch {
          // drop malformed lines on prune
        }
      }
      const tmp = this._path + '.tmp'
      writeFileSync(tmp, kept.join('\n') + (kept.length ? '\n' : ''), { encoding: 'utf8', mode: 0o600 })
      renameSync(tmp, this._path)
    } catch (err) {
      if (err.code !== 'ENOENT') throw err
      // file doesn't exist yet — nothing to prune
    }
  }
}
