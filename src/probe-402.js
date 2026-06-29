// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate

'use strict'

import { request as httpsRequest } from 'node:https'
import { request as httpRequest } from 'node:http'

/**
 * Probe a URL expecting an HTTP 402 Payment Required response.
 * Parses amount and currency from WWW-Authenticate.
 *
 * Supported formats:
 *   MPP:  WWW-Authenticate: MPP amount="X", currency="Y"
 *   L402: WWW-Authenticate: L402 invoice="lnbc..."
 *
 * Returns {amount: null, currency: null} on non-402, timeout, or parse failure.
 * Never throws.
 *
 * @param {string} url
 * @returns {Promise<{amount: string|null, currency: string|null}>}
 */
export function probe402 (url) {
  return new Promise((resolve) => {
    let parsed
    try { parsed = new URL(url) } catch {
      resolve({ amount: null, currency: null })
      return
    }

    const lib = parsed.protocol === 'https:' ? httpsRequest : httpRequest
    const req = lib({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: (parsed.pathname || '/') + (parsed.search || ''),
      method: 'GET',
      headers: { 'User-Agent': 'hermes-gate/0.2.1 (spend-gate-probe)' },
      timeout: 5000
    }, (res) => {
      res.resume()
      if (res.statusCode === 402) {
        resolve(_parse402Headers(res.headers))
      } else {
        resolve({ amount: null, currency: null })
      }
    })

    req.on('error', () => resolve({ amount: null, currency: null }))
    req.on('timeout', () => { req.destroy(); resolve({ amount: null, currency: null }) })
    req.end()
  })
}

function _parse402Headers (headers) {
  const auth = headers['www-authenticate'] || ''

  // MPP: amount="X", currency="Y"
  const amountM = auth.match(/amount="?([0-9]+(?:\.[0-9]+)?)"?/)
  const currencyM = auth.match(/currency="?([A-Za-z]+)"?/)

  let amount = amountM ? amountM[1] : null
  let currency = currencyM ? currencyM[1] : null

  // L402: invoice="lnbc..."
  if (!amount) {
    const invoiceM = auth.match(/invoice="(lnb[a-z0-9]+)"/)
    if (invoiceM) {
      const decoded = _decodeBolt11Amount(invoiceM[1])
      amount = decoded.amount
      currency = decoded.currency
    }
  }

  return { amount, currency }
}

function _decodeBolt11Amount (invoice) {
  // lnbc<amount><multiplier>1... mainnet | lntb testnet | lnbcrt regtest
  const m = invoice.match(/^ln(?:bc|tb|bcrt)(\d+)([munp]?)1/)
  if (!m) return { amount: null, currency: null }

  const val = parseInt(m[1], 10)
  const mult = m[2]
  // sat multipliers: '' = 100M, m = 100k, u = 100, n = 0.1, p = 0.0001
  const multToSat = { '': 100_000_000, m: 100_000, u: 100, n: 0.1, p: 0.0001 }
  const factor = multToSat[mult] ?? 1
  const sats = Math.floor(val * factor)

  return sats > 0
    ? { amount: String(sats), currency: 'sat' }
    : { amount: null, currency: null }
}
