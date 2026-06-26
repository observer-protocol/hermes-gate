#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

'use strict'

import { generate, provision, verify } from '../src/bootstrap.js'

const [,, cmd, sub, ...rest] = process.argv

function parseFlags (args) {
  const flags = {}
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())
      flags[key] = args[i + 1] && !args[i + 1].startsWith('--') ? args[++i] : true
    }
  }
  return flags
}

if (cmd !== 'bootstrap') {
  console.error('Usage: hermes-gate bootstrap <generate|provision|verify> [flags]')
  process.exit(1)
}

const flags = parseFlags(rest)

switch (sub) {
  case 'generate':
    generate({
      outputDir: flags.outputDir || './output',
      agentLabel: flags.agentLabel,
      allowedRails: flags.allowedRails ? flags.allowedRails.split(',') : undefined,
      ceilingAmount: flags.ceilingAmount,
      ceilCurrency: flags.ceilCurrency,
      dailyCapAmount: flags.dailyCapAmount,
      dailyCapCurrency: flags.dailyCapCurrency
    })
    break

  case 'provision':
    provision({
      agentUser: flags.agentUser,
      walletUser: flags.walletUser,
      outputDir: flags.outputDir || './output'
    })
    break

  case 'verify':
    verify({
      agentUser: flags.agentUser,
      walletUser: flags.walletUser
    })
    break

  default:
    console.error('Usage: hermes-gate bootstrap <generate|provision|verify>')
    process.exit(1)
}
