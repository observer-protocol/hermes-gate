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

async function runPluginInstall () {
  const { homedir } = await import('node:os')
  const { resolve, join } = await import('node:path')
  const { mkdirSync, cpSync, existsSync } = await import('node:fs')
  const { fileURLToPath } = await import('node:url')

  const pluginSrc = resolve(fileURLToPath(new URL('../plugin', import.meta.url)))
  if (!existsSync(pluginSrc)) {
    console.error(`hermes-gate: plugin directory not found at ${pluginSrc}`)
    process.exit(1)
  }

  const dest = join(homedir(), '.hermes', 'plugins', 'hermes-gate-spend-gate')
  mkdirSync(dest, { recursive: true })
  cpSync(pluginSrc, dest, { recursive: true })

  console.log(`hermes-gate: binding-tier plugin installed to ${dest}`)
  console.log()
  console.log('Next steps:')
  console.log('  1. Add to ~/.hermes/.env:')
  console.log('       HERMES_GATE_HTTP_PORT=8472')
  console.log('  2. Restart hermes-gate with that env var set.')
  console.log('     The gate will log: "HTTP endpoint listening on 127.0.0.1:8472 (binding tier)"')
  console.log('  3. Restart your Hermes gateway.')
  console.log('     Payment commands (mppx, tempo wallet pay, agentcash, privy-agent-wallets)')
  console.log('     are now intercepted before execution and checked against your SpendMandate.')
}

switch (cmd) {
  case 'bootstrap': {
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
    break
  }

  case 'plugin': {
    switch (sub) {
      case 'install':
        await runPluginInstall()
        break

      default:
        console.error('Usage: hermes-gate plugin install')
        process.exit(1)
    }
    break
  }

  default:
    console.error('Usage: hermes-gate <bootstrap|plugin> <subcommand> [flags]')
    process.exit(1)
}
