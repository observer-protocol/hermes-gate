// SPDX-License-Identifier: Apache-2.0
// Part of @observer-protocol/hermes-gate
//
// agentskills.io skill — thin wrapper over the gate_evaluate MCP tool.
// Zero enforcement logic: the gate enforces, this skill surfaces the decision.

'use strict'

/**
 * Evaluate a spend action via the gate MCP server.
 *
 * @param {{ rail: string, amount: string, currency: string, category?: string, note?: string }} action
 * @param {{ callTool: (name: string, args: object) => Promise<object> }} mcpClient
 * @returns {Promise<{ allow: boolean, reasons: object[], advisories: object[], mandateValidUntil: string }>}
 */
export async function evaluateSpend (action, mcpClient) {
  return mcpClient.callTool('gate_evaluate', action)
}

/**
 * agentskills.io skill manifest — describes this skill to the Hermes skill registry.
 */
export const skillManifest = {
  name: 'hermes-spend-gate',
  version: '0.1.0',
  description: 'Fail-closed spend gate — evaluates proposed spends against the agent\'s OP-issued SpendMandate',
  tools: ['gate_evaluate', 'gate_execute', 'gate_status'],
  permissions: ['mcp:gate_evaluate', 'mcp:gate_execute'],
  author: 'observer-protocol',
  homepage: 'https://github.com/observer-protocol/hermes-gate'
}
