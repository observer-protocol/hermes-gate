"""hermes-gate-spend-gate — fail-closed pre_tool_call spend gate.

Intercepts payment CLI commands (mppx, tempo wallet pay, agentcash, privy-agent-wallets)
inside Hermes's terminal tool before they execute. For each detected payment:

1. Probes the target URL to discover amount/currency from the 402 WWW-Authenticate header.
2. Evaluates the spend against the operator's SpendMandate via the hermes-gate HTTP endpoint.
3. Blocks the terminal call if the gate returns allow: false or is unreachable.

Fail-closed: if the gate is unreachable, or if amount/currency cannot be determined from
the 402 response, the payment is blocked.

Requires hermes-gate running with HERMES_GATE_HTTP_PORT set (default 8472).
Add to ~/.hermes/.env:
    HERMES_GATE_HTTP_PORT=8472
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from ._gate_client import GateClient
from ._payment_detector import detect_payment, probe_402

logger = logging.getLogger(__name__)

_client: Optional[GateClient] = None


def register(ctx: Any) -> None:
    global _client
    port = int(os.environ.get('HERMES_GATE_HTTP_PORT', '8472'))
    _client = GateClient(f'http://127.0.0.1:{port}')
    ctx.register_hook('pre_tool_call', _on_pre_tool_call)
    logger.info('hermes-gate-spend-gate: registered pre_tool_call hook (gate at 127.0.0.1:%d)', port)


def _on_pre_tool_call(
    tool_name: str = '',
    args: Any = None,
    **_: Any,
) -> Optional[dict]:
    if _client is None:
        return None

    payment = detect_payment(tool_name, args)
    if payment is None:
        return None  # not a payment command

    # Probe the 402 URL to discover amount/currency before authorizing.
    if payment.get('url'):
        try:
            details = probe_402(payment['url'])
            if details.get('amount'):
                payment['amount'] = details['amount']
            if details.get('currency'):
                payment['currency'] = details['currency']
        except Exception as e:
            logger.debug('hermes-gate: 402 probe error for %s: %s', payment.get('url'), e)

    if payment.get('amount') is None or payment.get('currency') is None:
        url = payment.get('url', 'unknown URL')
        return {
            'action': 'block',
            'message': (
                f'hermes-gate: payment blocked — could not determine amount/currency '
                f'from {url}. The payment service must return amount= and currency= '
                f'in the 402 WWW-Authenticate header (MPP), or a BOLT11 invoice (L402).'
            ),
        }

    try:
        result = _client.evaluate({
            'rail': payment['rail'],
            'amount': payment['amount'],
            'currency': payment['currency'],
        })
    except Exception as e:
        logger.warning('hermes-gate: HTTP endpoint unreachable — failing closed: %s', e)
        return {
            'action': 'block',
            'message': (
                f'hermes-gate: spend gate unreachable — failing closed. '
                f'Is the gate running with HERMES_GATE_HTTP_PORT={os.environ.get("HERMES_GATE_HTTP_PORT", "8472")}? '
                f'({e})'
            ),
        }

    if result.get('allow'):
        return None  # allow

    reasons = result.get('reasons') or []
    msg = reasons[0].get('message', 'Spend denied') if reasons else 'Spend denied by hermes-gate'
    return {'action': 'block', 'message': f'hermes-gate: {msg}'}
