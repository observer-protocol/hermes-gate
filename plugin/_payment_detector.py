"""Detect payment CLI commands in terminal tool calls and extract spend details.

Supports: mppx, tempo wallet pay, agentcash, privy-agent-wallets.
402 probing handles both MPP (amount=/currency= headers) and L402 (BOLT11 invoice).
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Optional

# Map payment client -> hermes-gate rail identifier
_RAIL_MAP: dict[str, str] = {
    'mppx': 'lightning',
    'tempo': 'ethereum-mainnet',
    'agentcash': 'ethereum-mainnet',
    'privy-agent-wallets': 'ethereum-mainnet',
}

# Each entry: (compiled pattern, client key)
# The first capture group is the target URL.
_PAYMENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\bmppx\b\s+(\S+)'), 'mppx'),
    (re.compile(r'\btempo\s+wallet\s+pay\s+(\S+)'), 'tempo'),
    (re.compile(r'\bagentcash\s+(?:pay|purchase)\s+(\S+)'), 'agentcash'),
    (re.compile(r'\bprivy-agent-wallets\s+pay\s+(\S+)'), 'privy-agent-wallets'),
]


def detect_payment(tool_name: str, args: object) -> Optional[dict]:
    """Return {rail, url, amount, currency} if the tool call is a payment, else None."""
    if tool_name != 'terminal':
        return None

    command = ''
    if isinstance(args, dict):
        command = args.get('command') or args.get('cmd') or ''
    if not command:
        return None

    for pattern, client in _PAYMENT_PATTERNS:
        m = pattern.search(command)
        if m:
            url = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            return {
                'rail': _RAIL_MAP[client],
                'url': url,
                'amount': None,
                'currency': None,
            }

    return None


def probe_402(url: str) -> dict[str, Optional[str]]:
    """GET the URL; parse amount/currency from the 402 WWW-Authenticate header.

    Returns {'amount': str|None, 'currency': str|None}.
    A 200 response means no payment is required (amount=None).
    Any non-402 error returns amount=None (caller will fail closed).
    """
    try:
        req = urllib.request.Request(url, method='GET')
        req.add_header('User-Agent', 'hermes-gate/0.2.0 (spend-gate-probe)')
        with urllib.request.urlopen(req, timeout=5):
            return {'amount': None, 'currency': None}  # 200 — no payment needed
    except urllib.error.HTTPError as e:
        if e.code == 402:
            return _parse_402_headers(dict(e.headers))
        return {'amount': None, 'currency': None}
    except Exception:
        return {'amount': None, 'currency': None}


def _parse_402_headers(headers: dict) -> dict[str, Optional[str]]:
    auth = (
        headers.get('WWW-Authenticate')
        or headers.get('www-authenticate')
        or ''
    )

    # MPP / generic 402: WWW-Authenticate: MPP amount="1.50", currency="USDT"
    amount_m = re.search(r'amount="?([0-9]+(?:\.[0-9]+)?)"?', auth)
    currency_m = re.search(r'currency="?([A-Z]+)"?', auth)

    amount: Optional[str] = amount_m.group(1) if amount_m else None
    currency: Optional[str] = currency_m.group(1) if currency_m else None

    # L402: WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."
    if not amount:
        invoice_m = re.search(r'invoice="(lnbc[^"]+)"', auth)
        if invoice_m:
            amount, currency = _decode_bolt11_amount(invoice_m.group(1))

    return {'amount': amount, 'currency': currency}


def _decode_bolt11_amount(invoice: str) -> tuple[Optional[str], Optional[str]]:
    """Parse sats from a BOLT11 prefix: lnbc<amount><multiplier>1...

    Multipliers: m=milli-BTC, u=micro-BTC, n=nano-BTC, p=pico-BTC, ''=whole BTC.
    Returns (sats_str, 'sat') or (None, None) if unparseable.
    """
    m = re.match(r'^ln(?:bc|tb|bcrt)(\d+)([munp]?)1', invoice)
    if not m:
        return None, None
    val = int(m.group(1))
    mult = m.group(2)
    mult_to_sat: dict[str, float] = {
        '':  100_000_000,
        'm': 100_000,
        'u': 100,
        'n': 0.1,
        'p': 0.0001,
    }
    sats = int(val * mult_to_sat.get(mult, 1.0))
    return (str(sats), 'sat') if sats > 0 else (None, None)
