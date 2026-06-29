"""Lightweight HTTP client for the hermes-gate /gate/evaluate endpoint.

Uses only stdlib — no requests/httpx dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class GateClient:
    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self._url = f'{base_url.rstrip("/")}/gate/evaluate'
        self._timeout = timeout

    def evaluate(self, action: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(action).encode('utf-8')
        req = urllib.request.Request(
            self._url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore')
            try:
                return json.loads(body)
            except Exception:
                return {
                    'allow': False,
                    'reasons': [{'ruleType': 'gate_http_error', 'message': f'HTTP {e.code}: {body[:200]}'}],
                    'advisories': [],
                }
