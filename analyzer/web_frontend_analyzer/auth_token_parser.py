#!/usr/bin/env python3
"""Auth/token/state hint parser module for frontend analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from html_form_parser import extract as extract_html
from js_api_parser import extract as extract_js
from web_frontend_parser import Hint


def extract(content: str, source_file: Path) -> Tuple[List[Hint], List[Hint]]:
    """Extract auth_hints and state_hints from HTML+JS evidence."""
    html = extract_html(content, source_file)
    js_routes, js_params, js_refs, js_hints = extract_js(content, html.title)
    del js_routes, js_params, js_refs

    auth_hints: List[Hint] = list(html.auth_hints)
    state_hints: List[Hint] = list(html.state_hints)
    auth_kinds = {"login", "logout", "password", "session", "csrf", "token", "nonce", "cookie", "auth"}
    state_kinds = {"apply", "save", "reboot", "restart", "reset", "restore", "upgrade"}
    auth_hints.extend([h for h in js_hints if h.kind in auth_kinds])
    state_hints.extend([h for h in js_hints if h.kind in state_kinds])
    return auth_hints, state_hints
