#!/usr/bin/env python3
"""Extract listener address/port facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import clean_value, evidence, iter_lines, parse_address_port, shell_tokens, strip_inline_comment

DIRECTIVES = [
    re.compile(r"^\s*Port\s+(.+)$", re.I),
    re.compile(r"^\s*Listen\s+(.+)$", re.I),
    re.compile(r"^\s*listen\s+(.+?);?\s*$", re.I),
    re.compile(r"^\s*server\.port\s*=\s*(.+)$", re.I),
    re.compile(r"^\s*(?:HTTP_PORT|WEB_PORT|PORT)\s*=\s*(.+)$", re.I),
]


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        for pattern in DIRECTIVES:
            match = pattern.search(line)
            if not match:
                continue
            address, port = parse_address_port(match.group(1))
            if port is None:
                continue
            results.append(_listener(source_file, pattern.pattern, line_no, raw, address, port))

        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            if token == "-p" and index + 1 < len(tokens):
                address, port = parse_address_port(tokens[index + 1])
            elif token.startswith("-p") and len(token) > 2:
                address, port = parse_address_port(token[2:])
            else:
                continue
            if port is not None:
                results.append(_listener(source_file, "-p", line_no, raw, address, port))
    return results


def _listener(source_file: str, pattern: str, line: int, snippet: str, address: object, port: int) -> Dict[str, object]:
    return {
        "address": clean_value(str(address)) if address else None,
        "port": port,
        "protocol": "http",
        "evidence": [evidence(source_file, pattern, line, snippet)],
    }

