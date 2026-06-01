#!/usr/bin/env python3
"""Extract authentication and access-control facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import clean_value, evidence, iter_lines, strip_inline_comment

PATTERNS = [
    ("auth_type", re.compile(r"^\s*AuthType\s+(.+)$", re.I)),
    ("realm", re.compile(r"^\s*(?:AuthName|realm)\s+(.+)$", re.I)),
    ("password_file", re.compile(r"^\s*(?:AuthUserFile|userfile)\s+(.+)$", re.I)),
    ("password_file", re.compile(r"^\s*auth\.backend\.htpasswd\.userfile\s*=\s*(.+)$", re.I)),
    ("auth_require", re.compile(r"^\s*auth\.require\s*=\s*(.+)$", re.I)),
    ("require", re.compile(r"^\s*Require\s+(.+)$", re.I)),
    ("allow", re.compile(r"^\s*allow\s+(.+)$", re.I)),
    ("deny", re.compile(r"^\s*deny\s+(.+)$", re.I)),
    ("satisfy", re.compile(r"^\s*satisfy\s+(.+)$", re.I)),
    ("htpasswd", re.compile(r"(\S*\.htpasswd\S*)", re.I)),
]


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        for rule_type, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            results.append(
                {
                    "rule_type": rule_type,
                    "path_or_scope": None,
                    "value": clean_value(match.group(1)),
                    "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
                }
            )
    return results

