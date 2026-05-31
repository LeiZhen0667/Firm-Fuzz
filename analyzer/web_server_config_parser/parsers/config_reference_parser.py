#!/usr/bin/env python3
"""Extract include and config-reference facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import clean_value, evidence, iter_lines, shell_tokens, strip_inline_comment

PATTERNS = [
    ("include", re.compile(r"^\s*include(?:_shell)?\s+(.+)$", re.I)),
    ("source", re.compile(r"^\s*(?:source|\.)\s+(.+)$", re.I)),
]


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        for ref_type, pattern in PATTERNS:
            match = pattern.search(line)
            if match:
                results.append(
                    {
                        "reference_type": ref_type,
                        "path": clean_value(match.group(1)),
                        "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
                    }
                )
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            if token in {"-c", "-f"} and index + 1 < len(tokens):
                results.append(
                    {
                        "reference_type": "command_option",
                        "path": clean_value(tokens[index + 1]),
                        "evidence": [evidence(source_file, token, line_no, raw)],
                    }
                )
    return results

