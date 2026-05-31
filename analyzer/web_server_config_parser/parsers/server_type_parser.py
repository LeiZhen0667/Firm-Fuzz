#!/usr/bin/env python3
"""Extract web server identity facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import evidence, iter_lines, strip_inline_comment

SERVER_PATTERNS = [
    ("busybox httpd", re.compile(r"\bbusybox\s+httpd\b|\bhttpd\s+.*\bbusybox\b", re.I)),
    ("lighttpd", re.compile(r"\blighttpd\b|server\.document-root|server\.port|cgi\.assign", re.I)),
    ("nginx", re.compile(r"\bnginx\b|\bserver\s*\{|\blocation\s+/", re.I)),
    ("boa", re.compile(r"\bboa\b|^\s*(Port|DocumentRoot|ScriptAlias|CGIPath)\b", re.I)),
    ("goahead", re.compile(r"\bgoahead\b|goahead-webs|webs\.conf", re.I)),
    ("httpd", re.compile(r"(?<![\w.-])httpd(?![\w.-])|\bmini_httpd\b|\bmicro_httpd\b", re.I)),
]


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    filename = source_file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    haystacks = [(0, filename), *iter_lines(content)]
    for line_no, raw in haystacks:
        line = strip_inline_comment(raw) if line_no else raw
        if not line:
            continue
        for server_type, pattern in SERVER_PATTERNS:
            if not pattern.search(line):
                continue
            results.append(
                {
                    "type": server_type,
                    "version": None,
                    "source": "config_or_startup",
                    "confidence": "medium" if line_no else "low",
                    "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
                }
            )
    return results

