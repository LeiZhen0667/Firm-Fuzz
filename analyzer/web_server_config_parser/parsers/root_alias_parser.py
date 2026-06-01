#!/usr/bin/env python3
"""Extract document root, server root, alias, and static mapping facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import clean_value, evidence, iter_lines, shell_tokens, strip_inline_comment

ROOT_PATTERNS = [
    ("document_root", re.compile(r"^\s*DocumentRoot\s+(.+)$", re.I)),
    ("server_root", re.compile(r"^\s*ServerRoot\s+(.+)$", re.I)),
    ("document_root", re.compile(r"^\s*server\.document-root\s*=\s*(.+)$", re.I)),
    ("document_root", re.compile(r"^\s*root\s+(.+?);?\s*$", re.I)),
    ("document_root", re.compile(r"^\s*(?:WEBROOT|WWWROOT|DOCUMENT_ROOT)\s*=\s*(.+)$", re.I)),
]

ALIAS_PATTERNS = [
    re.compile(r"^\s*Alias\s+(\S+)\s+(.+)$", re.I),
    re.compile(r'^\s*alias\.url\s*\+=\s*\(\s*"([^"]+)"\s*=>\s*"([^"]+)"', re.I),
    re.compile(r"^\s*alias\s+(.+?);?\s*$", re.I),
]


def extract(content: str, source_file: str) -> Dict[str, List[Dict[str, object]]]:
    roots: List[Dict[str, object]] = []
    aliases: List[Dict[str, object]] = []
    current_location_prefix = None
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        location_match = re.search(r"^\s*location\s+(\S+)\s*\{?\s*$", line, re.I)
        if location_match:
            current_location_prefix = clean_value(location_match.group(1))
        if "}" in line:
            current_location_prefix = None
        for root_type, pattern in ROOT_PATTERNS:
            match = pattern.search(line)
            if match:
                roots.append(
                    {
                        "root_type": root_type,
                        "path": clean_value(match.group(1)),
                        "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
                    }
                )
        for pattern in ALIAS_PATTERNS:
            match = pattern.search(line)
            if match:
                if pattern.pattern.startswith("^\\s*alias\\s+"):
                    filesystem_path = clean_value(match.group(1))
                    url_prefix = current_location_prefix
                else:
                    filesystem_path = clean_value(match.group(2))
                    url_prefix = clean_value(match.group(1))
                aliases.append(
                    {
                        "url_prefix": url_prefix,
                        "filesystem_path": filesystem_path,
                        "mapping_type": "alias",
                        "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
                    }
                )
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            if token == "-h" and index + 1 < len(tokens):
                roots.append(
                    {
                        "root_type": "document_root",
                        "path": clean_value(tokens[index + 1]),
                        "evidence": [evidence(source_file, "-h", line_no, raw)],
                    }
                )
            elif token.startswith("-h") and len(token) > 2:
                roots.append(
                    {
                        "root_type": "document_root",
                        "path": clean_value(token[2:]),
                        "evidence": [evidence(source_file, "-h", line_no, raw)],
                    }
                )
    return {"document_roots": roots, "aliases": aliases}

