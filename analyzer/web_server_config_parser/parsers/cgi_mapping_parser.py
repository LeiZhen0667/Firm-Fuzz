#!/usr/bin/env python3
"""Extract CGI mapping facts."""

from __future__ import annotations

import re
from typing import Dict, List

from common import clean_value, evidence, iter_lines, strip_inline_comment

PATTERNS = [
    ("script_alias", re.compile(r"^\s*ScriptAlias\s+(\S+)\s+(.+)$", re.I)),
    ("cgi_path", re.compile(r"^\s*CGIPath\s+(.+)$", re.I)),
    ("add_handler", re.compile(r"^\s*AddHandler\s+(\S+)\s+(.+)$", re.I)),
    ("cgi_assign", re.compile(r'^\s*cgi\.assign\s*=\s*\(\s*"([^"]+)"\s*=>\s*"([^"]*)"', re.I)),
    ("fastcgi", re.compile(r'^\s*fastcgi\.server\s*=\s*\(\s*"([^"]+)"', re.I)),
    ("location_cgi", re.compile(r"^\s*location\s+(/[^ \t{;]*cgi[^ \t{;]*)", re.I)),
    ("cgi_bin", re.compile(r"(/[^ \t\"']*cgi-bin/?)(?:\s+([^ \t\"']+))?", re.I)),
    ("cgi_extension", re.compile(r"(\*\.cgi|\.cgi\b)", re.I)),
]


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        for kind, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            item: Dict[str, object] = {
                "mapping_type": kind,
                "url_prefix": None,
                "filesystem_path": None,
                "handler": None,
                "extension": None,
                "evidence": [evidence(source_file, pattern.pattern, line_no, raw)],
            }
            groups = [clean_value(group) for group in match.groups() if group is not None]
            if kind == "script_alias" and len(groups) >= 2:
                item["url_prefix"], item["filesystem_path"] = groups[0], groups[1]
            elif kind in {"cgi_path", "location_cgi", "cgi_bin", "fastcgi"} and groups:
                item["url_prefix"] = groups[0]
                if len(groups) > 1:
                    item["filesystem_path"] = groups[1]
            elif kind in {"add_handler", "cgi_assign"} and groups:
                item["handler"] = groups[-1] if len(groups) > 1 else groups[0]
                item["extension"] = groups[0] if groups[0].startswith(".") or "*" in groups[0] else None
                if groups[0].startswith("/"):
                    item["url_prefix"] = groups[0]
            elif kind == "cgi_extension":
                item["extension"] = groups[0]
            results.append(item)
    return results

