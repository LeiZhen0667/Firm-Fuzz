#!/usr/bin/env python3
"""Shared helpers for web server config parser modules."""

from __future__ import annotations

import re
import shlex
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

PARSER_NAME = "web_server_config_parser"


def iter_lines(content: str) -> Iterator[Tuple[int, str]]:
    for index, line in enumerate(content.splitlines(), start=1):
        yield index, line.rstrip("\n")


def strip_inline_comment(line: str) -> str:
    """Remove common config comments while preserving URL fragments loosely."""
    stripped = line.strip()
    if not stripped:
        return ""
    for marker in ("#", "//"):
        pos = stripped.find(marker)
        if pos == 0:
            return ""
        if pos > 0 and stripped[pos - 1].isspace():
            stripped = stripped[:pos].rstrip()
    return stripped


def evidence(source_file: str, pattern: str, line: int, snippet: str, parser: str = PARSER_NAME) -> Dict[str, object]:
    return {
        "source_file": source_file,
        "parser": parser,
        "pattern": pattern,
        "line": line,
        "snippet": snippet.strip()[:500],
    }


def clean_value(value: str) -> str:
    value = value.strip().rstrip(";")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def shell_tokens(line: str) -> List[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def find_option(tokens: List[str], names: Iterable[str]) -> Optional[str]:
    names = set(names)
    for index, token in enumerate(tokens):
        if token in names and index + 1 < len(tokens):
            return tokens[index + 1]
        for name in names:
            if token.startswith(name) and len(token) > len(name):
                return token[len(name) :]
    return None


def parse_address_port(raw: str) -> Tuple[Optional[str], Optional[int]]:
    value = clean_value(raw)
    value = value.replace("http://", "").replace("https://", "")
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), _to_port(port)
    if ":" in value and not re.fullmatch(r"\d+", value):
        host, port = value.rsplit(":", 1)
        return host or None, _to_port(port)
    return None, _to_port(value)


def _to_port(value: str) -> Optional[int]:
    match = re.search(r"\d{1,5}", value or "")
    if not match:
        return None
    port = int(match.group(0))
    if 0 <= port <= 65535:
        return port
    return None


def dedupe_dicts(items: List[Dict[str, object]], key_fields: Iterable[str]) -> List[Dict[str, object]]:
    merged: Dict[Tuple[object, ...], Dict[str, object]] = {}
    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if key not in merged:
            merged[key] = item
            continue
        existing = merged[key]
        old_evidence = existing.get("evidence") or []
        new_evidence = item.get("evidence") or []
        if isinstance(old_evidence, list) and isinstance(new_evidence, list):
            existing["evidence"] = _dedupe_evidence(old_evidence + new_evidence)
    return list(merged.values())


def _dedupe_evidence(entries: List[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = set()
    result: List[Dict[str, object]] = []
    for entry in entries:
        key = (entry.get("source_file"), entry.get("line"), entry.get("pattern"), entry.get("snippet"))
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result

