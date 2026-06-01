#!/usr/bin/env python3
"""Extract web server startup command facts."""

from __future__ import annotations

from typing import Dict, List, Optional

from common import evidence, find_option, iter_lines, shell_tokens, strip_inline_comment

COMMAND_NAMES = {"httpd", "boa", "goahead", "lighttpd", "nginx"}


def extract(content: str, source_file: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line_no, raw in iter_lines(content):
        line = strip_inline_comment(raw)
        if not line:
            continue
        tokens = shell_tokens(line)
        command = _command_name(tokens, line)
        if not command:
            continue
        results.append(
            {
                "command": command,
                "argv": tokens,
                "config_path": find_option(tokens, {"-c", "-f"}),
                "document_root": find_option(tokens, {"-h"}),
                "port": find_option(tokens, {"-p"}),
                "error_log": find_option(tokens, {"-E"}),
                "auth_realm": find_option(tokens, {"-r"}),
                "evidence": [evidence(source_file, "startup_command_token", line_no, raw)],
            }
        )
    return results


def _command_name(tokens: List[str], line: str) -> Optional[str]:
    lowered = [token.lower() for token in tokens]
    if "busybox" in lowered:
        index = lowered.index("busybox")
        if index + 1 < len(lowered) and lowered[index + 1] == "httpd":
            return "busybox httpd"
    for name in COMMAND_NAMES:
        for token in lowered:
            basename = token.rsplit("/", 1)[-1]
            if basename == name:
                return name
    return None
