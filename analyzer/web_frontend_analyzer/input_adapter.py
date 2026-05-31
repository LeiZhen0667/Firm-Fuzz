#!/usr/bin/env python3
"""Input adapter for web frontend analyzer.

Supported inputs:
1) A single frontend file path
2) A directory path (recursive discovery)
3) A JSON file describing frontend file entries
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from web_frontend_parser import FRONTEND_EXTENSIONS, discover_frontend_files


@dataclass
class FrontendSource:
    source_file: str
    content: str


def load_sources(input_path: Path, input_format: str = "auto") -> List[FrontendSource]:
    """Load analyzable frontend sources from path/dir/json."""
    fmt = input_format
    if fmt == "auto":
        fmt = "json" if input_path.is_file() and input_path.suffix.lower() == ".json" else "path"

    if fmt == "json":
        return _load_from_json(input_path)
    return _load_from_path(input_path)


def _load_from_path(input_path: Path) -> List[FrontendSource]:
    if input_path.is_file():
        files = [input_path]
    else:
        files = discover_frontend_files(input_path)
    sources: List[FrontendSource] = []
    for file_path in files:
        if file_path.suffix.lower() not in FRONTEND_EXTENSIONS:
            continue
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        sources.append(FrontendSource(source_file=str(file_path), content=content))
    return sources


def _load_from_json(input_path: Path) -> List[FrontendSource]:
    data = json.loads(input_path.read_text(encoding="utf-8"))
    files = data.get("files", [])
    if not isinstance(files, list):
        raise ValueError("JSON input must contain list field: files")

    sources: List[FrontendSource] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        source_file = str(entry.get("source_file") or entry.get("path") or "")
        inline_content = entry.get("content")
        if inline_content is not None:
            sources.append(FrontendSource(source_file=source_file or "<inline>", content=str(inline_content)))
            continue

        if not source_file:
            continue
        path = Path(source_file)
        if not path.exists() or not path.is_file():
            continue
        if path.suffix.lower() not in FRONTEND_EXTENSIONS:
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        sources.append(FrontendSource(source_file=str(path), content=content))
    return sources


def input_json_template() -> dict:
    """Return a canonical JSON template for upstream modules."""
    return {
        "version": "1.0",
        "input_type": "web_frontend_sources",
        "files": [
            {
                "source_file": "/abs/path/to/page.asp",
                "content": "<html>...</html>",
            },
            {
                "source_file": "/abs/path/to/script_config.htm",
            },
        ],
    }
