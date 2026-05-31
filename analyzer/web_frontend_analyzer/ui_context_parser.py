#!/usr/bin/env python3
"""UI context parser module for frontend analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import List

from html_form_parser import extract as extract_html


def extract(content: str, source_file: Path) -> List[str]:
    """Extract UI context strings such as title/heading/labels/buttons."""
    parser = extract_html(content, source_file)
    parser.ui_context.add(f"page_filename:{source_file.name}")
    return sorted(parser.ui_context)
