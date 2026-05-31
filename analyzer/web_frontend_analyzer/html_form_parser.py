#!/usr/bin/env python3
"""HTML form parser module for frontend analyzer."""

from __future__ import annotations

from pathlib import Path

from web_frontend_parser import FrontendHTMLExtractor


def extract(content: str, source_file: Path) -> FrontendHTMLExtractor:
    """Extract form/routes/params/constraints from HTML-like content."""
    parser = FrontendHTMLExtractor(source_file)
    parser.feed(content)
    return parser
