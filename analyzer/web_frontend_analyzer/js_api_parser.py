#!/usr/bin/env python3
"""JavaScript API parser module for frontend analyzer."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from web_frontend_parser import Hint, Param, Route, _extract_js_api


def extract(content: str, ui_context: Optional[str]) -> Tuple[List[Route], List[Param], Set[str], List[Hint]]:
    """Extract JS-derived routes, params, refs, and hints."""
    return _extract_js_api(content, ui_context)
