#!/usr/bin/env python3
"""Regex route miner module for frontend analyzer."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from web_frontend_parser import Param, Route, _extract_regex_routes


def extract(content: str, ui_context: Optional[str]) -> Tuple[List[Route], List[Param], Set[str]]:
    """Extract route candidates and query params from arbitrary text."""
    return _extract_regex_routes(content, ui_context)
