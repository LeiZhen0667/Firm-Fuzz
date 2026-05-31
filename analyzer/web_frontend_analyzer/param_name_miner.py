#!/usr/bin/env python3
"""Parameter name miner module for frontend analyzer."""

from __future__ import annotations

from typing import List, Optional

from web_frontend_parser import Param, _add_urlencoded_params


def extract_urlencoded(
    text: str,
    route: Optional[str],
    source: str = "param_name_miner",
    confidence: str = "medium",
    evidence: str = "urlencoded string pattern",
) -> List[Param]:
    """Extract URL-encoded key names from text."""
    out: List[Param] = []
    _add_urlencoded_params(
        text=text,
        params=out,
        route=route,
        source=source,
        confidence=confidence,
        evidence=evidence,
    )
    return out
