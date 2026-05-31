#!/usr/bin/env python3
"""Template parser module for frontend analyzer."""

from __future__ import annotations

from typing import List, Tuple

from web_frontend_parser import Param, TemplateVar, _extract_template_vars


def extract(content: str) -> Tuple[List[TemplateVar], List[Param]]:
    """Extract template variables and template-related params."""
    return _extract_template_vars(content)
