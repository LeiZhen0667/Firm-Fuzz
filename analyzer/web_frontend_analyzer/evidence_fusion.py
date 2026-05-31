#!/usr/bin/env python3
"""Evidence fusion module for frontend analyzer."""

from __future__ import annotations

from typing import Dict, List

from web_frontend_parser import (
    Constraint,
    Hint,
    Param,
    Route,
    TemplateVar,
    _dedupe_constraints,
    _dedupe_hints,
    _dedupe_params,
    _dedupe_routes,
    _dedupe_template_vars,
)


def fuse(
    routes: List[Route],
    params: List[Param],
    constraints: List[Constraint],
    auth_hints: List[Hint],
    state_hints: List[Hint],
    template_vars: List[TemplateVar],
) -> Dict[str, List[dict]]:
    """Fuse and deduplicate evidence from multiple parser modules."""
    return {
        "routes": _dedupe_routes(routes),
        "params": _dedupe_params(params),
        "constraints": _dedupe_constraints(constraints),
        "auth_hints": _dedupe_hints(auth_hints),
        "state_hints": _dedupe_hints(state_hints),
        "template_vars": _dedupe_template_vars(template_vars),
    }
