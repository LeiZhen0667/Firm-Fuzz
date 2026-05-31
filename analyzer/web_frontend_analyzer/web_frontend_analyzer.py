#!/usr/bin/env python3
"""Modular web frontend analyzer entrypoint.

This file keeps compatibility with the existing parser output model while
exposing a module-based architecture expected by skill-web-parser.md.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from auth_token_parser import extract as extract_hints
from evidence_fusion import fuse
from html_form_parser import extract as extract_html
from input_adapter import FrontendSource, input_json_template, load_sources
from js_api_parser import extract as extract_js
from regex_route_miner import extract as extract_routes_regex
from template_parser import extract as extract_template
from web_frontend_parser import Route, _extract_inline_script_refs, _looks_like_route


def analyze_frontend_content(content: str, source_file: str) -> Dict[str, object]:
    path = Path(source_file)
    page_name = path.name if source_file else "<inline>"

    html = extract_html(content, path)
    js_routes, js_params, js_refs, _js_hints = extract_js(content, html.title)
    regex_routes, regex_params, regex_refs = extract_routes_regex(content, html.title)
    template_vars, template_params = extract_template(content)
    auth_hints, state_hints = extract_hints(content, path)

    for ref in _extract_inline_script_refs(content):
        html.references.add(ref)
        if _looks_like_route(ref):
            html.routes.append(
                Route(
                    url=ref,
                    method="GET",
                    source="js_api_parser",
                    ui_context=html.title,
                    confidence="medium",
                    evidence=[f"location/window route reference {ref!r}"],
                )
            )

    html.routes.extend(js_routes)
    html.routes.extend(regex_routes)
    html.params.extend(js_params)
    html.params.extend(regex_params)
    html.params.extend(template_params)
    html.references.update(js_refs)
    html.references.update(regex_refs)
    html.ui_context.add(f"page_filename:{page_name}")

    fused = fuse(
        routes=html.routes,
        params=html.params,
        constraints=html.constraints,
        auth_hints=auth_hints,
        state_hints=state_hints,
        template_vars=template_vars,
    )

    return {
        "source_file": source_file,
        "artifact_type": "html",
        "routes": fused["routes"],
        "params": fused["params"],
        "constraints": fused["constraints"],
        "auth_hints": fused["auth_hints"],
        "state_hints": fused["state_hints"],
        "ui_context": sorted(html.ui_context),
        "template_vars": fused["template_vars"],
        "sinks": html.sinks,
        "references": sorted(html.references),
    }


def analyze_frontend_file(path: Path) -> Dict[str, object]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    return analyze_frontend_content(raw, str(path))


def main() -> None:
    ap = argparse.ArgumentParser(description="Modular web frontend analyzer")
    ap.add_argument("input", type=Path, help="Input file, directory, or JSON input file")
    ap.add_argument(
        "--input-format",
        choices=["auto", "path", "json"],
        default="auto",
        help="Input interpretation mode",
    )
    ap.add_argument(
        "--print-input-template",
        action="store_true",
        help="Print canonical JSON input template and exit",
    )
    ap.add_argument("-o", "--output", type=Path, default=None, help="Output file path (JSON)")
    args = ap.parse_args()

    if args.print_input_template:
        print(json.dumps(input_json_template(), ensure_ascii=False, indent=2))
        return

    sources = load_sources(args.input, input_format=args.input_format)
    artifacts = [analyze_frontend_content(src.content, src.source_file) for src in sources]
    out_text = json.dumps(artifacts, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
