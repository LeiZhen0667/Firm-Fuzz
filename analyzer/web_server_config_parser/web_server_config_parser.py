#!/usr/bin/env python3
"""Web server config parser entrypoint.

The parser consumes readable GPL web-server config candidate JSON and emits
structured facts with evidence for later seed/fusion modules.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

PARSER_DIR = Path(__file__).resolve().parent
PARSERS_DIR = PARSER_DIR / "parsers"
sys.path.insert(0, str(PARSERS_DIR))

from auth_rule_parser import extract as extract_auth_rules
from cgi_mapping_parser import extract as extract_cgi_mappings
from config_reference_parser import extract as extract_config_references
from evidence_fusion import fuse
from listener_parser import extract as extract_listeners
from root_alias_parser import extract as extract_roots_aliases
from server_type_parser import extract as extract_servers
from startup_command_parser import extract as extract_startup_commands


@dataclass
class ConfigSource:
    source_file: str
    content: str


def input_json_template() -> Dict[str, object]:
    return {
        "version": "1.0",
        "input_type": "web_server_config_sources",
        "files": [
            {
                "source_file": "/abs/path/to/httpd.conf",
                "content": "DocumentRoot /www\nScriptAlias /cgi-bin/ /www/cgi-bin/\n",
            }
        ],
    }


def load_sources(input_path: Path) -> List[ConfigSource]:
    data = json.loads(input_path.read_text(encoding="utf-8-sig"))
    if data.get("input_type") not in {None, "web_server_config_sources"}:
        raise ValueError(f"Unexpected input_type in {input_path}: {data.get('input_type')}")
    files = data.get("files", [])
    if not isinstance(files, list):
        raise ValueError(f"JSON input must contain list field: files ({input_path})")
    sources: List[ConfigSource] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        source_file = str(entry.get("source_file") or entry.get("path") or "<inline>")
        content = entry.get("content")
        if content is None:
            continue
        sources.append(ConfigSource(source_file=source_file, content=str(content)))
    return sources


def analyze_sources(sources: Iterable[ConfigSource], source_input: str) -> Dict[str, object]:
    buckets: Dict[str, List[Dict[str, object]]] = {
        "servers": [],
        "listeners": [],
        "document_roots": [],
        "aliases": [],
        "cgi_mappings": [],
        "auth_rules": [],
        "startup_commands": [],
        "config_references": [],
        "routes": [],
        "references": [],
    }
    parse_warnings: List[Dict[str, object]] = []

    for source in sources:
        try:
            buckets["servers"].extend(extract_servers(source.content, source.source_file))
            buckets["listeners"].extend(extract_listeners(source.content, source.source_file))
            root_alias = extract_roots_aliases(source.content, source.source_file)
            buckets["document_roots"].extend(root_alias["document_roots"])
            buckets["aliases"].extend(root_alias["aliases"])
            buckets["cgi_mappings"].extend(extract_cgi_mappings(source.content, source.source_file))
            buckets["auth_rules"].extend(extract_auth_rules(source.content, source.source_file))
            buckets["startup_commands"].extend(extract_startup_commands(source.content, source.source_file))
            buckets["config_references"].extend(extract_config_references(source.content, source.source_file))
        except Exception as exc:  # Keep one bad candidate from blocking the batch.
            parse_warnings.append({"source_file": source.source_file, "message": str(exc)})

    fused = fuse(buckets)
    fused["routes"] = _derive_routes(fused)
    fused["references"] = _derive_references(fused)

    artifact: Dict[str, object] = {
        "version": "1.0",
        "artifact_type": "web_server_config",
        "source_input": source_input,
        "servers": fused["servers"],
        "listeners": fused["listeners"],
        "document_roots": fused["document_roots"],
        "aliases": fused["aliases"],
        "cgi_mappings": fused["cgi_mappings"],
        "auth_rules": fused["auth_rules"],
        "startup_commands": fused["startup_commands"],
        "config_references": fused["config_references"],
        "routes": fused["routes"],
        "references": fused["references"],
        "parse_warnings": parse_warnings,
        "summary": {},
    }
    artifact["summary"] = _summary(artifact)
    return artifact


def _derive_routes(facts: Dict[str, List[Dict[str, object]]]) -> List[Dict[str, object]]:
    routes: List[Dict[str, object]] = []
    for alias in facts.get("aliases", []):
        prefix = alias.get("url_prefix")
        if prefix:
            routes.append({"route": prefix, "route_type": "alias", "evidence": alias.get("evidence", [])})
    for mapping in facts.get("cgi_mappings", []):
        prefix = mapping.get("url_prefix") or mapping.get("extension")
        if prefix:
            routes.append({"route": prefix, "route_type": "cgi_mapping", "evidence": mapping.get("evidence", [])})
    return fuse({"routes": routes})["routes"]


def _derive_references(facts: Dict[str, List[Dict[str, object]]]) -> List[Dict[str, object]]:
    refs: List[Dict[str, object]] = []
    for root in facts.get("document_roots", []):
        refs.append({"path": root.get("path"), "reference_type": root.get("root_type"), "evidence": root.get("evidence", [])})
    for ref in facts.get("config_references", []):
        refs.append({"path": ref.get("path"), "reference_type": ref.get("reference_type"), "evidence": ref.get("evidence", [])})
    refs = [ref for ref in refs if ref.get("path")]
    return fuse({"references": refs})["references"]


def _summary(artifact: Dict[str, object]) -> Dict[str, object]:
    fields = [
        "servers",
        "listeners",
        "document_roots",
        "aliases",
        "cgi_mappings",
        "auth_rules",
        "startup_commands",
        "config_references",
        "routes",
        "references",
        "parse_warnings",
    ]
    summary = {f"{field}_count": len(artifact.get(field, [])) for field in fields}
    summary["server_types"] = sorted({item.get("type") for item in artifact.get("servers", []) if item.get("type")})
    summary["listener_ports"] = sorted({item.get("port") for item in artifact.get("listeners", []) if item.get("port") is not None})
    return summary


def discover_default_inputs(repo_root: Path) -> List[Path]:
    return sorted(repo_root.glob("output/web_json/*/web_server_config_sources.readable.json"))


def default_output_path(input_path: Path, output_arg: Optional[Path], multiple: bool) -> Path:
    if output_arg:
        if multiple or output_arg.suffix.lower() != ".json":
            return output_arg / f"{input_path.parent.name}.web_server_config_artifacts.json"
        return output_arg
    return PARSER_DIR / "output" / f"{input_path.parent.name}.web_server_config_artifacts.json"


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract web server config facts from readable JSON sources")
    ap.add_argument("inputs", nargs="*", type=Path, help="Input web_server_config_sources.readable.json files")
    ap.add_argument("-o", "--output", type=Path, default=None, help="Output JSON file or directory")
    ap.add_argument("--print-input-template", action="store_true", help="Print canonical JSON input template and exit")
    args = ap.parse_args()

    if args.print_input_template:
        print(json.dumps(input_json_template(), ensure_ascii=False, indent=2))
        return

    repo_root = PARSER_DIR.parents[1]
    inputs = args.inputs or discover_default_inputs(repo_root)
    if not inputs:
        out_dir = args.output or (PARSER_DIR / "output")
        out_dir.mkdir(parents=True, exist_ok=True)
        print(
            "[web_server_config_parser] No inputs found. Expected: "
            "output/web_json/*/web_server_config_sources.readable.json"
        )
        return

    multiple = len(inputs) > 1
    for input_path in inputs:
        sources = load_sources(input_path)
        artifact = analyze_sources(sources, str(input_path))
        out_path = default_output_path(input_path, args.output, multiple)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[web_server_config_parser] Wrote artifacts to: {out_path}")


if __name__ == "__main__":
    main()
