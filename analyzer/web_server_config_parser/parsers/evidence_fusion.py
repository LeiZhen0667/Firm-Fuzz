#!/usr/bin/env python3
"""Deduplicate extracted web server config facts without ranking them."""

from __future__ import annotations

from typing import Dict, List

from common import dedupe_dicts


def fuse(artifacts: Dict[str, List[Dict[str, object]]]) -> Dict[str, List[Dict[str, object]]]:
    return {
        "servers": dedupe_dicts(artifacts.get("servers", []), ["type", "version"]),
        "listeners": dedupe_dicts(artifacts.get("listeners", []), ["address", "port", "protocol"]),
        "document_roots": dedupe_dicts(artifacts.get("document_roots", []), ["root_type", "path"]),
        "aliases": dedupe_dicts(artifacts.get("aliases", []), ["url_prefix", "filesystem_path", "mapping_type"]),
        "cgi_mappings": dedupe_dicts(
            artifacts.get("cgi_mappings", []),
            ["mapping_type", "url_prefix", "filesystem_path", "handler", "extension"],
        ),
        "auth_rules": dedupe_dicts(artifacts.get("auth_rules", []), ["rule_type", "path_or_scope", "value"]),
        "startup_commands": dedupe_dicts(artifacts.get("startup_commands", []), ["command", "config_path", "document_root", "port"]),
        "config_references": dedupe_dicts(artifacts.get("config_references", []), ["reference_type", "path"]),
        "routes": dedupe_dicts(artifacts.get("routes", []), ["route", "route_type"]),
        "references": dedupe_dicts(artifacts.get("references", []), ["path", "reference_type"]),
    }

