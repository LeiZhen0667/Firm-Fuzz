#!/usr/bin/env python3
"""Stage-2 analysis over full preprocessed binary context."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


ROUTE_RE = re.compile(
    r"(?i)(?:^/|/goform/|/cgi-bin/|/HNAP1/|/hnap1/|(?:^|/)[^/\s]+\.(?:cgi|asp|htm|html)$)"
)
ROUTE_NAME_RE = re.compile(r"(?i)(cgi|asp|handler|login|logout|apply|upgrade|reboot|hnap)")
PARAM_CALL_RE = re.compile(
    r'\b(?P<api>websGetVar2?|cgiFormString|cgiFormInteger|cgiFormDouble|get_cgi|getVar|get_single|GetValue|getenv)\s*\((?P<args>[^;\n]+)\)'
)
REGISTER_CALL_RE = re.compile(
    r'\b(?P<api>websFormDefine|websUrlHandlerDefine|cgi_register|ejRegister|asp_register)\s*\((?P<args>[^;\n]+)\)'
)
CONFIG_CALL_RE = re.compile(
    r'\b(?P<api>nvram_(?:get|safe_get|set|unset|commit|default_get)|uci_(?:get|set|commit)|apmib_(?:get|set)|mib_(?:get|set)|config_(?:get|set))\s*\((?P<args>[^;\n]+)\)'
)
CONSTRAINT_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("int_cast", re.compile(r"\b(?P<api>atoi|atol|strtol|strtoul)\s*\(\s*(?P<target>[A-Za-z_]\w*)")),
    ("strlen_compare", re.compile(r"\bstrlen\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*\)\s*(?P<op>[<>!=]=?)\s*(?P<value>\d+)")),
    ("string_enum", re.compile(r'\b(?P<api>strcmp|strncmp|strcasecmp|strncasecmp)\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*,\s*"(?P<value>[^"]+)"')),
    ("format_scan", re.compile(r'\bsscanf\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*,\s*"(?P<value>[^"]+)"')),
    ("ip_format", re.compile(r"\b(?P<api>inet_addr|inet_aton)\s*\(\s*(?P<target>[A-Za-z_]\w*)")),
    ("numeric_boundary", re.compile(r"\bif\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*(?P<op>[<>]=?|==|!=)\s*(?P<value>-?\d+)\s*\)")),
)
AUTH_KEYWORDS = {
    "login",
    "logout",
    "password",
    "passwd",
    "session",
    "auth",
    "cookie",
    "token",
    "nonce",
    "admin",
}
STATE_KEYWORDS = {
    "apply",
    "save",
    "reboot",
    "restart",
    "reset",
    "restore",
    "upgrade",
    "commit",
}
RESPONSE_KEYWORDS = {
    "success",
    "fail",
    "error",
    "invalid",
    "warning",
    "login",
    "logout",
    "reboot",
    "upgrade",
    "session",
}
SINK_CATEGORIES: Dict[str, str] = {
    "system": "command",
    "popen": "command",
    "execl": "command",
    "execv": "command",
    "execve": "command",
    "execvp": "command",
    "dosystem": "command",
    "strcpy": "memory",
    "strncpy": "memory",
    "strcat": "memory",
    "strncat": "memory",
    "sprintf": "memory",
    "snprintf": "memory",
    "vsprintf": "memory",
    "memcpy": "memory",
    "memmove": "memory",
    "gets": "memory",
    "fopen": "file",
    "open": "file",
    "unlink": "file",
    "remove": "file",
    "rename": "file",
    "chmod": "file",
    "chown": "file",
    "nvram_set": "config",
    "nvram_commit": "config",
    "uci_set": "config",
    "uci_commit": "config",
    "apmib_set": "config",
    "mib_set": "config",
    "reboot": "state",
    "restart": "state",
    "kill": "state",
    "socket": "network",
    "connect": "network",
    "send": "network",
    "sendto": "network",
    "recv": "network",
}
PARAM_READERS = {
    "websGetVar",
    "websGetVar2",
    "cgiFormString",
    "cgiFormInteger",
    "cgiFormDouble",
    "get_cgi",
    "getVar",
    "get_single",
    "GetValue",
    "getenv",
}
CONFIG_APIS = {
    "nvram_get",
    "nvram_safe_get",
    "nvram_set",
    "nvram_unset",
    "nvram_commit",
    "nvram_default_get",
    "uci_get",
    "uci_set",
    "uci_commit",
    "apmib_get",
    "apmib_set",
    "mib_get",
    "mib_set",
    "config_get",
    "config_set",
}
HANDLER_PATTERNS = (
    re.compile(r"(?i)(?:^|_)(?:cgi|asp|ej|hnap|login|logout|apply|upgrade|reboot|handler)(?:_|$)"),
    re.compile(r"(?i)do_(?:login|apply|upgrade|reboot|auth)"),
)


def _confidence(rank: int) -> str:
    if rank >= 3:
        return "high"
    if rank == 2:
        return "medium"
    return "low"


def _string_literals(text: str) -> List[str]:
    return [match.group(1) for match in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)]


def _classify_string(value: str) -> List[str]:
    lowered = value.lower()
    tags: List[str] = []
    if ROUTE_RE.search(value):
        tags.append("route")
    if any(word in lowered for word in AUTH_KEYWORDS):
        tags.append("auth")
    if any(word in lowered for word in STATE_KEYWORDS):
        tags.append("state")
    if any(word in lowered for word in RESPONSE_KEYWORDS) and (" " in value or "." in value or "_" in value):
        tags.append("response")
    if not tags:
        if value.startswith("HTTP_") or value in {"QUERY_STRING", "CONTENT_LENGTH", "REQUEST_METHOD"}:
            tags.append("env")
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{2,64}", value):
            tags.append("identifier")
    return tags


def _dedupe_dict_items(items: Iterable[Dict[str, Any]], key_fields: Sequence[str]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[Any, ...]] = set()
    deduped: List[Dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _evidence(
    preprocess_file: str,
    parser: str,
    *,
    function_name: Optional[str] = None,
    function_addr: Optional[str] = None,
    address: Optional[str] = None,
    snippet: str = "",
    confidence: str = "medium",
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "source_file": preprocess_file,
        "tool": "preprocessed_ida",
        "parser": parser,
        "confidence": confidence,
    }
    if function_name:
        item["function"] = function_name
    if function_addr:
        item["function_addr"] = function_addr
    if address:
        item["address"] = address
    if snippet:
        item["snippet"] = snippet[:400]
    return item


def _function_text(function: Dict[str, Any]) -> str:
    pseudo = function.get("pseudocode")
    if pseudo:
        return str(pseudo)
    disassembly = function.get("disassembly", [])
    return "\n".join(str(row.get("text", "")) for row in disassembly)


def _load_preprocessed(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def analyze_preprocessed_artifact(data: Dict[str, Any], *, preprocess_path: Path) -> Dict[str, Any]:
    binary = data.get("binary", {})
    preprocess_file = str(preprocess_path.resolve())
    strings = list(data.get("strings", []))
    functions = list(data.get("functions", []))
    callgraph_edges = list(data.get("callgraph_edges", []))

    strings_by_addr = {str(item.get("addr")): item for item in strings if item.get("addr")}
    functions_by_addr = {str(item.get("addr")): item for item in functions if item.get("addr")}
    functions_by_name = {str(item.get("name")): item for item in functions if item.get("name")}

    interesting_strings: List[Dict[str, Any]] = []
    routes: List[Dict[str, Any]] = []
    auth_hints: List[Dict[str, Any]] = []
    state_hints: List[Dict[str, Any]] = []
    response_strings: List[Dict[str, Any]] = []
    candidate_functions: Set[str] = set()

    for string_item in strings:
        value = str(string_item.get("value", ""))
        tags = _classify_string(value)
        if not tags:
            continue
        string_addr = str(string_item.get("addr"))
        string_refs = list(string_item.get("xrefs", []))
        interesting = {
            "value": value,
            "addr": string_addr,
            "categories": tags,
            "xref_count": len(string_refs),
            "xrefs": string_refs,
            "evidence": [
                _evidence(
                    preprocess_file,
                    "string_classifier",
                    address=string_addr,
                    snippet=value,
                    confidence=_confidence(3 if "route" in tags else 2),
                )
            ],
        }
        interesting_strings.append(interesting)
        for xref in string_refs:
            if xref.get("function_addr"):
                candidate_functions.add(str(xref["function_addr"]))
        if "route" in tags:
            routes.append(
                {
                    "route": value,
                    "route_type": "string_literal",
                    "source": "preprocessed_string",
                    "evidence": interesting["evidence"],
                }
            )
        if "auth" in tags:
            auth_hints.append(
                {
                    "hint": value,
                    "kind": "string",
                    "addr": string_addr,
                    "evidence": interesting["evidence"],
                }
            )
        if "state" in tags:
            state_hints.append(
                {
                    "hint": value,
                    "kind": "string",
                    "addr": string_addr,
                    "evidence": interesting["evidence"],
                }
            )
        if "response" in tags:
            response_strings.append(
                {
                    "value": value,
                    "addr": string_addr,
                    "evidence": interesting["evidence"],
                }
            )

    handlers: List[Dict[str, Any]] = []
    route_mappings: List[Dict[str, Any]] = []
    params: List[Dict[str, Any]] = []
    constraints: List[Dict[str, Any]] = []
    config_accesses: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []
    xrefs: List[Dict[str, Any]] = []
    pseudo_snippets: List[Dict[str, Any]] = []

    seen_handlers: Set[Tuple[str, str]] = set()
    seen_routes: Set[Tuple[str, str, str]] = set()
    seen_params: Set[Tuple[str, str, str]] = set()
    seen_constraints: Set[Tuple[str, str, str, str]] = set()
    seen_configs: Set[Tuple[str, str, str]] = set()
    seen_sinks: Set[Tuple[str, str, str]] = set()

    for function in functions:
        func_name = str(function.get("name", ""))
        func_addr = str(function.get("addr", ""))
        text = _function_text(function)
        disassembly_rows = list(function.get("disassembly", []))
        import_refs = list(function.get("import_refs", []))
        string_refs = list(function.get("string_refs", []))

        is_handler_name = any(pattern.search(func_name) for pattern in HANDLER_PATTERNS)
        if is_handler_name:
            candidate_functions.add(func_addr)
            key = (func_name, func_addr)
            if key not in seen_handlers:
                seen_handlers.add(key)
                handlers.append(
                    {
                        "name": func_name,
                        "addr": func_addr,
                        "size": function.get("size"),
                        "source": "function_name",
                        "evidence": [
                            _evidence(
                                preprocess_file,
                                "handler_name",
                                function_name=func_name,
                                function_addr=func_addr,
                                address=func_addr,
                                snippet=func_name,
                                confidence="medium",
                            )
                        ],
                    }
                )

        interesting_lines = [
            line.get("text", "")
            for line in disassembly_rows
            if any(
                token in str(line.get("text", ""))
                for token in ("GetVar", "get_cgi", "nvram_", "uci_", "apmib_", "login", "apply", "reboot", "upgrade")
            )
        ]
        if function.get("pseudocode"):
            text_lines = str(function["pseudocode"]).splitlines()
            interesting_lines.extend(
                line.strip()
                for line in text_lines
                if any(token in line for token in ("GetVar", "get_cgi", "nvram_", "uci_", "apmib_", "login", "apply", "reboot", "upgrade"))
            )
        if interesting_lines:
            pseudo_snippets.append(
                {
                    "function": func_name,
                    "function_addr": func_addr,
                    "snippet": "\n".join(interesting_lines[:20]),
                }
            )

        for ref in import_refs:
            import_name = str(ref.get("name", "")).strip()
            lowered_import = import_name.lower()
            if not import_name:
                continue
            if import_name in PARAM_READERS:
                candidate_functions.add(func_addr)
                key = (func_name, import_name, func_addr)
                if key not in seen_params:
                    seen_params.add(key)
                    params.append(
                        {
                            "name": import_name,
                            "reader_api": import_name,
                            "source": "import_xref",
                            "function": func_name,
                            "function_addr": func_addr,
                            "evidence": [
                                _evidence(
                                    preprocess_file,
                                    "param_reader_xref",
                                    function_name=func_name,
                                    function_addr=func_addr,
                                    address=str(ref.get("xref_addr") or ""),
                                    snippet=str(ref.get("snippet") or ""),
                                    confidence="medium",
                                )
                            ],
                        }
                    )
            if import_name in CONFIG_APIS:
                candidate_functions.add(func_addr)
                key = (func_name, import_name, func_addr)
                if key not in seen_configs:
                    seen_configs.add(key)
                    config_accesses.append(
                        {
                            "api": import_name,
                            "access_type": "write" if import_name.endswith(("_set", "_commit", "_unset")) else "read",
                            "source": "import_xref",
                            "function": func_name,
                            "function_addr": func_addr,
                            "evidence": [
                                _evidence(
                                    preprocess_file,
                                    "config_xref",
                                    function_name=func_name,
                                    function_addr=func_addr,
                                    address=str(ref.get("xref_addr") or ""),
                                    snippet=str(ref.get("snippet") or ""),
                                    confidence="high",
                                )
                            ],
                        }
                    )
            if lowered_import in SINK_CATEGORIES:
                candidate_functions.add(func_addr)
                key = (func_name, import_name, str(ref.get("xref_addr") or ""))
                if key not in seen_sinks:
                    seen_sinks.add(key)
                    sinks.append(
                        {
                            "api": import_name,
                            "category": SINK_CATEGORIES[lowered_import],
                            "function": func_name,
                            "function_addr": func_addr,
                            "xref_addr": str(ref.get("xref_addr") or ""),
                            "snippet": str(ref.get("snippet") or ""),
                            "evidence": [
                                _evidence(
                                    preprocess_file,
                                    "sink_xref",
                                    function_name=func_name,
                                    function_addr=func_addr,
                                    address=str(ref.get("xref_addr") or ""),
                                    snippet=str(ref.get("snippet") or ""),
                                    confidence="high",
                                )
                            ],
                        }
                    )
                xrefs.append(
                    {
                        "kind": SINK_CATEGORIES[lowered_import],
                        "api": import_name,
                        "function": func_name,
                        "function_addr": func_addr,
                        "xref_addr": str(ref.get("xref_addr") or ""),
                        "snippet": str(ref.get("snippet") or ""),
                    }
                )

        for ref in string_refs:
            string_addr = str(ref.get("string_addr", ""))
            string_item = strings_by_addr.get(string_addr)
            if not string_item:
                continue
            value = str(string_item.get("value", ""))
            tags = _classify_string(value)
            if "route" not in tags:
                continue
            confidence_rank = 2
            if ROUTE_NAME_RE.search(func_name):
                confidence_rank = 3
            key = (value, func_name, func_addr)
            if key not in seen_routes:
                seen_routes.add(key)
                route_mappings.append(
                    {
                        "route": value,
                        "handler": func_name,
                        "handler_addr": func_addr,
                        "source": "string_xref",
                        "confidence": _confidence(confidence_rank),
                        "evidence": [
                            _evidence(
                                preprocess_file,
                                "string_xref",
                                function_name=func_name,
                                function_addr=func_addr,
                                address=str(ref.get("xref_addr") or ""),
                                snippet=str(ref.get("snippet") or ""),
                                confidence=_confidence(confidence_rank),
                            )
                        ],
                    }
                )

        for match in PARAM_CALL_RE.finditer(text):
            api = match.group("api")
            literals = _string_literals(match.group("args"))
            if not literals:
                continue
            param_name = literals[0]
            default_value = literals[1] if len(literals) > 1 else None
            key = (func_name, api, param_name)
            if key in seen_params:
                continue
            seen_params.add(key)
            params.append(
                {
                    "name": param_name,
                    "reader_api": api,
                    "default": default_value,
                    "source": "function_text",
                    "function": func_name,
                    "function_addr": func_addr,
                    "evidence": [
                        _evidence(
                            preprocess_file,
                            "param_reader",
                            function_name=func_name,
                            function_addr=func_addr,
                            address=func_addr,
                            snippet=match.group(0),
                            confidence="high" if api != "getenv" else "medium",
                        )
                    ],
                }
            )

        for match in CONFIG_CALL_RE.finditer(text):
            api = match.group("api")
            literals = _string_literals(match.group("args"))
            access_key = literals[0] if literals else None
            key = (func_name, api, access_key or "")
            if key in seen_configs:
                continue
            seen_configs.add(key)
            config_accesses.append(
                {
                    "api": api,
                    "access_type": "write" if api.endswith(("_set", "_commit", "_unset")) else "read",
                    "key": access_key,
                    "source": "function_text",
                    "function": func_name,
                    "function_addr": func_addr,
                    "evidence": [
                        _evidence(
                            preprocess_file,
                            "config_access",
                            function_name=func_name,
                            function_addr=func_addr,
                            address=func_addr,
                            snippet=match.group(0),
                            confidence="high",
                        )
                    ],
                }
            )

        for match in REGISTER_CALL_RE.finditer(text):
            api = match.group("api")
            literals = _string_literals(match.group("args"))
            route = literals[0] if literals else None
            if not route:
                continue
            handler_name_match = re.search(r",\s*([A-Za-z_]\w+)\s*\)?", match.group("args"))
            handler_name = handler_name_match.group(1) if handler_name_match else func_name
            handler_obj = functions_by_name.get(handler_name)
            handler_addr = str(handler_obj.get("addr")) if handler_obj else func_addr
            key = (route, handler_name, handler_addr)
            if key in seen_routes:
                continue
            seen_routes.add(key)
            route_mappings.append(
                {
                    "route": route,
                    "handler": handler_name,
                    "handler_addr": handler_addr,
                    "registration_api": api,
                    "source": "function_text",
                    "confidence": "high",
                    "evidence": [
                        _evidence(
                            preprocess_file,
                            "handler_registration",
                            function_name=func_name,
                            function_addr=func_addr,
                            address=func_addr,
                            snippet=match.group(0),
                            confidence="high",
                        )
                    ],
                }
            )

        for kind, pattern in CONSTRAINT_PATTERNS:
            for match in pattern.finditer(text):
                target = match.groupdict().get("target") or match.groupdict().get("expr") or ""
                value = match.groupdict().get("value") or match.groupdict().get("api") or ""
                key = (func_name, kind, target, value)
                if key in seen_constraints:
                    continue
                seen_constraints.add(key)
                item: Dict[str, Any] = {
                    "kind": kind,
                    "target": target,
                    "value": value,
                    "function": func_name,
                    "function_addr": func_addr,
                    "source": "function_text",
                    "evidence": [
                        _evidence(
                            preprocess_file,
                            "constraint",
                            function_name=func_name,
                            function_addr=func_addr,
                            address=func_addr,
                            snippet=match.group(0),
                            confidence="medium",
                        )
                    ],
                }
                if match.groupdict().get("op"):
                    item["operator"] = match.groupdict()["op"]
                constraints.append(item)

    route_mappings = _dedupe_dict_items(route_mappings, ("route", "handler", "handler_addr"))
    handlers = _dedupe_dict_items(handlers, ("name", "addr"))
    params = _dedupe_dict_items(params, ("name", "reader_api", "function_addr"))
    constraints = _dedupe_dict_items(constraints, ("kind", "target", "function_addr", "value"))
    config_accesses = _dedupe_dict_items(config_accesses, ("api", "key", "function_addr"))
    sinks = _dedupe_dict_items(sinks, ("api", "function_addr", "xref_addr"))
    routes = _dedupe_dict_items(routes, ("route", "route_type"))
    auth_hints = _dedupe_dict_items(auth_hints, ("hint", "addr"))
    state_hints = _dedupe_dict_items(state_hints, ("hint", "addr"))
    interesting_strings = _dedupe_dict_items(interesting_strings, ("addr",))
    response_strings = _dedupe_dict_items(response_strings, ("addr",))
    xrefs = _dedupe_dict_items(xrefs, ("api", "function_addr", "xref_addr"))

    candidate_function_rows = []
    for func_addr in sorted(candidate_functions):
        function = functions_by_addr.get(func_addr)
        if not function:
            continue
        candidate_function_rows.append(
            {
                "name": function.get("name"),
                "addr": func_addr,
                "size": function.get("size"),
                "caller_count": len(function.get("callers", [])),
                "callee_count": len(function.get("callees", [])),
            }
        )

    candidate_addr_set = {row["addr"] for row in candidate_function_rows if row.get("addr")}
    filtered_callgraph = [
        edge
        for edge in callgraph_edges
        if str(edge.get("caller_addr")) in candidate_addr_set or str(edge.get("callee_addr")) in candidate_addr_set
    ]

    keyword_counter = Counter()
    keyword_counter["auth"] = len(auth_hints)
    keyword_counter["state"] = len(state_hints)
    keyword_counter["response"] = len(response_strings)

    artifact = {
        "version": "1.0",
        "artifact_type": "web_backend_binary",
        "input_type": "unreadable_web_backend_binary",
        "binary": {
            **binary,
            "preprocess_source": preprocess_file,
        },
        "routes": routes,
        "handlers": handlers,
        "route_mappings": route_mappings,
        "params": params,
        "constraints": constraints,
        "config_accesses": config_accesses,
        "sinks": sinks,
        "response_strings": response_strings,
        "auth_hints": auth_hints,
        "state_hints": state_hints,
        "strings": interesting_strings,
        "functions": candidate_function_rows,
        "xrefs": xrefs,
        "callgraph_edges": filtered_callgraph,
        "analysis_warnings": list(data.get("analysis_warnings", [])),
        "summary": {
            "route_count": len(routes),
            "handler_count": len(handlers),
            "route_mapping_count": len(route_mappings),
            "param_count": len(params),
            "constraint_count": len(constraints),
            "config_access_count": len(config_accesses),
            "sink_count": len(sinks),
            "response_string_count": len(response_strings),
            "interesting_string_count": len(interesting_strings),
            "candidate_function_count": len(candidate_function_rows),
            "hint_categories": dict(keyword_counter),
        },
        "pseudo_snippets": pseudo_snippets,
    }
    return artifact


def analyze_preprocessed_file(preprocess_path: Path) -> Dict[str, Any]:
    data = _load_preprocessed(preprocess_path)
    return analyze_preprocessed_artifact(data, preprocess_path=preprocess_path)
