#!/usr/bin/env python3
"""Extract structured web-backend facts from the current IDA database."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_idaapi
    import ida_kernwin
    import ida_lines
    import ida_loader
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError as exc:  # pragma: no cover - runs inside IDA
    raise SystemExit(f"This script must run inside IDA Python: {exc}") from exc


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
    "doSystem": "command",
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


def _to_hex(ea: int) -> str:
    return f"0x{ea:x}"


def _json_safe(text: Any) -> str:
    if text is None:
        return ""
    return str(text)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _confidence(rank: int) -> str:
    if rank >= 3:
        return "high"
    if rank == 2:
        return "medium"
    return "low"


def _function_of(ea: int) -> Optional[ida_funcs.func_t]:
    return ida_funcs.get_func(ea)


def _function_name_of(ea: int) -> Optional[str]:
    func = _function_of(ea)
    if not func:
        return None
    return idc.get_func_name(func.start_ea)


def _snippet_for_ea(ea: int) -> str:
    try:
        return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
    except Exception:
        return idc.GetDisasm(ea) or ""


def _evidence(
    source_file: str,
    parser: str,
    *,
    address: Optional[int] = None,
    function: Optional[str] = None,
    snippet: str = "",
    confidence: str = "medium",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "source_file": source_file,
        "tool": "ida",
        "parser": parser,
        "confidence": confidence,
    }
    if address is not None:
        payload["address"] = _to_hex(address)
    if function:
        payload["function"] = function
    if snippet:
        payload["snippet"] = snippet
    return payload


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


def _collect_segments() -> List[Dict[str, Any]]:
    segments: List[Dict[str, Any]] = []
    index = 0
    while True:
        seg = ida_segment.getnseg(index)
        if seg is None:
            break
        segments.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": _to_hex(seg.start_ea),
                "end": _to_hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "perm": seg.perm,
            }
        )
        index += 1
    return segments


def _all_function_names() -> Dict[str, int]:
    matches: Dict[str, int] = {}
    for ea, name in idautils.Names():
        if not name:
            continue
        matches[name] = ea
    return matches


def _resolve_symbol_addresses(names: Iterable[str]) -> Dict[str, int]:
    known = _all_function_names()
    resolved: Dict[str, int] = {}
    for target in names:
        if target in known:
            resolved[target] = known[target]
            continue
        for name, ea in known.items():
            if name == target or name.endswith(target):
                resolved[target] = ea
                break
    return resolved


def _decompile(func_ea: int) -> Optional[str]:
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
    except Exception:
        return None
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return None
    if not cfunc:
        return None
    try:
        return str(cfunc)
    except Exception:
        return None


def _iter_function_items(func: ida_funcs.func_t) -> Iterable[int]:
    for ea in idautils.FuncItems(func.start_ea):
        yield ea


def _collect_callgraph_edges(candidate_funcs: Set[int], max_edges_per_func: int = 32) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, int]] = set()
    for func_ea in sorted(candidate_funcs):
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        caller_name = idc.get_func_name(func.start_ea)
        count = 0
        for item_ea in _iter_function_items(func):
            for callee in idautils.CodeRefsFrom(item_ea, False):
                callee_func = ida_funcs.get_func(callee)
                if not callee_func:
                    continue
                key = (func.start_ea, callee_func.start_ea)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    {
                        "caller": caller_name,
                        "caller_addr": _to_hex(func.start_ea),
                        "callee": idc.get_func_name(callee_func.start_ea),
                        "callee_addr": _to_hex(callee_func.start_ea),
                        "callsite": _to_hex(item_ea),
                    }
                )
                count += 1
                if count >= max_edges_per_func:
                    break
            if count >= max_edges_per_func:
                break
    return edges


def _xref_functions_to(addr: int, limit: int = 128) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, int]] = set()
    for xref in idautils.XrefsTo(addr):
        func = _function_of(xref.frm)
        if not func:
            continue
        key = (func.start_ea, xref.frm)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "function": idc.get_func_name(func.start_ea),
                "function_addr": _to_hex(func.start_ea),
                "xref_addr": _to_hex(xref.frm),
                "snippet": _snippet_for_ea(xref.frm),
            }
        )
        if len(refs) >= limit:
            break
    return refs


def _candidate_functions_from_names() -> Set[int]:
    funcs: Set[int] = set()
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if any(pattern.search(name) for pattern in HANDLER_PATTERNS):
            funcs.add(func_ea)
    return funcs


def _collect_strings(source_file: str, max_strings: int, max_xrefs: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Set[int]]:
    strings_db = idautils.Strings()
    strings_db.setup(minlen=4)
    interesting: List[Dict[str, Any]] = []
    routes: List[Dict[str, Any]] = []
    auth_hints: List[Dict[str, Any]] = []
    state_hints: List[Dict[str, Any]] = []
    candidate_funcs: Set[int] = set()

    for idx, s in enumerate(strings_db):
        if idx >= max_strings:
            break
        value = _json_safe(str(s))
        tags = _classify_string(value)
        if not tags:
            continue
        xrefs = _xref_functions_to(int(s.ea), limit=max_xrefs)
        xref_count = len(xrefs)
        for xref in xrefs:
            try:
                candidate_funcs.add(int(xref["function_addr"], 16))
            except Exception:
                continue
        item = {
            "value": value,
            "addr": _to_hex(int(s.ea)),
            "categories": tags,
            "xref_count": xref_count,
            "xrefs": xrefs,
            "evidence": [
                _evidence(
                    source_file,
                    "string_classifier",
                    address=int(s.ea),
                    snippet=value[:200],
                    confidence=_confidence(3 if "route" in tags else 2),
                )
            ],
        }
        interesting.append(item)
        if "route" in tags:
            routes.append(
                {
                    "route": value,
                    "route_type": "string_literal",
                    "source": "ida_string",
                    "evidence": item["evidence"],
                }
            )
        if "auth" in tags:
            auth_hints.append(
                {
                    "hint": value,
                    "kind": "string",
                    "addr": _to_hex(int(s.ea)),
                    "evidence": item["evidence"],
                }
            )
        if "state" in tags:
            state_hints.append(
                {
                    "hint": value,
                    "kind": "string",
                    "addr": _to_hex(int(s.ea)),
                    "evidence": item["evidence"],
                }
            )
    return interesting, routes, auth_hints, state_hints, candidate_funcs


def _record_api_xrefs(
    source_file: str,
    api_names: Iterable[str],
    parser_name: str,
    default_category: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Set[int]]:
    symbol_map = _resolve_symbol_addresses(api_names)
    rows: List[Dict[str, Any]] = []
    candidate_funcs: Set[int] = set()
    for api_name, ea in symbol_map.items():
        category = default_category or SINK_CATEGORIES.get(api_name, "unknown")
        for xref in idautils.XrefsTo(ea):
            func = _function_of(xref.frm)
            if not func:
                continue
            func_name = idc.get_func_name(func.start_ea)
            candidate_funcs.add(func.start_ea)
            rows.append(
                {
                    "api": api_name,
                    "category": category,
                    "function": func_name,
                    "function_addr": _to_hex(func.start_ea),
                    "xref_addr": _to_hex(xref.frm),
                    "snippet": _snippet_for_ea(xref.frm),
                    "evidence": [
                        _evidence(
                            source_file,
                            parser_name,
                            address=xref.frm,
                            function=func_name,
                            snippet=_snippet_for_ea(xref.frm),
                            confidence="high",
                        )
                    ],
                }
            )
    return rows, candidate_funcs


def _extract_handler_like_functions(source_file: str, candidate_funcs: Set[int]) -> List[Dict[str, Any]]:
    handlers: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for func_ea in sorted(candidate_funcs):
        name = idc.get_func_name(func_ea)
        if func_ea in seen:
            continue
        if not any(pattern.search(name) for pattern in HANDLER_PATTERNS):
            continue
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        seen.add(func_ea)
        handlers.append(
            {
                "name": name,
                "addr": _to_hex(func_ea),
                "size": func.end_ea - func.start_ea,
                "source": "function_name",
                "evidence": [
                    _evidence(
                        source_file,
                        "handler_name",
                        address=func_ea,
                        function=name,
                        snippet=name,
                        confidence="medium",
                    )
                ],
            }
        )
    return handlers


def _extract_from_pseudocode(
    source_file: str,
    candidate_funcs: Set[int],
    *,
    max_candidate_functions: int,
    max_snippet_lines: int,
) -> Dict[str, Any]:
    params: List[Dict[str, Any]] = []
    constraints: List[Dict[str, Any]] = []
    config_accesses: List[Dict[str, Any]] = []
    route_mappings: List[Dict[str, Any]] = []
    handlers: List[Dict[str, Any]] = []
    pseudo_snippets: List[Dict[str, Any]] = []
    seen_params: Set[Tuple[str, str, str]] = set()
    seen_constraints: Set[Tuple[str, str, str, str]] = set()
    seen_configs: Set[Tuple[str, str, str]] = set()
    seen_routes: Set[Tuple[str, str]] = set()
    seen_handlers: Set[str] = set()

    for func_ea in sorted(candidate_funcs)[:max_candidate_functions]:
        func_name = idc.get_func_name(func_ea)
        pseudocode = _decompile(func_ea)
        if not pseudocode:
            continue
        lines = pseudocode.splitlines()
        interesting_lines = [
            line.strip()
            for line in lines
            if any(token in line for token in ("GetVar", "get_cgi", "nvram_", "uci_", "apmib_", "cgi", "login", "apply", "reboot", "upgrade", "system(", "popen(", "strcpy(", "sprintf("))
        ]
        if interesting_lines:
            pseudo_snippets.append(
                {
                    "function": func_name,
                    "function_addr": _to_hex(func_ea),
                    "snippet": "\n".join(interesting_lines[:max_snippet_lines]),
                }
            )
        if func_name not in seen_handlers and any(pattern.search(func_name) for pattern in HANDLER_PATTERNS):
            seen_handlers.add(func_name)
            handlers.append(
                {
                    "name": func_name,
                    "addr": _to_hex(func_ea),
                    "source": "decompile_candidate",
                    "evidence": [
                        _evidence(
                            source_file,
                            "decompile_candidate",
                            address=func_ea,
                            function=func_name,
                            snippet=func_name,
                            confidence="medium",
                        )
                    ],
                }
            )
        for match in PARAM_CALL_RE.finditer(pseudocode):
            api = match.group("api")
            args = match.group("args")
            literals = _string_literals(args)
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
                    "source": "pseudocode",
                    "function": func_name,
                    "function_addr": _to_hex(func_ea),
                    "evidence": [
                        _evidence(
                            source_file,
                            "param_reader",
                            address=func_ea,
                            function=func_name,
                            snippet=match.group(0)[:240],
                            confidence="high" if api != "getenv" else "medium",
                        )
                    ],
                }
            )
        for match in CONFIG_CALL_RE.finditer(pseudocode):
            api = match.group("api")
            args = match.group("args")
            literals = _string_literals(args)
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
                    "source": "pseudocode",
                    "function": func_name,
                    "function_addr": _to_hex(func_ea),
                    "evidence": [
                        _evidence(
                            source_file,
                            "config_access",
                            address=func_ea,
                            function=func_name,
                            snippet=match.group(0)[:240],
                            confidence="high",
                        )
                    ],
                }
            )
        for match in REGISTER_CALL_RE.finditer(pseudocode):
            api = match.group("api")
            args = match.group("args")
            literals = _string_literals(args)
            route = literals[0] if literals else None
            handler_name_match = re.search(r",\s*([A-Za-z_]\w+)\s*\)?", args)
            handler_name = handler_name_match.group(1) if handler_name_match else func_name
            if not route:
                continue
            key = (route, handler_name)
            if key in seen_routes:
                continue
            seen_routes.add(key)
            route_mappings.append(
                {
                    "route": route,
                    "handler": handler_name,
                    "handler_addr": _to_hex(func_ea) if handler_name == func_name else None,
                    "registration_api": api,
                    "source": "pseudocode",
                    "confidence": "high",
                    "evidence": [
                        _evidence(
                            source_file,
                            "handler_registration",
                            address=func_ea,
                            function=func_name,
                            snippet=match.group(0)[:240],
                            confidence="high",
                        )
                    ],
                }
            )
        for kind, pattern in CONSTRAINT_PATTERNS:
            for match in pattern.finditer(pseudocode):
                target = match.groupdict().get("target") or match.groupdict().get("expr") or ""
                value = match.groupdict().get("value") or match.groupdict().get("api") or ""
                op = match.groupdict().get("op")
                key = (func_name, kind, target, value)
                if key in seen_constraints:
                    continue
                seen_constraints.add(key)
                item: Dict[str, Any] = {
                    "kind": kind,
                    "target": target,
                    "value": value,
                    "function": func_name,
                    "function_addr": _to_hex(func_ea),
                    "source": "pseudocode",
                    "evidence": [
                        _evidence(
                            source_file,
                            "constraint",
                            address=func_ea,
                            function=func_name,
                            snippet=match.group(0)[:240],
                            confidence="medium",
                        )
                    ],
                }
                if op:
                    item["operator"] = op
                constraints.append(item)

    return {
        "params": params,
        "constraints": constraints,
        "config_accesses": config_accesses,
        "route_mappings": route_mappings,
        "handlers": handlers,
        "pseudo_snippets": pseudo_snippets,
    }


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


def _functions_summary(candidate_funcs: Set[int]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for func_ea in sorted(candidate_funcs):
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        callers = len(list(idautils.CodeRefsTo(func.start_ea, False)))
        callees_seen: Set[int] = set()
        for item in _iter_function_items(func):
            for callee in idautils.CodeRefsFrom(item, False):
                callee_func = ida_funcs.get_func(callee)
                if callee_func:
                    callees_seen.add(callee_func.start_ea)
        rows.append(
            {
                "name": idc.get_func_name(func.start_ea),
                "addr": _to_hex(func.start_ea),
                "size": func.end_ea - func.start_ea,
                "caller_count": callers,
                "callee_count": len(callees_seen),
            }
        )
    return rows


def build_artifact(
    *,
    source_file: str,
    max_strings: int,
    max_string_xrefs: int,
    max_candidate_functions: int,
    max_snippet_lines: int,
) -> Dict[str, Any]:
    ida_auto.auto_wait()
    input_path = Path(idc.get_input_file_path()).resolve()
    info = ida_ida.inf_get_procname()
    bitness = ida_ida.inf_get_app_bitness()
    endian = "big" if ida_ida.inf_is_be() else "little"

    interesting_strings, routes, auth_hints, state_hints, string_candidate_funcs = _collect_strings(
        source_file,
        max_strings=max_strings,
        max_xrefs=max_string_xrefs,
    )
    sink_rows, sink_candidate_funcs = _record_api_xrefs(source_file, SINK_CATEGORIES.keys(), "sink_xref")
    param_rows, param_candidate_funcs = _record_api_xrefs(source_file, PARAM_READERS, "param_reader_xref", default_category="param_reader")
    config_rows, config_candidate_funcs = _record_api_xrefs(source_file, CONFIG_APIS, "config_xref", default_category="config")

    candidate_funcs = set()
    candidate_funcs.update(_candidate_functions_from_names())
    candidate_funcs.update(string_candidate_funcs)
    candidate_funcs.update(sink_candidate_funcs)
    candidate_funcs.update(param_candidate_funcs)
    candidate_funcs.update(config_candidate_funcs)

    decompiled = _extract_from_pseudocode(
        source_file,
        candidate_funcs,
        max_candidate_functions=max_candidate_functions,
        max_snippet_lines=max_snippet_lines,
    )

    handlers = _extract_handler_like_functions(source_file, candidate_funcs)
    handlers.extend(decompiled["handlers"])
    handlers = _dedupe_dict_items(handlers, ("name", "addr"))

    params = []
    for row in param_rows:
        params.append(
            {
                "name": row["api"],
                "reader_api": row["api"],
                "source": "xrefs",
                "function": row["function"],
                "function_addr": row["function_addr"],
                "evidence": row["evidence"],
            }
        )
    params.extend(decompiled["params"])
    params = _dedupe_dict_items(params, ("name", "reader_api", "function_addr"))

    config_accesses = []
    for row in config_rows:
        config_accesses.append(
            {
                "api": row["api"],
                "access_type": "write" if row["api"].endswith(("_set", "_commit", "_unset")) else "read",
                "source": "xrefs",
                "function": row["function"],
                "function_addr": row["function_addr"],
                "evidence": row["evidence"],
            }
        )
    config_accesses.extend(decompiled["config_accesses"])
    config_accesses = _dedupe_dict_items(config_accesses, ("api", "key", "function_addr"))

    route_mappings = list(decompiled["route_mappings"])
    for string_item in interesting_strings:
        if "route" not in string_item["categories"]:
            continue
        for ref in string_item["xrefs"][:6]:
            confidence_rank = 2
            if ROUTE_NAME_RE.search(ref["function"]):
                confidence_rank = 3
            route_mappings.append(
                {
                    "route": string_item["value"],
                    "handler": ref["function"],
                    "handler_addr": ref["function_addr"],
                    "source": "string_xref",
                    "confidence": _confidence(confidence_rank),
                    "evidence": [
                        _evidence(
                            source_file,
                            "string_xref",
                            address=int(ref["xref_addr"], 16),
                            function=ref["function"],
                            snippet=ref["snippet"],
                            confidence=_confidence(confidence_rank),
                        )
                    ],
                }
            )
    route_mappings = _dedupe_dict_items(route_mappings, ("route", "handler", "handler_addr"))

    response_strings = [
        {
            "value": item["value"],
            "addr": item["addr"],
            "evidence": item["evidence"],
        }
        for item in interesting_strings
        if "response" in item["categories"]
    ]

    xrefs: List[Dict[str, Any]] = []
    for row in sink_rows + param_rows + config_rows:
        xrefs.append(
            {
                "kind": row["category"],
                "api": row["api"],
                "function": row["function"],
                "function_addr": row["function_addr"],
                "xref_addr": row["xref_addr"],
                "snippet": row["snippet"],
            }
        )

    callgraph_edges = _collect_callgraph_edges(candidate_funcs)
    functions = _functions_summary(candidate_funcs)
    sink_rows = _dedupe_dict_items(sink_rows, ("api", "function_addr", "xref_addr"))
    constraints = _dedupe_dict_items(decompiled["constraints"], ("kind", "target", "function_addr", "value"))
    routes = _dedupe_dict_items(routes, ("route", "route_type"))
    auth_hints = _dedupe_dict_items(auth_hints, ("hint", "addr"))
    state_hints = _dedupe_dict_items(state_hints, ("hint", "addr"))

    keyword_counter = Counter()
    for hint in auth_hints:
        keyword_counter["auth"] += 1
    for hint in state_hints:
        keyword_counter["state"] += 1
    for item in response_strings:
        keyword_counter["response"] += 1

    artifact: Dict[str, Any] = {
        "version": "1.0",
        "artifact_type": "web_backend_binary",
        "input_type": "unreadable_web_backend_binary",
        "binary": {
            "source_file": str(input_path),
            "idb_path": ida_nalt.get_input_file_path(),
            "sha256": _sha256_file(input_path),
            "size": input_path.stat().st_size,
            "format": ida_loader.get_file_type_name() if "ida_loader" in globals() else "",
            "arch": info,
            "bits": bitness,
            "endian": endian,
            "entry": _to_hex(ida_ida.inf_get_start_ea()),
            "segments": _collect_segments(),
        },
        "routes": routes,
        "handlers": handlers,
        "route_mappings": route_mappings,
        "params": params,
        "constraints": constraints,
        "config_accesses": config_accesses,
        "sinks": sink_rows,
        "response_strings": response_strings,
        "auth_hints": auth_hints,
        "state_hints": state_hints,
        "strings": interesting_strings,
        "functions": functions,
        "xrefs": xrefs,
        "callgraph_edges": callgraph_edges,
        "analysis_warnings": [],
        "summary": {
            "route_count": len(routes),
            "handler_count": len(handlers),
            "route_mapping_count": len(route_mappings),
            "param_count": len(params),
            "constraint_count": len(constraints),
            "config_access_count": len(config_accesses),
            "sink_count": len(sink_rows),
            "response_string_count": len(response_strings),
            "interesting_string_count": len(interesting_strings),
            "candidate_function_count": len(functions),
            "hint_categories": dict(keyword_counter),
        },
        "pseudo_snippets": decompiled["pseudo_snippets"],
    }
    return artifact


def _write_output(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Extract web backend facts from the current IDA database")
    parser.add_argument("--output", type=Path, required=True, help="Artifact output JSON path")
    parser.add_argument("--max-strings", type=int, default=20000, help="Maximum strings to inspect")
    parser.add_argument("--max-string-xrefs", type=int, default=8, help="Maximum xrefs stored per string")
    parser.add_argument("--max-candidate-functions", type=int, default=180, help="Maximum candidate functions to decompile")
    parser.add_argument("--max-snippet-lines", type=int, default=12, help="Maximum pseudocode lines to store per function")
    args = parser.parse_args(argv)

    source_file = str(Path(idc.get_input_file_path()).resolve())
    artifact = build_artifact(
        source_file=source_file,
        max_strings=args.max_strings,
        max_string_xrefs=args.max_string_xrefs,
        max_candidate_functions=args.max_candidate_functions,
        max_snippet_lines=args.max_snippet_lines,
    )
    _write_output(args.output, artifact)
    print(f"[extract_web_facts] Wrote artifact to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
