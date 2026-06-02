#!/usr/bin/env python3
"""Export full intermediate binary context from the current IDA database."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_lines
    import ida_loader
    import ida_nalt
    import ida_segment
    import idautils
    import idc
except ImportError as exc:  # pragma: no cover - must run in IDA
    raise SystemExit(f"This script must run inside IDA Python: {exc}") from exc


def _to_hex(ea: int) -> str:
    return f"0x{ea:x}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _disasm_line(ea: int) -> str:
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "") or ""


def _instruction_bytes_hex(ea: int) -> str:
    size = idc.get_item_size(ea)
    if size <= 0:
        return ""
    raw = ida_bytes.get_bytes(ea, size) or b""
    return raw.hex()


def _collect_segments() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    index = 0
    while True:
        seg = ida_segment.getnseg(index)
        if seg is None:
            break
        rows.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": _to_hex(seg.start_ea),
                "end": _to_hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "perm": seg.perm,
            }
        )
        index += 1
    return rows


def _collect_imports() -> Tuple[List[Dict[str, Any]], Dict[int, Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    by_addr: Dict[int, Dict[str, Any]] = {}
    qty = ida_nalt.get_import_module_qty()
    for module_index in range(qty):
        module_name = ida_nalt.get_import_module_name(module_index) or f"module_{module_index}"

        def _callback(ea: int, name: Optional[str], ordinal: int) -> bool:
            row = {
                "module": module_name,
                "name": name or f"ord_{ordinal}",
                "ordinal": ordinal,
                "addr": _to_hex(ea),
            }
            rows.append(row)
            by_addr[ea] = row
            return True

        ida_nalt.enum_import_names(module_index, _callback)
    return rows, by_addr


def _collect_exports() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, ordinal, ea, name in idautils.Entries():
        rows.append(
            {
                "index": index,
                "ordinal": ordinal,
                "addr": _to_hex(ea),
                "name": name,
            }
        )
    return rows


def _collect_names() -> List[Dict[str, Any]]:
    return [{"addr": _to_hex(ea), "name": name} for ea, name in idautils.Names()]


def _collect_strings(min_string_len: int) -> Tuple[List[Dict[str, Any]], Set[int]]:
    rows: List[Dict[str, Any]] = []
    string_addrs: Set[int] = set()
    strings_db = idautils.Strings()
    strings_db.setup(minlen=min_string_len)
    for item in strings_db:
        ea = int(item.ea)
        xrefs = []
        seen_xrefs: Set[Tuple[int, int]] = set()
        for xref in idautils.XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            function_addr = _to_hex(func.start_ea) if func else None
            function_name = idc.get_func_name(func.start_ea) if func else None
            key = (xref.frm, func.start_ea if func else -1)
            if key in seen_xrefs:
                continue
            seen_xrefs.add(key)
            xrefs.append(
                {
                    "xref_addr": _to_hex(xref.frm),
                    "function_addr": function_addr,
                    "function_name": function_name,
                    "snippet": _disasm_line(xref.frm),
                    "xref_type": int(xref.type),
                }
            )
        rows.append(
            {
                "addr": _to_hex(ea),
                "length": len(str(item)),
                "type": int(item.strtype),
                "value": str(item),
                "xrefs": xrefs,
            }
        )
        string_addrs.add(ea)
    return rows, string_addrs


def _decompile_function(func_ea: int) -> Tuple[Optional[str], Optional[str]]:
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None, "hexrays_unavailable"
    except Exception as exc:
        return None, f"hexrays_init_failed:{exc}"
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as exc:
        return None, f"decompile_failed:{exc}"
    if not cfunc:
        return None, "decompile_returned_none"
    try:
        return str(cfunc), None
    except Exception as exc:
        return None, f"decompile_to_string_failed:{exc}"


def _iter_function_items(func: ida_funcs.func_t) -> Iterable[int]:
    for ea in idautils.FuncItems(func.start_ea):
        yield ea


def _collect_functions(
    *,
    string_addrs: Set[int],
    imports_by_addr: Dict[int, Dict[str, Any]],
    include_pseudocode: bool,
    include_disassembly: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    functions: List[Dict[str, Any]] = []
    callgraph_edges: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        func_name = idc.get_func_name(func_ea)
        caller_rows: List[Dict[str, Any]] = []
        callee_rows: List[Dict[str, Any]] = []
        string_refs: List[Dict[str, Any]] = []
        import_refs: List[Dict[str, Any]] = []
        data_refs: List[Dict[str, Any]] = []
        disassembly: List[Dict[str, Any]] = []
        seen_callers: Set[Tuple[int, int]] = set()
        seen_callees: Set[Tuple[int, int]] = set()
        seen_strings: Set[Tuple[int, int]] = set()
        seen_imports: Set[Tuple[int, int]] = set()
        seen_data_refs: Set[Tuple[int, int]] = set()

        for caller_ea in idautils.CodeRefsTo(func.start_ea, False):
            caller_func = ida_funcs.get_func(caller_ea)
            if not caller_func:
                continue
            key = (caller_func.start_ea, caller_ea)
            if key in seen_callers:
                continue
            seen_callers.add(key)
            caller_rows.append(
                {
                    "function_addr": _to_hex(caller_func.start_ea),
                    "function_name": idc.get_func_name(caller_func.start_ea),
                    "callsite": _to_hex(caller_ea),
                    "snippet": _disasm_line(caller_ea),
                }
            )

        for item_ea in _iter_function_items(func):
            if include_disassembly:
                disassembly.append(
                    {
                        "addr": _to_hex(item_ea),
                        "size": idc.get_item_size(item_ea),
                        "bytes": _instruction_bytes_hex(item_ea),
                        "text": _disasm_line(item_ea),
                    }
                )

            for callee_ea in idautils.CodeRefsFrom(item_ea, False):
                callee_func = ida_funcs.get_func(callee_ea)
                if callee_func:
                    key = (callee_func.start_ea, item_ea)
                    if key not in seen_callees:
                        seen_callees.add(key)
                        callee_rows.append(
                            {
                                "function_addr": _to_hex(callee_func.start_ea),
                                "function_name": idc.get_func_name(callee_func.start_ea),
                                "callsite": _to_hex(item_ea),
                                "snippet": _disasm_line(item_ea),
                            }
                        )
                        callgraph_edges.append(
                            {
                                "caller": func_name,
                                "caller_addr": _to_hex(func.start_ea),
                                "callee": idc.get_func_name(callee_func.start_ea),
                                "callee_addr": _to_hex(callee_func.start_ea),
                                "callsite": _to_hex(item_ea),
                            }
                        )
                import_meta = imports_by_addr.get(callee_ea)
                if import_meta:
                    key = (callee_ea, item_ea)
                    if key not in seen_imports:
                        seen_imports.add(key)
                        import_refs.append(
                            {
                                "name": import_meta["name"],
                                "module": import_meta["module"],
                                "import_addr": import_meta["addr"],
                                "xref_addr": _to_hex(item_ea),
                                "snippet": _disasm_line(item_ea),
                            }
                        )

            for data_ea in idautils.DataRefsFrom(item_ea):
                if data_ea in string_addrs:
                    key = (data_ea, item_ea)
                    if key in seen_strings:
                        continue
                    seen_strings.add(key)
                    string_refs.append(
                        {
                            "string_addr": _to_hex(data_ea),
                            "xref_addr": _to_hex(item_ea),
                            "snippet": _disasm_line(item_ea),
                        }
                    )
                    continue
                name = idc.get_name(data_ea)
                if not name:
                    continue
                key = (data_ea, item_ea)
                if key in seen_data_refs:
                    continue
                seen_data_refs.add(key)
                data_refs.append(
                    {
                        "target_addr": _to_hex(data_ea),
                        "target_name": name,
                        "xref_addr": _to_hex(item_ea),
                        "snippet": _disasm_line(item_ea),
                    }
                )

        pseudocode = None
        decompile_error = None
        if include_pseudocode:
            pseudocode, decompile_error = _decompile_function(func.start_ea)
            if decompile_error:
                warnings.append(
                    {
                        "level": "warning",
                        "kind": "decompile",
                        "function_addr": _to_hex(func.start_ea),
                        "function_name": func_name,
                        "message": decompile_error,
                    }
                )

        functions.append(
            {
                "addr": _to_hex(func.start_ea),
                "name": func_name,
                "start_ea": _to_hex(func.start_ea),
                "end_ea": _to_hex(func.end_ea),
                "size": func.end_ea - func.start_ea,
                "prototype": idc.get_type(func.start_ea),
                "flags": int(func.flags),
                "segment": idc.get_segm_name(func.start_ea),
                "callers": caller_rows,
                "callees": callee_rows,
                "string_refs": string_refs,
                "import_refs": import_refs,
                "data_refs": data_refs,
                "disassembly": disassembly,
                "pseudocode": pseudocode,
                "decompile_error": decompile_error,
            }
        )

    return functions, callgraph_edges, warnings


def _artifact_summary(
    *,
    imports: List[Dict[str, Any]],
    exports: List[Dict[str, Any]],
    names: List[Dict[str, Any]],
    strings: List[Dict[str, Any]],
    functions: List[Dict[str, Any]],
    callgraph_edges: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "import_count": len(imports),
        "export_count": len(exports),
        "name_count": len(names),
        "string_count": len(strings),
        "function_count": len(functions),
        "callgraph_edge_count": len(callgraph_edges),
    }


def build_artifact(
    *,
    include_pseudocode: bool,
    include_disassembly: bool,
    min_string_len: int,
) -> Dict[str, Any]:
    ida_auto.auto_wait()
    input_path = Path(idc.get_input_file_path()).resolve()
    imports, imports_by_addr = _collect_imports()
    exports = _collect_exports()
    names = _collect_names()
    strings, string_addrs = _collect_strings(min_string_len)
    functions, callgraph_edges, warnings = _collect_functions(
        string_addrs=string_addrs,
        imports_by_addr=imports_by_addr,
        include_pseudocode=include_pseudocode,
        include_disassembly=include_disassembly,
    )
    binary = {
        "source_file": str(input_path),
        "idb_path": str(input_path),
        "sha256": _sha256_file(input_path),
        "size": input_path.stat().st_size,
        "format": ida_loader.get_file_type_name(),
        "arch": ida_ida.inf_get_procname(),
        "bits": ida_ida.inf_get_app_bitness(),
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "entry": _to_hex(ida_ida.inf_get_start_ea()),
        "segments": _collect_segments(),
    }
    return {
        "version": "1.0",
        "artifact_type": "web_backend_binary_preprocessed",
        "input_type": "unreadable_web_backend_binary",
        "binary": binary,
        "imports": imports,
        "exports": exports,
        "names": names,
        "strings": strings,
        "functions": functions,
        "callgraph_edges": callgraph_edges,
        "analysis_warnings": warnings,
        "summary": _artifact_summary(
            imports=imports,
            exports=exports,
            names=names,
            strings=strings,
            functions=functions,
            callgraph_edges=callgraph_edges,
        ),
    }


def _parse_args_from_ida(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export full intermediate binary context from IDA")
    parser.add_argument("--output", type=Path, required=True, help="Output preprocess JSON path")
    parser.add_argument("--min-string-len", type=int, default=4, help="Minimum string length to export")
    parser.add_argument("--include-pseudocode", action="store_true", help="Export full pseudocode for every function")
    parser.add_argument("--include-disassembly", action="store_true", help="Export full disassembly for every function")
    return parser.parse_args(list(argv))


def _ida_script_argv() -> List[str]:
    ida_argv = list(getattr(idc, "ARGV", []) or [])
    if len(ida_argv) > 1:
        return ida_argv[1:]
    return sys.argv[1:]


def main() -> int:
    args = _parse_args_from_ida(_ida_script_argv())
    artifact = build_artifact(
        include_pseudocode=args.include_pseudocode,
        include_disassembly=args.include_disassembly,
        min_string_len=args.min_string_len,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[export_full_context] Wrote preprocess artifact to: {args.output}")
    return 0


if __name__ == "__main__":
    exit_code = 1
    try:
        exit_code = main()
    except Exception as exc:  # pragma: no cover - IDA runtime behavior
        print(f"[export_full_context] Fatal error: {exc}")
        raise
    finally:
        try:
            idc.qexit(exit_code)
        except Exception:
            pass
