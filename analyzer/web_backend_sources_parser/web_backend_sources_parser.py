#!/usr/bin/env python3
"""Parse readable backend source JSON artifacts into structured backend facts."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_INPUT_GLOB = "output/web_json/*/web_backend_sources.readable.json"
FALLBACK_INPUT_GLOB = "collector/output/web_json/*/web_backend_sources.readable.json"
DEFAULT_OUTPUT_DIR = Path("analyzer/web_backend_sources_parser/output")


def _line_snippet(line: str, limit: int = 220) -> str:
    snippet = line.strip()
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 3] + "..."


def make_evidence(
    source_file: str, parser: str, pattern: str, line: int, snippet: str
) -> Dict[str, Any]:
    return {
        "source_file": source_file,
        "parser": parser,
        "pattern": pattern,
        "line": line,
        "snippet": snippet,
    }


def first_string_literal(text: str) -> Optional[str]:
    match = re.search(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    if not match:
        return None
    return match.group(1)


def infer_param_source(api_name: str, param_name: str, line_text: str) -> str:
    lowered_api = api_name.lower()
    lowered_line = line_text.lower()
    lowered_param = param_name.lower()
    if "cookie" in lowered_api or "cookie" in lowered_line or "cookie" in lowered_param:
        return "cookie"
    if "header" in lowered_api or "http_" in lowered_param:
        return "header"
    if "env" in lowered_api or "getenv" in lowered_api:
        return "env"
    if "query" in lowered_api or "query_string" in lowered_line:
        return "query"
    if "form" in lowered_api or "post" in lowered_api or "body" in lowered_api:
        return "body"
    return "unknown"


@dataclass(frozen=True)
class Pattern:
    parser: str
    kind: str
    regex: re.Pattern[str]


HANDLER_PATTERNS: Sequence[Pattern] = (
    Pattern(
        "handler_parser",
        "registration",
        re.compile(
            r'\bwebsFormDefine\s*\(\s*"(?P<route>[^"]+)"\s*,\s*(?P<handler>[A-Za-z_]\w*)',
        ),
    ),
    Pattern(
        "handler_parser",
        "registration",
        re.compile(
            r'\bwebsUrlHandlerDefine\s*\(\s*"(?P<route>[^"]+)"[^,]*,\s*(?P<handler>[A-Za-z_]\w*)',
        ),
    ),
    Pattern(
        "handler_parser",
        "registration",
        re.compile(
            r'\bcgi_register\s*\(\s*"(?P<route>[^"]+)"\s*,\s*(?P<handler>[A-Za-z_]\w*)',
        ),
    ),
    Pattern(
        "handler_parser",
        "registration",
        re.compile(
            r'\bregister_handler\s*\(\s*"(?P<route>[^"]+)"\s*,\s*(?P<handler>[A-Za-z_]\w*)',
        ),
    ),
    Pattern(
        "handler_parser",
        "dispatch_table",
        re.compile(
            r'\{\s*"(?P<route>[^"]+)"\s*,\s*(?P<handler>[A-Za-z_]\w*)\s*\}',
        ),
    ),
    Pattern(
        "handler_parser",
        "handler_symbol",
        re.compile(
            r"\b(?:int|void|char\s*\*)\s+(?P<handler>[A-Za-z_]\w*(?:_cgi|_handler|_asp|_form|_apply|_submit))\s*\(",
        ),
    ),
)


ROUTE_PATTERNS: Sequence[Pattern] = (
    Pattern(
        "route_parser",
        "url_literal",
        re.compile(
            r'"(?P<route>/(?:goform|cgi-bin|api|hnap1|HNAP1)[^"]*)"',
        ),
    ),
    Pattern(
        "route_parser",
        "cgi_asp_stm_literal",
        re.compile(
            r'"(?P<route>[^"]+\.(?:cgi|asp|stm)(?:\?[^"]*)?)"',
        ),
    ),
    Pattern(
        "route_parser",
        "dispatch_key_value",
        re.compile(
            r'"(?P<dispatch_key>action|cmd|page|handler|module)"\s*[,=]\s*"(?P<route>[^"]+)"',
            re.IGNORECASE,
        ),
    ),
    Pattern(
        "route_parser",
        "location_header",
        re.compile(r'"Location:\s*(?P<route>[^"]+)"', re.IGNORECASE),
    ),
)


PARAM_PATTERNS: Sequence[Pattern] = (
    Pattern(
        "param_read_parser",
        "websGetVar",
        re.compile(
            r'\b(?P<api>websGetVar2?|cgiFormString|cgiFormInteger|cgiFormDouble)\s*\(\s*[^,]*,\s*"(?P<param>[^"]+)"(?:\s*,\s*(?P<default>[^)\n]+))?',
        ),
    ),
    Pattern(
        "param_read_parser",
        "common_getter",
        re.compile(
            r'\b(?P<api>get_cgi|getVar|get_single|GetValue)\s*\(\s*"(?P<param>[^"]+)"(?:\s*,\s*(?P<default>[^)\n]+))?',
        ),
    ),
    Pattern(
        "param_read_parser",
        "getenv",
        re.compile(
            r'\b(?P<api>getenv)\s*\(\s*"(?P<param>QUERY_STRING|CONTENT_LENGTH|HTTP_COOKIE|REQUEST_METHOD|HTTP_[A-Z_]+)"\s*\)',
        ),
    ),
    Pattern(
        "param_read_parser",
        "custom_getter",
        re.compile(
            r'\b(?P<api>[A-Za-z_]\w*(?:get|cgi|param|query|form|cookie|header)[A-Za-z_]\w*)\s*\(\s*"(?P<param>[A-Za-z0-9_.:-]+)"',
            re.IGNORECASE,
        ),
    ),
)


CONSTRAINT_PATTERNS: Sequence[Pattern] = (
    Pattern(
        "constraint_parser",
        "int_cast",
        re.compile(
            r"\b(?P<api>atoi|atol|strtol|strtoul)\s*\(\s*(?P<target>[A-Za-z_]\w*)",
        ),
    ),
    Pattern(
        "constraint_parser",
        "strlen_compare",
        re.compile(
            r"\bstrlen\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*\)\s*(?P<op>[<>!=]=?)\s*(?P<value>\d+)",
        ),
    ),
    Pattern(
        "constraint_parser",
        "string_enum",
        re.compile(
            r"\b(?P<api>strcmp|strncmp|strcasecmp|strncasecmp)\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*,\s*\"(?P<value>[^\"]+)\"(?:\s*,\s*(?P<n>\d+))?",
        ),
    ),
    Pattern(
        "constraint_parser",
        "format_scan",
        re.compile(
            r'\bsscanf\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*,\s*"(?P<value>[^"]+)"',
        ),
    ),
    Pattern(
        "constraint_parser",
        "ip_format",
        re.compile(
            r"\b(?P<api>inet_addr|inet_aton)\s*\(\s*(?P<target>[A-Za-z_]\w*)",
        ),
    ),
    Pattern(
        "constraint_parser",
        "null_or_empty",
        re.compile(
            r"\bif\s*\(\s*(?P<expr>!\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*==\s*NULL|[A-Za-z_]\w*\s*!=\s*NULL)\s*\)",
        ),
    ),
    Pattern(
        "constraint_parser",
        "numeric_boundary",
        re.compile(
            r"\bif\s*\(\s*(?P<target>[A-Za-z_]\w*)\s*(?P<op>[<>]=?|==|!=)\s*(?P<value>-?\d+)\s*\)",
        ),
    ),
)


CONFIG_PATTERN = Pattern(
    "config_access_parser",
    "config_api",
    re.compile(
        r"\b(?P<api>nvram_(?:get|safe_get|set|unset|commit)|uci_(?:get|set|commit)|config_(?:get|set)|apmib_(?:get|set)|mib_(?:get|set))\s*\((?P<args>[^)]*)\)",
    ),
)


SINK_PATTERNS: Sequence[Tuple[str, re.Pattern[str]]] = (
    ("command", re.compile(r"\b(system|popen|execl|execv|execve|execvp|spawnl|spawnlp)\s*\(")),
    ("file", re.compile(r"\b(fopen|open|unlink|remove|rename|chmod|chown)\s*\(")),
    ("memory", re.compile(r"\b(strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|memcpy|memmove|gets)\s*\(")),
    ("network", re.compile(r"\b(socket|connect|send|recv)\s*\(")),
    ("config_state", re.compile(r"\b(nvram_commit|uci_commit|config_set|apmib_set|mib_set)\s*\(")),
    ("state", re.compile(r"\b(reboot|restart|reset|restore|upgrade|flash_write|apply)\w*\s*\(")),
)


AUTH_REGEX = re.compile(
    r"\b(login|logout|auth|admin|privilege|permission|password|passwd|pwd|session|sid|cookie|token|csrf|nonce|check_login|is_admin|auth_check)\b",
    re.IGNORECASE,
)
STATE_REGEX = re.compile(
    r"\b(apply|save|commit|reboot|restart|reset|restore|upgrade)\b",
    re.IGNORECASE,
)

INCLUDE_REGEX = re.compile(r'^\s*#\s*include\s+[<"](?P<include>[^>"]+)[>"]')
STRING_LITERAL_REGEX = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


class FactCollector:
    def __init__(self) -> None:
        self._facts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._seen: Dict[str, set[str]] = defaultdict(set)

    def add(self, bucket: str, fact: Dict[str, Any], dedupe_keys: Sequence[str]) -> None:
        dedupe_payload = {k: fact.get(k) for k in dedupe_keys}
        dedupe_key = json.dumps(dedupe_payload, sort_keys=True, ensure_ascii=False)
        if dedupe_key in self._seen[bucket]:
            return
        self._seen[bucket].add(dedupe_key)
        self._facts[bucket].append(fact)

    def get(self, bucket: str) -> List[Dict[str, Any]]:
        return self._facts.get(bucket, [])

    def counts(self) -> Dict[str, int]:
        return {bucket: len(values) for bucket, values in self._facts.items()}


def parse_file_content(
    source_file: str, content: str, collector: FactCollector, file_stats: Dict[str, int]
) -> None:
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        snippet = _line_snippet(line)

        for pattern in HANDLER_PATTERNS:
            match = pattern.regex.search(line)
            if not match:
                continue
            handler = match.groupdict().get("handler")
            route = match.groupdict().get("route")
            evidence = make_evidence(source_file, pattern.parser, pattern.kind, idx, snippet)
            if handler:
                collector.add(
                    "handlers",
                    {
                        "handler": handler,
                        "kind": pattern.kind,
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    ("handler", "kind", "source_file"),
                )
                file_stats["handlers"] += 1
            if route:
                collector.add(
                    "routes",
                    {
                        "route": route,
                        "kind": "handler_linked",
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    ("route", "kind", "source_file"),
                )
                collector.add(
                    "route_mappings",
                    {
                        "route": route,
                        "handler": handler,
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    ("route", "handler", "source_file"),
                )
                file_stats["routes"] += 1

        for pattern in ROUTE_PATTERNS:
            for match in pattern.regex.finditer(line):
                route = match.groupdict().get("route")
                if not route:
                    continue
                evidence = make_evidence(source_file, pattern.parser, pattern.kind, idx, snippet)
                collector.add(
                    "routes",
                    {
                        "route": route,
                        "kind": pattern.kind,
                        "dispatch_key": match.groupdict().get("dispatch_key"),
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    ("route", "kind", "dispatch_key", "source_file"),
                )
                file_stats["routes"] += 1

        for pattern in PARAM_PATTERNS:
            for match in pattern.regex.finditer(line):
                api = match.groupdict().get("api") or "unknown_api"
                param = match.groupdict().get("param")
                if not param:
                    continue
                default_value = match.groupdict().get("default")
                source = infer_param_source(api, param, line)
                evidence = make_evidence(source_file, pattern.parser, pattern.kind, idx, snippet)
                collector.add(
                    "params",
                    {
                        "param": param,
                        "read_api": api,
                        "param_source": source,
                        "default_value": default_value.strip() if default_value else None,
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    ("param", "read_api", "param_source", "default_value", "source_file"),
                )
                file_stats["params"] += 1

        for pattern in CONSTRAINT_PATTERNS:
            for match in pattern.regex.finditer(line):
                target = match.groupdict().get("target")
                evidence = make_evidence(source_file, pattern.parser, pattern.kind, idx, snippet)
                collector.add(
                    "constraints",
                    {
                        "constraint_type": pattern.kind,
                        "api": match.groupdict().get("api"),
                        "target": target,
                        "operator": match.groupdict().get("op"),
                        "value": match.groupdict().get("value"),
                        "extra": match.groupdict().get("expr") or match.groupdict().get("n"),
                        "source_file": source_file,
                        "evidence": evidence,
                    },
                    (
                        "constraint_type",
                        "api",
                        "target",
                        "operator",
                        "value",
                        "extra",
                        "source_file",
                    ),
                )
                file_stats["constraints"] += 1

        config_match = CONFIG_PATTERN.regex.search(line)
        if config_match:
            api = config_match.group("api")
            args = config_match.group("args")
            key = first_string_literal(args)
            access_type = "commit" if api.endswith("commit") else ("set" if "_set" in api else "get")
            evidence = make_evidence(
                source_file, CONFIG_PATTERN.parser, CONFIG_PATTERN.kind, idx, snippet
            )
            collector.add(
                "config_accesses",
                {
                    "api": api,
                    "access_type": access_type,
                    "config_key": key,
                    "raw_args": args.strip(),
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("api", "access_type", "config_key", "raw_args", "source_file"),
            )
            file_stats["config_accesses"] += 1

        for category, regex in SINK_PATTERNS:
            sink_match = regex.search(line)
            if not sink_match:
                continue
            api = sink_match.group(1)
            evidence = make_evidence(source_file, "sink_parser", category, idx, snippet)
            collector.add(
                "sinks",
                {
                    "sink_category": category,
                    "api": api,
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("sink_category", "api", "source_file"),
            )
            file_stats["sinks"] += 1

        for match in AUTH_REGEX.finditer(line):
            keyword = match.group(1)
            evidence = make_evidence(source_file, "auth_state_parser", "auth_keyword", idx, snippet)
            collector.add(
                "auth_hints",
                {
                    "keyword": keyword,
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("keyword", "source_file", "evidence"),
            )
            file_stats["auth_hints"] += 1

        for match in STATE_REGEX.finditer(line):
            keyword = match.group(1)
            evidence = make_evidence(
                source_file, "auth_state_parser", "state_keyword", idx, snippet
            )
            collector.add(
                "state_hints",
                {
                    "keyword": keyword,
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("keyword", "source_file", "evidence"),
            )
            file_stats["state_hints"] += 1

        include_match = INCLUDE_REGEX.search(line)
        if include_match:
            include_path = include_match.group("include")
            evidence = make_evidence(
                source_file, "string_reference_parser", "include_reference", idx, snippet
            )
            collector.add(
                "references",
                {
                    "reference_type": "include",
                    "value": include_path,
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("reference_type", "value", "source_file"),
            )
            file_stats["references"] += 1

        for string_match in STRING_LITERAL_REGEX.finditer(line):
            value = string_match.group(1)
            if len(value.strip()) < 4:
                continue
            lowered = value.lower()
            if any(token in lowered for token in ("error", "fail", "invalid", "unauthorized")):
                string_type = "error_hint"
            elif any(token in lowered for token in ("success", "ok", "done")):
                string_type = "success_hint"
            elif value.startswith("/"):
                string_type = "path_or_route"
            else:
                string_type = "generic"
            evidence = make_evidence(
                source_file, "string_reference_parser", "string_literal", idx, snippet
            )
            collector.add(
                "strings",
                {
                    "string": value,
                    "string_type": string_type,
                    "source_file": source_file,
                    "evidence": evidence,
                },
                ("string", "string_type", "source_file"),
            )
            file_stats["strings"] += 1


def parse_artifact(input_path: Path) -> Dict[str, Any]:
    with input_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    warnings: List[Dict[str, Any]] = []
    input_type = data.get("input_type")
    if input_type != "web_backend_sources":
        warnings.append(
            {
                "type": "unexpected_input_type",
                "message": f"Expected input_type=web_backend_sources, got {input_type!r}",
            }
        )

    files = data.get("files")
    if not isinstance(files, list):
        raise ValueError("Input JSON must contain a 'files' list.")

    collector = FactCollector()
    file_entries: List[Dict[str, Any]] = []
    parsed_files = 0
    skipped_files = 0

    for entry in files:
        source_file = entry.get("source_file")
        content = entry.get("content")
        if not isinstance(source_file, str) or not isinstance(content, str):
            skipped_files += 1
            warnings.append(
                {
                    "type": "invalid_file_entry",
                    "message": "files[] item missing string source_file/content",
                }
            )
            continue

        parsed_files += 1
        file_stats: Dict[str, int] = defaultdict(int)
        parse_file_content(source_file, content, collector, file_stats)
        file_entries.append(
            {
                "source_file": source_file,
                "line_count": len(content.splitlines()),
                "counts": dict(file_stats),
            }
        )

    summary = {
        "parsed_files": parsed_files,
        "skipped_files": skipped_files,
        "total_files_in_input": len(files),
        "counts": collector.counts(),
    }

    return {
        "version": "1.0",
        "input_type": "web_backend_sources",
        "artifact_type": "web_backend_sources",
        "source_count": parsed_files,
        "files": file_entries,
        "handlers": collector.get("handlers"),
        "routes": collector.get("routes"),
        "route_mappings": collector.get("route_mappings"),
        "params": collector.get("params"),
        "constraints": collector.get("constraints"),
        "config_accesses": collector.get("config_accesses"),
        "sinks": collector.get("sinks"),
        "auth_hints": collector.get("auth_hints"),
        "state_hints": collector.get("state_hints"),
        "strings": collector.get("strings"),
        "references": collector.get("references"),
        "parse_warnings": warnings,
        "summary": summary,
    }


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def default_output_for_input(input_path: Path, output_dir: Path) -> Path:
    parent_name = input_path.parent.name if input_path.parent.name else "root"
    stem = input_path.name.replace(".readable.json", "")
    file_name = f"{parent_name}.{stem}.artifacts.json"
    return output_dir / file_name


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def run_single(input_path: Path, output_path: Path) -> Path:
    result = parse_artifact(input_path)
    write_json(output_path, result)
    return output_path


def run_batch(input_paths: Sequence[Path], output_dir: Path) -> List[Tuple[Path, Path]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    produced: List[Tuple[Path, Path]] = []
    for input_path in input_paths:
        out_path = default_output_for_input(input_path, output_dir)
        run_single(input_path, out_path)
        produced.append((input_path, out_path))

    manifest = {
        "version": "1.0",
        "batch_input_glob": DEFAULT_INPUT_GLOB,
        "produced_count": len(produced),
        "results": [
            {"input": str(inp.as_posix()), "output": str(out.as_posix())}
            for inp, out in produced
        ],
    }
    write_json(output_dir / "manifest.json", manifest)
    return produced


def resolve_input_paths(input_json: Optional[str], input_glob: str) -> List[Path]:
    if input_json:
        path = Path(input_json)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {path}")
        return [path]

    matches = [Path(path) for path in sorted(Path(".").glob(input_glob))]
    if not matches and input_glob == DEFAULT_INPUT_GLOB:
        matches = [Path(path) for path in sorted(Path(".").glob(FALLBACK_INPUT_GLOB))]
    if not matches:
        raise FileNotFoundError(
            f"No input files found by glob: {input_glob}. "
            "Provide an explicit input path or place input files under output/web_json/*."
        )
    return matches


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse web_backend_sources readable JSON into backend extraction artifacts."
    )
    parser.add_argument(
        "input_json",
        nargs="?",
        help="Input JSON path. If omitted, batch mode uses --input-glob.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON path in single-file mode.",
    )
    parser.add_argument(
        "--input-glob",
        default=DEFAULT_INPUT_GLOB,
        help=f"Input glob for batch mode (default: {DEFAULT_INPUT_GLOB})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Default output directory (default: {DEFAULT_OUTPUT_DIR.as_posix()})",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    input_paths = resolve_input_paths(args.input_json, args.input_glob)

    if args.input_json:
        input_path = input_paths[0]
        output_path = Path(args.output) if args.output else default_output_for_input(
            input_path, output_dir
        )
        out = run_single(input_path, output_path)
        print(f"[web_backend_sources_parser] parsed: {input_path}")
        print(f"[web_backend_sources_parser] output: {out}")
        return 0

    produced = run_batch(input_paths, output_dir)
    print(
        f"[web_backend_sources_parser] batch parsed {len(produced)} files, "
        f"output_dir={output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
