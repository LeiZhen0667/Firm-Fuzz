#!/usr/bin/env python3
"""Repository entrypoint for the web backend binary analyzer.

This CLI builds the worklist and JSON manifest used by the path-A MCP driver.
The active Codex/IDA session can then consume that manifest and execute the
analysis by calling :func:`analyze_directory_via_mcp` from ida_mcp_driver.py.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ida_mcp_driver import (
    HttpJsonRpcIdaMcpSession,
    analyze_directory_via_mcp,
    discover_binary_candidates,
    manifest_for_candidates,
    summarize_results,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a path-A IDA MCP worklist for unreadable web backend binaries."
    )
    parser.add_argument(
        "input_root",
        type=Path,
        help="Directory that contains unreadable web backend binaries",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output",
        help="Artifact output directory",
    )
    parser.add_argument(
        "--extractor-script",
        type=Path,
        default=Path(__file__).resolve().parent / "ida_scripts" / "extract_web_facts.py",
        help="IDA extractor script path",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recurse into subdirectories",
    )
    parser.add_argument(
        "--exclude-object-files",
        action="store_true",
        help="Skip object files such as *.o",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Optional manifest path. Defaults to stdout.",
    )
    parser.add_argument(
        "--run-mcp",
        action="store_true",
        help="Run path-A extraction immediately against a reachable IDA MCP HTTP endpoint.",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="IDA MCP host for --run-mcp",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=13337,
        help="IDA MCP port for --run-mcp",
    )
    parser.add_argument(
        "--mcp-timeout-seconds",
        type=int,
        default=30,
        help="Per-request timeout when talking to IDA MCP over HTTP",
    )
    args = parser.parse_args()

    candidates = discover_binary_candidates(
        args.input_root,
        recursive=args.recursive,
        include_object_files=not args.exclude_object_files,
    )
    manifest = manifest_for_candidates(
        candidates,
        input_root=args.input_root,
        output_dir=args.output_dir,
        extractor_script=args.extractor_script,
    )
    payload = json.dumps(manifest, ensure_ascii=False, indent=2)

    if args.manifest_out:
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(payload, encoding="utf-8")
        print(f"[web_backend_binary_analyzer] Wrote manifest to: {args.manifest_out}")
        print(f"[web_backend_binary_analyzer] Binary candidates: {len(candidates)}")
    else:
        print(payload)

    if not args.run_mcp:
        return

    session = HttpJsonRpcIdaMcpSession(
        host=args.mcp_host,
        port=args.mcp_port,
        timeout_seconds=args.mcp_timeout_seconds,
    )
    results = analyze_directory_via_mcp(
        session,
        input_root=args.input_root,
        output_dir=args.output_dir,
        extractor_script=args.extractor_script,
        recursive=args.recursive,
        include_object_files=not args.exclude_object_files,
    )
    summary = summarize_results(results)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
