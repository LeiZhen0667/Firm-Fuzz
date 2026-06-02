#!/usr/bin/env python3
"""Stage-1 entrypoint: headless IDA preprocessing for unreadable web backend binaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import (
    DEFAULT_MIN_STRING_LEN,
    discover_binary_candidates,
    resolve_ida_batch_executable,
    summarize_status_rows,
)
from ida_batch_driver import results_to_rows, run_headless_preprocess


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run headless IDA preprocessing over unreadable web backend binaries "
            "and save full intermediate context for later analysis."
        )
    )
    parser.add_argument("input_path", type=Path, help="Binary file or directory of binary candidates")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "preprocessed",
        help="Directory for full preprocess JSON artifacts",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "logs",
        help="Directory for IDA batch logs",
    )
    parser.add_argument(
        "--ida-batch",
        type=Path,
        default=None,
        help="Path to IDA batch executable such as idat.exe or idat64.exe",
    )
    parser.add_argument(
        "--ida-script",
        type=Path,
        default=Path(__file__).resolve().parent / "ida_scripts" / "export_full_context.py",
        help="IDA Python script that exports full preprocessing context",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recurse into subdirectories when input_path is a directory",
    )
    parser.add_argument(
        "--exclude-object-files",
        action="store_true",
        help="Skip relocatable object files such as *.o",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=1800,
        help="Per-binary timeout for headless IDA preprocessing",
    )
    parser.add_argument(
        "--min-string-len",
        type=int,
        default=DEFAULT_MIN_STRING_LEN,
        help="Minimum string length saved by the IDA preprocessor",
    )
    parser.add_argument(
        "--no-pseudocode",
        action="store_true",
        help="Do not save full pseudocode for each function",
    )
    parser.add_argument(
        "--no-disassembly",
        action="store_true",
        help="Do not save full disassembly for each function",
    )
    parser.add_argument(
        "--no-reuse-existing-idb",
        action="store_true",
        help="Force IDA to open the original binary path instead of an existing .i64/.idb",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="Optional JSON summary output path",
    )
    args = parser.parse_args()

    candidates = discover_binary_candidates(
        args.input_path,
        recursive=args.recursive,
        include_object_files=not args.exclude_object_files,
    )
    ida_batch_exe = resolve_ida_batch_executable(args.ida_batch)
    results = run_headless_preprocess(
        ida_batch_exe=ida_batch_exe,
        script_path=args.ida_script,
        candidates=candidates,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
        timeout_seconds=args.timeout_seconds,
        include_pseudocode=not args.no_pseudocode,
        include_disassembly=not args.no_disassembly,
        min_string_len=args.min_string_len,
        reuse_existing_idb=not args.no_reuse_existing_idb,
    )
    rows = results_to_rows(results)
    summary = summarize_status_rows(rows)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
