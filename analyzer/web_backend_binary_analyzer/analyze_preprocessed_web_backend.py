#!/usr/bin/env python3
"""Stage-2 entrypoint: analyze full preprocessed binary context for fuzzing-ready web facts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import default_analysis_output_path, discover_preprocessed_inputs, summarize_status_rows
from preprocessed_web_analyzer import analyze_preprocessed_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read full preprocessed binary context and derive fuzzing-oriented "
            "web backend artifacts such as routes, handlers, params, sinks, "
            "auth hints, and state hints."
        )
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="A *.preprocessed.json file or a directory containing them",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "final",
        help="Directory for final web_backend_binary artifacts",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="Optional JSON summary output path",
    )
    args = parser.parse_args()

    inputs = discover_preprocessed_inputs(args.input_path)
    rows = []
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for preprocess_path in inputs:
        artifact = analyze_preprocessed_file(preprocess_path)
        output_path = default_analysis_output_path(preprocess_path, args.output_dir)
        output_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
        rows.append(
            {
                "preprocess_path": str(preprocess_path.resolve()),
                "output_path": str(output_path.resolve()),
                "status": "ok",
                "binary": artifact.get("binary", {}).get("source_file"),
                "route_count": artifact.get("summary", {}).get("route_count"),
                "handler_count": artifact.get("summary", {}).get("handler_count"),
                "param_count": artifact.get("summary", {}).get("param_count"),
                "sink_count": artifact.get("summary", {}).get("sink_count"),
            }
        )

    summary = summarize_status_rows(rows)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
