#!/usr/bin/env python3
"""Headless IDA batch driver for full binary preprocessing."""

from __future__ import annotations

import shutil
import tempfile
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from common import (
    BinaryCandidate,
    default_preprocess_output_path,
    existing_idb_path,
    output_stem,
    quote_ida_arg,
)


@dataclass
class PreprocessResult:
    candidate: BinaryCandidate
    output_path: Path
    log_path: Path
    status: str
    elapsed_seconds: float
    returncode: Optional[int]
    command: List[str]
    message: str = ""


def _build_ida_command(
    *,
    ida_batch_exe: Path,
    log_path: Path,
    script_arg: str,
    target_path: Path,
    force_new_database: bool,
) -> List[str]:
    command = [
        str(ida_batch_exe.resolve()),
        "-A",
        f"-L{log_path.resolve()}",
        script_arg,
    ]
    if force_new_database:
        command.append("-c")
    command.append(str(target_path.resolve()))
    return command


def _log_contains_access_denied(log_path: Path) -> bool:
    if not log_path.exists():
        return False
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    lowered = text.lower()
    return "access denied" in lowered and "could not open the database" in lowered


def _build_script_argument(
    script_path: Path,
    *,
    output_path: Path,
    include_pseudocode: bool,
    include_disassembly: bool,
    min_string_len: int,
) -> str:
    parts = [
        quote_ida_arg(str(script_path.resolve())),
        "--output",
        quote_ida_arg(str(output_path.resolve())),
        "--min-string-len",
        str(min_string_len),
    ]
    if include_pseudocode:
        parts.append("--include-pseudocode")
    if include_disassembly:
        parts.append("--include-disassembly")
    return "-S" + " ".join(parts)


def run_headless_preprocess(
    *,
    ida_batch_exe: Path,
    script_path: Path,
    candidates: Sequence[BinaryCandidate],
    output_dir: Path,
    log_dir: Path,
    timeout_seconds: int,
    include_pseudocode: bool,
    include_disassembly: bool,
    min_string_len: int,
    reuse_existing_idb: bool,
) -> List[PreprocessResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    results: List[PreprocessResult] = []

    for candidate in candidates:
        output_path = default_preprocess_output_path(candidate, output_dir)
        log_path = log_dir / f"{output_stem(candidate)}.ida.log"
        target_path = candidate.path
        force_new_database = False
        isolated_temp_dir: Optional[tempfile.TemporaryDirectory[str]] = None
        if reuse_existing_idb:
            existing_idb = existing_idb_path(candidate.path)
            if existing_idb is not None:
                target_path = existing_idb

        script_arg = _build_script_argument(
            script_path,
            output_path=output_path,
            include_pseudocode=include_pseudocode,
            include_disassembly=include_disassembly,
            min_string_len=min_string_len,
        )
        command = _build_ida_command(
            ida_batch_exe=ida_batch_exe,
            log_path=log_path,
            script_arg=script_arg,
            target_path=target_path,
            force_new_database=force_new_database,
        )

        started = time.time()
        status = "ok"
        returncode: Optional[int] = None
        message = ""
        try:
            completed = subprocess.run(
                command,
                cwd=str(candidate.path.parent),
                timeout=timeout_seconds,
                check=False,
            )
            returncode = completed.returncode
            if completed.returncode != 0 and not output_path.exists():
                status = "failed"
                message = f"IDA exited with return code {completed.returncode}"
            elif completed.returncode != 0 and output_path.exists():
                status = "partial"
                message = (
                    f"IDA exited with return code {completed.returncode}, "
                    "but a preprocess artifact was written."
                )
        except subprocess.TimeoutExpired:
            returncode = None
            if output_path.exists():
                status = "partial"
                message = (
                    f"IDA timed out after {timeout_seconds}s, "
                    "but a preprocess artifact was written."
                )
            else:
                status = "timeout"
                message = f"IDA timed out after {timeout_seconds}s"

        if status == "failed" and not output_path.exists() and _log_contains_access_denied(log_path):
            force_new_database = True
            target_path = candidate.path
            command = _build_ida_command(
                ida_batch_exe=ida_batch_exe,
                log_path=log_path,
                script_arg=script_arg,
                target_path=target_path,
                force_new_database=force_new_database,
            )
            try:
                completed = subprocess.run(
                    command,
                    cwd=str(candidate.path.parent),
                    timeout=timeout_seconds,
                    check=False,
                )
                returncode = completed.returncode
                if completed.returncode == 0 and output_path.exists():
                    status = "ok"
                    message = "Retried with a fresh IDA database after access-denied on existing IDB."
                elif completed.returncode != 0 and output_path.exists():
                    status = "partial"
                    message = (
                        "Retried with a fresh IDA database after access-denied on existing IDB, "
                        f"but IDA still exited with return code {completed.returncode}."
                    )
                else:
                    status = "failed"
                    message = (
                        "Retried with a fresh IDA database after access-denied on existing IDB, "
                        f"but IDA still exited with return code {completed.returncode}."
                    )
            except subprocess.TimeoutExpired:
                returncode = None
                if output_path.exists():
                    status = "partial"
                    message = (
                        "Retried with a fresh IDA database after access-denied on existing IDB, "
                        f"then timed out after {timeout_seconds}s but still wrote an artifact."
                    )
                else:
                    status = "timeout"
                    message = (
                        "Retried with a fresh IDA database after access-denied on existing IDB, "
                        f"but timed out after {timeout_seconds}s."
                    )

        if status == "failed" and not output_path.exists() and _log_contains_access_denied(log_path):
            isolated_temp_dir = tempfile.TemporaryDirectory(prefix="ida_preprocess_")
            isolated_binary_dir = Path(isolated_temp_dir.name)
            isolated_target = isolated_binary_dir / candidate.path.name
            shutil.copy2(candidate.path, isolated_target)
            force_new_database = True
            target_path = isolated_target
            command = _build_ida_command(
                ida_batch_exe=ida_batch_exe,
                log_path=log_path,
                script_arg=script_arg,
                target_path=target_path,
                force_new_database=force_new_database,
            )
            try:
                completed = subprocess.run(
                    command,
                    cwd=str(isolated_binary_dir),
                    timeout=timeout_seconds,
                    check=False,
                )
                returncode = completed.returncode
                if completed.returncode == 0 and output_path.exists():
                    status = "ok"
                    message = (
                        "Retried in an isolated temporary directory after source IDB "
                        "path access-denied, and preprocessing succeeded."
                    )
                elif completed.returncode != 0 and output_path.exists():
                    status = "partial"
                    message = (
                        "Retried in an isolated temporary directory after source IDB path "
                        f"access-denied, but IDA exited with return code {completed.returncode}."
                    )
                else:
                    status = "failed"
                    message = (
                        "Retried in an isolated temporary directory after source IDB path "
                        f"access-denied, but IDA exited with return code {completed.returncode}."
                    )
            except subprocess.TimeoutExpired:
                returncode = None
                if output_path.exists():
                    status = "partial"
                    message = (
                        "Retried in an isolated temporary directory after source IDB path "
                        f"access-denied, then timed out after {timeout_seconds}s but wrote an artifact."
                    )
                else:
                    status = "timeout"
                    message = (
                        "Retried in an isolated temporary directory after source IDB path "
                        f"access-denied, but timed out after {timeout_seconds}s."
                    )

        results.append(
            PreprocessResult(
                candidate=candidate,
                output_path=output_path,
                log_path=log_path,
                status=status,
                elapsed_seconds=round(time.time() - started, 3),
                returncode=returncode,
                command=command,
                message=message,
            )
        )
        if isolated_temp_dir is not None:
            isolated_temp_dir.cleanup()

    return results


def results_to_rows(results: Iterable[PreprocessResult]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for item in results:
        rows.append(
            {
                "binary_path": str(item.candidate.path),
                "relative_path": item.candidate.relative_path.as_posix(),
                "output_path": str(item.output_path),
                "log_path": str(item.log_path),
                "status": item.status,
                "elapsed_seconds": item.elapsed_seconds,
                "returncode": item.returncode,
                "message": item.message,
                "command": item.command,
            }
        )
    return rows
