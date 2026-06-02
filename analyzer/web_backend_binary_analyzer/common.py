#!/usr/bin/env python3
"""Shared helpers for web backend binary preprocessing and analysis."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


IGNORED_SUFFIXES = {
    ".i64",
    ".id0",
    ".id1",
    ".id2",
    ".nam",
    ".til",
    ".json",
    ".md",
    ".txt",
    ".py",
    ".cfg",
    ".conf",
    ".ini",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".css",
    ".csv",
    ".log",
}

EXECUTABLE_SUFFIXES = {"", ".o", ".so", ".elf", ".bin", ".cgi", ".asp", ".exe", ".dll"}
DEFAULT_MIN_STRING_LEN = 4


@dataclass(frozen=True)
class BinaryCandidate:
    path: Path
    relative_path: Path
    size: int
    flavor: str
    bits: Optional[int]


def _has_binary_magic(header: bytes) -> Optional[str]:
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"MZ"):
        return "pe"
    if header[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "macho"
    return None


def _guess_bits(path: Path, header: bytes) -> Optional[int]:
    if header.startswith(b"\x7fELF") and len(header) >= 5:
        if header[4] == 1:
            return 32
        if header[4] == 2:
            return 64
    if header.startswith(b"MZ"):
        try:
            with path.open("rb") as f:
                f.seek(0x3C)
                pe_off = int.from_bytes(f.read(4), "little", signed=False)
                f.seek(pe_off + 4)
                machine = int.from_bytes(f.read(2), "little", signed=False)
            if machine in {0x14C, 0x1C0, 0x1C4, 0x1D3, 0x1F0}:
                return 32
            if machine in {0x8664, 0xAA64, 0x200}:
                return 64
        except OSError:
            return None
    if header[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"}:
        return 32
    if header[:4] in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return 64
    return None


def discover_binary_candidates(
    input_root: Path,
    *,
    recursive: bool = True,
    include_object_files: bool = True,
) -> List[BinaryCandidate]:
    root = input_root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Input root does not exist: {root}")

    if root.is_file():
        return [_build_candidate(root, relative_path=Path(root.name))]

    iterator = root.rglob("*") if recursive else root.glob("*")
    candidates: List[BinaryCandidate] = []
    for path in iterator:
        if not path.is_file():
            continue
        if path.suffix.lower() in IGNORED_SUFFIXES:
            continue
        if path.suffix.lower() == ".o" and not include_object_files:
            continue
        candidate = _build_candidate(path.resolve(), relative_path=path.resolve().relative_to(root))
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=lambda item: (item.relative_path.as_posix(), item.size))
    return candidates


def _build_candidate(path: Path, *, relative_path: Path) -> Optional[BinaryCandidate]:
    header = path.read_bytes()[:64]
    flavor = _has_binary_magic(header)
    if flavor is None and path.suffix.lower() not in EXECUTABLE_SUFFIXES:
        return None
    if flavor is None and b"\x00" not in header:
        return None
    return BinaryCandidate(
        path=path.resolve(),
        relative_path=relative_path,
        size=path.stat().st_size,
        flavor=flavor or "unknown",
        bits=_guess_bits(path, header),
    )


def output_stem(candidate: BinaryCandidate) -> str:
    stem = ".".join(candidate.relative_path.parts)
    return stem or candidate.path.name


def default_preprocess_output_path(candidate: BinaryCandidate, output_dir: Path) -> Path:
    return output_dir.resolve() / f"{output_stem(candidate)}.preprocessed.json"


def default_analysis_output_path(preprocess_path: Path, output_dir: Path) -> Path:
    name = preprocess_path.name
    if name.endswith(".preprocessed.json"):
        base = name[: -len(".preprocessed.json")]
    else:
        base = preprocess_path.stem
    return output_dir.resolve() / f"{base}.web_backend_binary_artifacts.json"


def existing_idb_path(binary_path: Path) -> Optional[Path]:
    base = binary_path.with_suffix("")
    for suffix in (".i64", ".idb"):
        candidate = base.with_suffix(suffix)
        if candidate.is_file():
            return candidate
    for suffix in (".i64", ".idb"):
        candidate = Path(str(binary_path) + suffix)
        if candidate.is_file():
            return candidate
    return None


def quote_ida_arg(text: str) -> str:
    return '"' + text.replace('"', '\\"') + '"'


def resolve_ida_batch_executable(preferred: Optional[Path] = None) -> Path:
    checked: List[Path] = []

    def _candidate_paths(root: Path) -> Iterable[Path]:
        for name in ("idat64.exe", "idat.exe", "ida64.exe", "ida.exe"):
            yield root / name

    if preferred is not None:
        preferred = preferred.resolve()
        if preferred.is_file():
            return preferred
        if preferred.is_dir():
            for candidate in _candidate_paths(preferred):
                checked.append(candidate)
                if candidate.is_file():
                    return candidate

    for env_name in ("IDA_BATCH_PATH", "IDA_PATH", "IDA_INSTALL_DIR"):
        value = os.environ.get(env_name)
        if not value:
            continue
        env_path = Path(value).expanduser()
        if env_path.is_file():
            return env_path.resolve()
        if env_path.is_dir():
            for candidate in _candidate_paths(env_path.resolve()):
                checked.append(candidate)
                if candidate.is_file():
                    return candidate

    roots: List[Path] = [
        Path("C:/Users/admin/Desktop/IDA Professional_9.1"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
    ]
    glob_patterns = [
        "C:/Users/*/Desktop/IDA*",
        "C:/Program Files/IDA*",
        "C:/Program Files (x86)/IDA*",
    ]

    for root in roots:
        if root.is_dir() and root.name.lower().startswith("ida"):
            for candidate in _candidate_paths(root):
                checked.append(candidate)
                if candidate.is_file():
                    return candidate

    for pattern in glob_patterns:
        for match in glob.glob(pattern):
            root = Path(match)
            if not root.is_dir():
                continue
            for candidate in _candidate_paths(root):
                checked.append(candidate)
                if candidate.is_file():
                    return candidate

    checked_text = "\n".join(str(item) for item in checked[:20])
    raise FileNotFoundError(
        "Could not locate an IDA batch executable. "
        "Pass --ida-batch or set IDA_BATCH_PATH/IDA_PATH/IDA_INSTALL_DIR.\n"
        f"Checked:\n{checked_text}"
    )


def discover_preprocessed_inputs(path: Path) -> List[Path]:
    resolved = path.resolve()
    if resolved.is_file():
        return [resolved]
    if not resolved.exists():
        raise FileNotFoundError(f"Preprocessed input path does not exist: {resolved}")
    inputs = sorted(resolved.rglob("*.preprocessed.json"))
    if not inputs:
        raise FileNotFoundError(f"No *.preprocessed.json files found under: {resolved}")
    return inputs


def summarize_status_rows(rows: Sequence[dict]) -> dict:
    success = [row for row in rows if row.get("status") == "ok"]
    failed = [row for row in rows if row.get("status") != "ok"]
    return {
        "total": len(rows),
        "ok": len(success),
        "non_ok": len(failed),
        "results": list(rows),
    }
