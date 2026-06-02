#!/usr/bin/env python3
"""Path-A orchestration helpers for driving IDA through MCP.

This module is intentionally split from the Codex tool wiring. The repository
can keep a concrete, testable workflow definition, while the active Codex/MCP
session injects a session adapter that implements the small protocol below.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence


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
}

EXECUTABLE_SUFFIXES = {"", ".o", ".so", ".elf", ".bin", ".cgi", ".asp", ".exe", ".dll"}
MAX_OPEN_WAIT_SECONDS = 900


@dataclass(frozen=True)
class BinaryCandidate:
    path: Path
    relative_path: Path
    size: int
    flavor: str


@dataclass
class AnalysisResult:
    candidate: BinaryCandidate
    output_path: Path
    status: str
    details: Dict[str, Any]


class IdaMcpSession(Protocol):
    """Minimal protocol needed by the path-A workflow."""

    def list_instances(self) -> List[Dict[str, Any]]:
        ...

    def open_file(
        self,
        file_path: str,
        *,
        autonomous: bool = True,
        new_database: bool = False,
        switch: bool = True,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        ...

    def select_instance(self, *, host: Optional[str], port: int) -> Dict[str, Any]:
        ...

    def server_health(self) -> Dict[str, Any]:
        ...

    def py_eval(self, code: str) -> Dict[str, Any]:
        ...


class HttpJsonRpcIdaMcpSession:
    """Direct JSON-RPC client for an IDA MCP HTTP endpoint."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 13337,
        timeout_seconds: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self._next_id = 1

    def _call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        conn = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=timeout_seconds or self.timeout_seconds,
        )
        try:
            conn.request(
                "POST",
                "/mcp",
                body=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            raw = response.read().decode("utf-8", errors="replace")
        except socket.timeout as exc:
            raise TimeoutError(
                f"Timed out calling {name} on {self.host}:{self.port}"
            ) from exc
        finally:
            conn.close()

        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw}")

        parsed = json.loads(raw)
        if "error" in parsed:
            raise RuntimeError(parsed["error"].get("message", "Unknown MCP error"))

        result = parsed.get("result", {})
        if result.get("isError"):
            content = result.get("content", [])
            message = content[0].get("text", "Unknown tool error") if content else "Unknown tool error"
            raise RuntimeError(message)
        structured = result.get("structuredContent")
        return structured if isinstance(structured, dict) else {"result": structured}

    def list_instances(self) -> List[Dict[str, Any]]:
        result = self._call_tool("list_instances", {})
        return list(result.get("result", []))

    def open_file(
        self,
        file_path: str,
        *,
        autonomous: bool = True,
        new_database: bool = False,
        switch: bool = True,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        result = self._call_tool(
            "open_file",
            {
                "file_path": file_path,
                "autonomous": autonomous,
                "new_database": new_database,
                "switch": switch,
                "timeout": timeout,
            },
            timeout_seconds=max(timeout, self.timeout_seconds),
        )
        if switch and result.get("success") and result.get("host") and result.get("port"):
            self.host = str(result["host"])
            self.port = int(result["port"])
        return result

    def select_instance(self, *, host: Optional[str], port: int) -> Dict[str, Any]:
        arguments: Dict[str, Any] = {"port": port}
        if host:
            arguments["host"] = host
        result = self._call_tool("select_instance", arguments)
        if result.get("success") and result.get("host") and result.get("port"):
            self.host = str(result["host"])
            self.port = int(result["port"])
        return result

    def server_health(self) -> Dict[str, Any]:
        return self._call_tool("server_health", {})

    def py_eval(self, code: str) -> Dict[str, Any]:
        return self._call_tool("py_eval", {"code": code})


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


def discover_binary_candidates(
    input_root: Path,
    *,
    recursive: bool = True,
    include_object_files: bool = True,
) -> List[BinaryCandidate]:
    root = input_root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Input root does not exist: {root}")

    iterator = root.rglob("*") if recursive else root.glob("*")
    candidates: List[BinaryCandidate] = []
    for path in iterator:
        if not path.is_file():
            continue
        if path.suffix.lower() in IGNORED_SUFFIXES:
            continue

        suffix = path.suffix.lower()
        if suffix == ".o" and not include_object_files:
            continue

        header = path.read_bytes()[:16]
        flavor = _has_binary_magic(header)
        if flavor is None and suffix not in EXECUTABLE_SUFFIXES:
            continue
        if flavor is None and b"\x00" not in header:
            continue

        candidates.append(
            BinaryCandidate(
                path=path.resolve(),
                relative_path=path.resolve().relative_to(root),
                size=path.stat().st_size,
                flavor=flavor or "unknown",
            )
        )

    candidates.sort(key=lambda item: (item.relative_path.as_posix(), item.size))
    return candidates


def default_output_path(candidate: BinaryCandidate, input_root: Path, output_dir: Path) -> Path:
    rel = candidate.path.resolve().relative_to(input_root.resolve())
    stem = ".".join(rel.parts)
    if not stem:
        stem = candidate.path.name
    return output_dir.resolve() / f"{stem}.web_backend_binary_artifacts.json"


def manifest_for_candidates(
    candidates: Sequence[BinaryCandidate],
    *,
    input_root: Path,
    output_dir: Path,
    extractor_script: Path,
) -> Dict[str, Any]:
    files = []
    for candidate in candidates:
        files.append(
            {
                "binary_path": str(candidate.path),
                "relative_path": candidate.relative_path.as_posix(),
                "size": candidate.size,
                "flavor": candidate.flavor,
                "output_path": str(default_output_path(candidate, input_root, output_dir)),
                "extractor_script": str(extractor_script.resolve()),
            }
        )
    return {
        "version": "1.0",
        "workflow": "web_backend_binary_path_a",
        "input_root": str(input_root.resolve()),
        "output_dir": str(output_dir.resolve()),
        "extractor_script": str(extractor_script.resolve()),
        "binaries": files,
    }


def ensure_anchor(session: IdaMcpSession) -> List[Dict[str, Any]]:
    instances = session.list_instances()
    if not instances:
        raise RuntimeError(
            "No running IDA instance is registered in idapromcp. "
            "Start an anchor instance or configure an IDA RPC launcher first."
        )
    return instances


def open_binary(session: IdaMcpSession, candidate: BinaryCandidate, *, timeout: int = 120) -> Dict[str, Any]:
    try:
        return session.open_file(
            str(candidate.path),
            autonomous=True,
            new_database=False,
            switch=True,
            timeout=timeout,
        )
    except TimeoutError as exc:
        deadline = time.time() + max(timeout, 30)
        last_instances: List[Dict[str, Any]] = []
        while time.time() < deadline:
            instances = session.list_instances()
            last_instances = instances
            for inst in instances:
                idb_path = str(inst.get("idb_path") or "")
                binary_name = str(inst.get("binary") or "")
                if candidate.path.name == binary_name or idb_path.endswith(candidate.path.name + ".i64") or idb_path.endswith(candidate.path.name + ".idb"):
                    host = inst.get("host")
                    port = inst.get("port")
                    if host and port:
                        session.select_instance(host=str(host), port=int(port))
                    return {
                        "success": True,
                        "recovered_via_instance_poll": True,
                        "host": host,
                        "port": port,
                        "binary": binary_name,
                        "message": str(exc),
                    }
            time.sleep(2.0)
        raise TimeoutError(
            f"Timed out opening {candidate.path} and no matching instance appeared. "
            f"Last discovered instances: {json.dumps(last_instances, ensure_ascii=False)}"
        ) from exc


def wait_for_auto_analysis(
    session: IdaMcpSession,
    *,
    timeout_seconds: int = MAX_OPEN_WAIT_SECONDS,
    poll_interval: float = 5.0,
    expected_binary_name: Optional[str] = None,
) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_health: Dict[str, Any] = {}
    while time.time() < deadline:
        if expected_binary_name and hasattr(session, "list_instances") and hasattr(session, "select_instance"):
            try:
                for inst in session.list_instances():
                    binary_name = str(inst.get("binary") or "")
                    idb_path = str(inst.get("idb_path") or "")
                    if binary_name == expected_binary_name or idb_path.endswith(expected_binary_name + ".i64") or idb_path.endswith(expected_binary_name + ".idb"):
                        host = inst.get("host")
                        port = inst.get("port")
                        if host and port:
                            session.select_instance(host=str(host), port=int(port))
                        break
            except Exception:
                pass
        last_health = session.server_health()
        if last_health.get("auto_analysis_ready"):
            return last_health
        time.sleep(poll_interval)
    raise TimeoutError(
        f"IDA auto-analysis did not become ready within {timeout_seconds} seconds. "
        f"Last health: {json.dumps(last_health, ensure_ascii=False)}"
    )


def build_py_eval_runner(script_path: Path, output_path: Path, extra_args: Optional[Iterable[str]] = None) -> str:
    argv = [str(script_path.resolve()), "--output", str(output_path.resolve())]
    if extra_args:
        argv.extend(extra_args)
    quoted = ", ".join(repr(arg) for arg in argv)
    return "\n".join(
        [
            "import runpy",
            "import sys",
            f"sys.argv = [{quoted}]",
            f"runpy.run_path({str(script_path.resolve())!r}, run_name='__main__')",
        ]
    )


def run_extractor(
    session: IdaMcpSession,
    *,
    script_path: Path,
    output_path: Path,
    extra_args: Optional[Iterable[str]] = None,
    timeout_wait_seconds: int = 180,
    poll_interval_seconds: float = 2.0,
) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    code = build_py_eval_runner(script_path, output_path, extra_args=extra_args)
    before_mtime = output_path.stat().st_mtime if output_path.exists() else None
    try:
        result = session.py_eval(code)
    except TimeoutError as exc:
        deadline = time.time() + timeout_wait_seconds
        while time.time() < deadline:
            if output_path.exists():
                after_mtime = output_path.stat().st_mtime
                if before_mtime is None or after_mtime != before_mtime:
                    return {
                        "result": "",
                        "stdout": "",
                        "stderr": "",
                        "timed_out": True,
                        "recovered_via_output_poll": True,
                        "message": str(exc),
                    }
            time.sleep(poll_interval_seconds)
        raise
    if output_path.exists():
        after_mtime = output_path.stat().st_mtime
        result["output_written"] = before_mtime is None or after_mtime != before_mtime
    return result


def analyze_candidate_via_mcp(
    session: IdaMcpSession,
    candidate: BinaryCandidate,
    *,
    input_root: Path,
    output_dir: Path,
    extractor_script: Path,
    open_timeout_seconds: int = 120,
    auto_analysis_timeout_seconds: int = MAX_OPEN_WAIT_SECONDS,
    extra_script_args: Optional[Iterable[str]] = None,
) -> AnalysisResult:
    ensure_anchor(session)
    open_result = open_binary(session, candidate, timeout=open_timeout_seconds)
    health = wait_for_auto_analysis(
        session,
        timeout_seconds=auto_analysis_timeout_seconds,
        expected_binary_name=candidate.path.name,
    )
    output_path = default_output_path(candidate, input_root, output_dir)
    exec_result = run_extractor(
        session,
        script_path=extractor_script,
        output_path=output_path,
        extra_args=extra_script_args,
    )
    status = "ok" if output_path.exists() else "missing_output"
    return AnalysisResult(
        candidate=candidate,
        output_path=output_path,
        status=status,
        details={
            "open_result": open_result,
            "health": health,
            "exec_result": exec_result,
        },
    )


def analyze_directory_via_mcp(
    session: IdaMcpSession,
    *,
    input_root: Path,
    output_dir: Path,
    extractor_script: Path,
    recursive: bool = True,
    include_object_files: bool = True,
    extra_script_args: Optional[Iterable[str]] = None,
) -> List[AnalysisResult]:
    candidates = discover_binary_candidates(
        input_root,
        recursive=recursive,
        include_object_files=include_object_files,
    )
    results: List[AnalysisResult] = []
    for candidate in candidates:
        results.append(
            analyze_candidate_via_mcp(
                session,
                candidate,
                input_root=input_root,
                output_dir=output_dir,
                extractor_script=extractor_script,
                extra_script_args=extra_script_args,
            )
        )
    return results


def summarize_results(results: Sequence[AnalysisResult]) -> Dict[str, Any]:
    ok = [item for item in results if item.status == "ok"]
    missing = [item for item in results if item.status != "ok"]
    return {
        "total": len(results),
        "ok": len(ok),
        "non_ok": len(missing),
        "outputs": [str(item.output_path) for item in ok],
        "failures": [
            {
                "binary": str(item.candidate.path),
                "status": item.status,
                "details": item.details,
            }
            for item in missing
        ],
    }


def _manifest_main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Create a path-A MCP work manifest for unreadable web backend binaries."
    )
    parser.add_argument("input_root", type=Path, help="Directory containing binary candidates")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output",
        help="Directory for extracted web_backend_binary artifacts",
    )
    parser.add_argument(
        "--extractor-script",
        type=Path,
        default=Path(__file__).resolve().parent / "ida_scripts" / "extract_web_facts.py",
        help="IDA Python extractor script path",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recurse into subdirectories when discovering binaries",
    )
    parser.add_argument(
        "--exclude-object-files",
        action="store_true",
        help="Skip relocatable object files such as *.o",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional manifest output path. Prints to stdout when omitted.",
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
    text = json.dumps(manifest, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    _manifest_main()
