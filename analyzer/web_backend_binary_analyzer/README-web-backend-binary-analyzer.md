# Web Backend Binary Analyzer

## Goal

This module implements the repository side of path A from
`analyzer/web_backend_binary_automation_plan.md`:

`Codex -> IDA MCP -> open binary -> wait for auto-analysis -> run IDA script -> write structured artifacts`

The target is offline extraction of web-service facts from unreadable backend
binaries so later black-box HTTP fuzzing can reuse them as structured inputs:

- route and handler candidates
- parameter readers and parameter names
- lightweight constraints
- sink proximity
- response strings
- authentication hints
- state-change hints

## Layout

```text
analyzer/web_backend_binary_analyzer/
  web_backend_binary_analyzer.py
  ida_mcp_driver.py
  ida_scripts/
    extract_web_facts.py
  output/
```

## What Each File Does

- `web_backend_binary_analyzer.py`
  Creates the binary worklist and manifest for a target directory.
- `ida_mcp_driver.py`
  Contains the path-A orchestration logic as a reusable Python module. It
  expects a small session adapter that exposes the same operations as the
  active IDA MCP session: `list_instances`, `open_file`, `server_health`,
  `py_eval`, and `select_instance`.
- `ida_scripts/extract_web_facts.py`
  Runs inside IDA Python and extracts structured facts from the currently open
  database.

## Candidate Discovery

Binary discovery intentionally ignores IDA side files such as:

- `.i64`
- `.id0`
- `.id1`
- `.id2`
- `.nam`
- `.til`

It accepts ELF/PE/Mach-O magic and keeps object files such as `.o` by default,
because vendor GPL drops often keep small CGI/helper objects beside the main
HTTP daemon.

## Manifest Generation

Example:

```powershell
python analyzer/web_backend_binary_analyzer/web_backend_binary_analyzer.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --manifest-out analyzer/web_backend_binary_analyzer/output/Linksys_e1200_v1.0.04.001_us.path_a_manifest.json
```

If you already have a reachable IDA MCP HTTP endpoint, you can also execute the
path-A workflow directly:

```powershell
python analyzer/web_backend_binary_analyzer/web_backend_binary_analyzer.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --run-mcp `
  --mcp-host 127.0.0.1 `
  --mcp-port 13337 `
  --manifest-out analyzer/web_backend_binary_analyzer/output/Linksys_e1200_v1.0.04.001_us.path_a_manifest.json
```

The manifest records:

- binary path
- relative path
- expected artifact path
- extractor script path

## Path-A MCP Execution Model

The repository code cannot directly invoke Codex tools by itself. Instead, the
runtime session can either inject an adapter object or use the built-in
`HttpJsonRpcIdaMcpSession` against a local MCP HTTP endpoint.

Adapter-style usage:

```python
from pathlib import Path
from ida_mcp_driver import analyze_directory_via_mcp

results = analyze_directory_via_mcp(
    session=my_ida_mcp_session,
    input_root=Path("collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us"),
    output_dir=Path("analyzer/web_backend_binary_analyzer/output"),
    extractor_script=Path("analyzer/web_backend_binary_analyzer/ida_scripts/extract_web_facts.py"),
)
```

Direct HTTP usage:

```python
from pathlib import Path
from ida_mcp_driver import HttpJsonRpcIdaMcpSession, analyze_directory_via_mcp

session = HttpJsonRpcIdaMcpSession(host="127.0.0.1", port=13337, timeout_seconds=30)
results = analyze_directory_via_mcp(
    session=session,
    input_root=Path("collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us"),
    output_dir=Path("analyzer/web_backend_binary_analyzer/output"),
    extractor_script=Path("analyzer/web_backend_binary_analyzer/ida_scripts/extract_web_facts.py"),
)
```

For each binary, the workflow is:

1. Ensure `idapromcp.list_instances()` is non-empty.
2. Call `open_file(binary, autonomous=True, switch=True)`.
3. Poll `server_health()` until `auto_analysis_ready` becomes true.
4. Execute `extract_web_facts.py` in IDA via `py_eval`.
5. Save `<relative.binary.path>.web_backend_binary_artifacts.json`.

The driver also handles a practical failure mode seen with some large IDBs:
`py_eval` may time out at the RPC layer even though IDA keeps running the
script. In that case the driver polls for the expected output file and treats
the run as recovered if the artifact appears.

## Extracted Artifact Shape

The IDA script emits one JSON artifact per binary with these top-level fields:

- `binary`
- `routes`
- `handlers`
- `route_mappings`
- `params`
- `constraints`
- `config_accesses`
- `sinks`
- `response_strings`
- `auth_hints`
- `state_hints`
- `strings`
- `functions`
- `xrefs`
- `callgraph_edges`
- `summary`

Every fact keeps evidence with the parser name, address, function, snippet, and
confidence.

## IDA-Side Heuristics

The first implementation stays intentionally lightweight:

- string classification for routes, auth hints, state hints, and response text
- xrefs to sink APIs, config APIs, and parameter-reader APIs
- handler inference from function names and route-string xrefs
- parameter extraction from pseudocode calls such as `get_cgi("foo")`
- constraint extraction from pseudocode patterns such as `atoi`, `strlen`,
  `strcmp`, `strtol`, `sscanf`, and numeric comparisons
- direct registration extraction from pseudocode calls such as
  `websFormDefine`, `websUrlHandlerDefine`, `cgi_register`, `ejRegister`, and
  `asp_register`

## Notes

- This path-A implementation is designed for interactive MCP-driven analysis.
- The same `extract_web_facts.py` script can also be reused by a future
  headless path-B driver.
- The orchestrator preserves low-confidence facts instead of dropping them,
  because later fusion/seed selection should decide what to prioritize.
