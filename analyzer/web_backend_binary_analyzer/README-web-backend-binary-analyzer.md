# Web Backend Binary Analyzer

## Goal

This module now follows the two-stage workflow you requested:

1. Stage 1: run IDA in headless/batch mode and save a full intermediate
   preprocessing result without Web-specific filtering.
2. Stage 2: read that intermediate result and derive fuzzing-oriented Web
   service artifacts such as routes, handlers, params, constraints, sinks,
   response strings, authentication hints, and state-change hints.

The main production path is deliberately designed to avoid MCP during
preprocessing. MCP support remains available as an optional interactive helper,
but it is no longer the primary pipeline.

## Main Entry Scripts

The two primary entrypoints are:

- `preprocess_web_backend_binaries.py`
  Runs IDA headless over one binary or a directory of binaries and writes full
  intermediate context as `*.preprocessed.json`.
- `analyze_preprocessed_web_backend.py`
  Reads one or more `*.preprocessed.json` files and emits final
  `*.web_backend_binary_artifacts.json` files for downstream fuzzing.

## Layout

```text
analyzer/web_backend_binary_analyzer/
  common.py
  preprocess_web_backend_binaries.py
  analyze_preprocessed_web_backend.py
  preprocessed_web_analyzer.py
  ida_batch_driver.py
  ida_mcp_driver.py
  web_backend_binary_analyzer.py
  ida_scripts/
    export_full_context.py
    extract_web_facts.py
  output/
```

## Stage 1: Full Intermediate Preprocessing

### Design

Stage 1 intentionally does not try to decide what is important for fuzzing.
Instead, it preserves the information needed for later analysis, review, and
reconstruction of function behavior.

For each binary, the preprocessed JSON keeps:

- binary metadata
- segment layout
- imports
- exports
- named symbols
- strings with xrefs
- every discovered function
- callers and callees per function
- string references per function
- import references per function
- non-string data references per function
- optional full disassembly per function
- optional full pseudocode per function
- global callgraph edges
- analysis warnings such as decompilation failures

### Stage-1 Entry

Example:

```powershell
python analyzer/web_backend_binary_analyzer/preprocess_web_backend_binaries.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --recursive `
  --summary-out analyzer/web_backend_binary_analyzer/output/preprocess.summary.json
```

Useful options:

- `--ida-batch`
  Explicit path to `idat.exe`, `idat64.exe`, `ida.exe`, or `ida64.exe`
- `--no-pseudocode`
  Save preprocessing results without full decompiled functions
- `--no-disassembly`
  Save preprocessing results without full disassembly
- `--exclude-object-files`
  Skip `.o` files

### Stage-1 IDA Script

`ida_scripts/export_full_context.py` is the in-IDA exporter used by the batch
driver. It is meant for headless usage and writes a full
`web_backend_binary_preprocessed` artifact.

## Stage 2: Fuzzing-Oriented Analysis

### Design

Stage 2 reads the full intermediate result and applies the Web-oriented logic:

- route-like string recognition
- auth/state/response string classification
- route-to-function mapping from string xrefs and registration-style calls
- parameter extraction from pseudocode/disassembly text
- config access extraction
- sink extraction
- lightweight constraint extraction
- candidate handler discovery
- candidate callgraph filtering

This stage changes analysis policy, not raw evidence. The full preprocess
artifact remains the source of truth.

### Stage-2 Entry

Example:

```powershell
python analyzer/web_backend_binary_analyzer/analyze_preprocessed_web_backend.py `
  analyzer/web_backend_binary_analyzer/output/preprocessed `
  --summary-out analyzer/web_backend_binary_analyzer/output/final.summary.json
```

## Intermediate Artifact Shape

The stage-1 output artifact type is:

- `web_backend_binary_preprocessed`

It includes these top-level fields:

- `binary`
- `imports`
- `exports`
- `names`
- `strings`
- `functions`
- `callgraph_edges`
- `analysis_warnings`
- `summary`

Each function record may include:

- `addr`
- `name`
- `size`
- `prototype`
- `segment`
- `callers`
- `callees`
- `string_refs`
- `import_refs`
- `data_refs`
- `disassembly`
- `pseudocode`
- `decompile_error`

This is intentionally much richer than the final fuzzing artifact so you can
inspect what a function actually contains instead of only seeing filtered
snippets.

## Final Artifact Shape

The stage-2 output artifact type is:

- `web_backend_binary`

It includes:

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

## Optional MCP Path

`ida_mcp_driver.py` and `web_backend_binary_analyzer.py` are still kept for the
optional path-A interactive workflow:

`Codex/MCP -> open binary -> wait for analysis -> run in-IDA extraction`

That path is useful for interactive deep dives, but the recommended stable
workflow is now:

`headless preprocessing -> saved intermediate context -> stage-2 analysis`
