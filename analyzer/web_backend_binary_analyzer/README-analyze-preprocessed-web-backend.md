# Analyze Preprocessed Web Backend

## Goal

`analyze_preprocessed_web_backend.py` is the stage-2 entrypoint for unreadable
Web backend binaries.

Its job is to read the full intermediate `*.preprocessed.json` artifacts
produced by stage 1 and derive Web/fuzzing-oriented structured artifacts.

Unlike stage 1, this script does apply analysis policy. It tries to answer
questions such as:

- which strings look like routes or CGI endpoints
- which functions look like handlers
- which functions read HTTP parameters
- which functions access configuration state
- which functions are near dangerous sinks
- which strings can be used as feedback signals
- which strings hint at authentication or state-changing behavior

## Input

The input can be:

- one `*.preprocessed.json` file
- a directory containing multiple `*.preprocessed.json` files

The expected input artifact type is:

```json
"artifact_type": "web_backend_binary_preprocessed"
```

This script does not invoke IDA. It only consumes saved intermediate context.

## What The Script Does

For each preprocessed artifact, the script:

1. loads full intermediate binary context
2. classifies strings into route/auth/state/response-style buckets
3. identifies candidate handler functions from function names and route xrefs
4. extracts parameter readers from function text
5. extracts configuration accesses from function text and import references
6. extracts sink references from import calls
7. extracts lightweight constraints from pseudocode/disassembly text
8. maps route-like strings to handler-like functions
9. filters a candidate callgraph relevant to Web-facing analysis
10. writes one `*.web_backend_binary_artifacts.json` file per input

The result is intentionally more compact and fuzzing-oriented than the
stage-1 preprocess artifact.

## Usage

Analyze an entire preprocess directory:

```powershell
python analyzer/web_backend_binary_analyzer/analyze_preprocessed_web_backend.py `
  analyzer/web_backend_binary_analyzer/output/preprocessed/Linksys_e1200_v1.0.04.001_us `
  --output-dir analyzer/web_backend_binary_analyzer/output/final/Linksys_e1200_v1.0.04.001_us `
  --summary-out analyzer/web_backend_binary_analyzer/output/final/Linksys_e1200_v1.0.04.001_us.analysis.summary.json
```

Analyze a single preprocess file:

```powershell
python analyzer/web_backend_binary_analyzer/analyze_preprocessed_web_backend.py `
  analyzer/web_backend_binary_analyzer/output/preprocessed/Linksys_e1200_v1.0.04.001_us/httpd.preprocessed.json
```

## Command-Line Options

- `input_path`
  One preprocess file or a directory containing preprocess files.
- `-o`, `--output-dir`
  Directory where final `*.web_backend_binary_artifacts.json` files are saved.
- `--summary-out`
  Optional JSON summary output path.

## Output Files

### 1. Per-binary final analysis artifacts

File naming:

```text
<preprocess_stem>.web_backend_binary_artifacts.json
```

Examples:

- `httpd.web_backend_binary_artifacts.json`
- `upnp.web_backend_binary_artifacts.json`
- `login.o.web_backend_binary_artifacts.json`

### 2. Analysis summary JSON

If `--summary-out` is provided, the script also writes a summary file
containing per-binary status and a few top-level counts such as route count,
handler count, param count, and sink count.

## Final Artifact Structure

The output artifact type is:

```json
"artifact_type": "web_backend_binary"
```

Top-level structure:

```json
{
  "version": "1.0",
  "artifact_type": "web_backend_binary",
  "input_type": "unreadable_web_backend_binary",
  "binary": {},
  "routes": [],
  "handlers": [],
  "route_mappings": [],
  "params": [],
  "constraints": [],
  "config_accesses": [],
  "sinks": [],
  "response_strings": [],
  "auth_hints": [],
  "state_hints": [],
  "strings": [],
  "references": [],
  "functions": [],
  "xrefs": [],
  "callgraph_edges": [],
  "analysis_warnings": [],
  "summary": {},
  "pseudo_snippets": []
}
```

## Field Meanings

### `binary`

Carries the original binary metadata from preprocessing and adds:

- `preprocess_source`
  Absolute path to the `*.preprocessed.json` file used as source.

### `routes`

Route-like strings directly recognized as HTTP/CGI endpoints.

Typical fields:

- `route`
- `route_type`
- `source`
- `evidence`

### `handlers`

Candidate Web handlers inferred from function names or function context.

Typical fields:

- `name`
- `addr`
- `size`
- `source`
- `evidence`

### `route_mappings`

Candidate route-to-handler bindings inferred from:

- string xrefs
- handler-style function names
- registration-like calls found in function text

Typical fields:

- `route`
- `handler`
- `handler_addr`
- `source`
- `registration_api`
- `confidence`
- `evidence`

### `params`

Candidate parameter-reading facts.

These may come from:

- import references to parameter-reader APIs
- pseudocode/disassembly text matching calls like `get_cgi("foo")`

Typical fields:

- `name`
- `reader_api`
- `param_source`
- `default`
- `source`
- `function`
- `function_addr`
- `evidence`

### `constraints`

Lightweight parameter/value constraints inferred from function text.

Current sources include patterns such as:

- `atoi`, `strtol`
- `strlen(...) < N`
- `strcmp(...)`
- `sscanf(...)`
- `inet_addr(...)`
- numeric comparisons in `if` conditions

Typical fields:

- `kind`
- `target`
- `value`
- `operator`
- `function`
- `function_addr`
- `source`
- `evidence`

### `config_accesses`

Read/write accesses to configuration backends such as:

- `nvram_*`
- `uci_*`
- `apmib_*`
- `mib_*`
- `config_*`

Typical fields:

- `api`
- `access_type`
- `key`
- `source`
- `function`
- `function_addr`
- `evidence`

### `sinks`

Potentially dangerous sinks and state-changing operations inferred from import
references.

Current sink categories include:

- `command`
- `memory`
- `file`
- `config`
- `state`
- `network`

Typical fields:

- `api`
- `category`
- `function`
- `function_addr`
- `xref_addr`
- `snippet`
- `evidence`

### `response_strings`

Strings that look useful as HTTP feedback or pseudo-coverage signals.

Typical fields:

- `value`
- `addr`
- `evidence`

### `auth_hints`

Authentication-related strings, such as:

- login/logout/session
- password/passwd
- auth/token/cookie/admin

Typical fields:

- `hint`
- `kind`
- `addr`
- `evidence`

### `state_hints`

Strings suggesting state-changing behavior, such as:

- apply/save
- reboot/restart
- reset/restore
- upgrade/commit

Typical fields:

- `hint`
- `kind`
- `addr`
- `evidence`

### `strings`

Filtered interesting strings retained for stage-2 reasoning.

These are not all raw strings from preprocessing. They are the subset that
matched route/auth/state/response/identifier-style heuristics and remain useful
for fuzzing-oriented interpretation.

Typical fields:

- `value`
- `addr`
- `categories`
- `xref_count`
- `xrefs`
- `evidence`

### `references`

General-purpose references kept for later fusion with frontend/config/readable
backend artifacts.

These include useful paths, route registrations, CGI references, filesystem
references, and environment-related strings that are worth preserving even when
they are not best represented as routes or parameters alone.

Typical fields:

- `value`
- `reference_type`
- `addr`
- `function`
- `function_addr`
- `evidence`

### `functions`

Filtered candidate function summaries relevant to the current Web analysis.

This is not the full function list from stage 1. It is a reduced set built
from:

- route/string references
- handler-name heuristics
- parameter-reader references
- config-access references
- sink references

Typical fields:

- `name`
- `addr`
- `size`
- `caller_count`
- `callee_count`

### `xrefs`

Compact cross-reference facts preserved from sink/config/parameter-related
evidence.

Typical fields:

- `kind`
- `api`
- `function`
- `function_addr`
- `xref_addr`
- `snippet`

### `callgraph_edges`

Filtered callgraph edges limited to candidate functions relevant to the Web
analysis.

Typical fields:

- `caller`
- `caller_addr`
- `callee`
- `callee_addr`
- `callsite`

### `analysis_warnings`

Warnings carried over from preprocessing, such as decompilation failures.

### `summary`

Compact counts for downstream inspection.

Observed fields include:

- `route_count`
- `handler_count`
- `route_mapping_count`
- `param_count`
- `constraint_count`
- `config_access_count`
- `sink_count`
- `response_string_count`
- `interesting_string_count`
- `candidate_function_count`
- `hint_categories`

### `pseudo_snippets`

Short extracted snippets from candidate functions that contain high-signal
tokens such as:

- parameter readers
- configuration APIs
- login/apply/reboot/upgrade logic

These snippets are meant as lightweight review aids, not full function dumps.

## Evidence Model

Most extracted facts carry an `evidence` list. A typical evidence object
contains:

- `source_file`
- `tool`
- `parser`
- `confidence`
- `function`
- `function_addr`
- `address`
- `snippet`

This lets you trace a stage-2 conclusion back to its originating preprocess
artifact and the specific function/text fragment that triggered it.

## Current Heuristics

The current stage-2 analyzer uses lightweight static heuristics rather than
full taint or semantic recovery.

Examples:

- route-like strings: `/goform/`, `/cgi-bin/`, `*.cgi`, `*.asp`, `/HNAP1/`
- handler-like function names: `*_cgi`, `*_handler`, `do_login_*`, `apply_*`
- parameter APIs: `websGetVar`, `cgiFormString`, `get_cgi`, `getenv`
- config APIs: `nvram_*`, `uci_*`, `apmib_*`, `config_*`
- sinks: `system`, `popen`, `strcpy`, `sprintf`, `open`, `socket`, etc.

These heuristics are intentionally explainable and evidence-driven. They are
useful for fuzzing preparation, but they should not be mistaken for precise
semantic reconstruction or vulnerability proof.

## Relationship To Stage 1

Stage 1 preserves broad context for auditability.

Stage 2 filters and interprets that context into a form more directly useful
for:

- seed construction
- sink-aware prioritization
- response-based feedback dictionaries
- route/handler/param correlation
- auth/state-change targeting

The recommended workflow is:

1. run `preprocess_web_backend_binaries.py`
2. inspect `*.preprocessed.json` when needed
3. run `analyze_preprocessed_web_backend.py`
4. consume `*.web_backend_binary_artifacts.json` in later fusion or fuzzing
