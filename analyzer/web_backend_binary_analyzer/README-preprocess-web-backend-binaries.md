# Preprocess Web Backend Binaries

## Goal

`preprocess_web_backend_binaries.py` is the stage-1 entrypoint for unreadable
Web backend binaries.

Its job is to run IDA in headless/batch mode and save a full intermediate JSON
artifact for each binary before any Web-specific filtering or fuzzing-oriented
inference happens.

This script is intended for offline preprocessing. The output is designed for:

- manual review of binary contents
- later stage-2 Web analysis
- artifact caching and reuse
- debugging extraction quality
- preserving rich context that would otherwise be lost by early filtering

## What The Script Does

For each binary candidate, the script:

1. discovers candidate binaries under the given input path
2. resolves an IDA batch executable such as `idat.exe` or `idat64.exe`
3. launches IDA in headless mode
4. runs `ida_scripts/export_full_context.py` inside IDA
5. saves one `*.preprocessed.json` file per binary
6. saves one `*.ida.log` file per binary
7. prints and optionally saves a JSON summary of batch status

The script does not try to decide which functions are relevant to Web fuzzing.
It preserves broad intermediate context so later analysis can make that
decision with more evidence.

## Input

The input can be:

- a single binary file
- a directory containing binaries
- a directory tree when `--recursive` is used

By default, candidate discovery ignores side files such as:

- `.i64`
- `.id0`
- `.id1`
- `.id2`
- `.nam`
- `.til`
- common text/config/script extensions

Object files such as `.o` are included by default because vendor GPL drops
often place small CGI/helper objects next to the main HTTP daemon.

## Usage

Basic example:

```powershell
python analyzer/web_backend_binary_analyzer/preprocess_web_backend_binaries.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --recursive
```

Save outputs to explicit directories:

```powershell
python analyzer/web_backend_binary_analyzer/preprocess_web_backend_binaries.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --recursive `
  --output-dir analyzer/web_backend_binary_analyzer/output/preprocessed/Linksys_e1200_v1.0.04.001_us `
  --log-dir analyzer/web_backend_binary_analyzer/output/logs/Linksys_e1200_v1.0.04.001_us `
  --summary-out analyzer/web_backend_binary_analyzer/output/preprocessed/Linksys_e1200_v1.0.04.001_us.preprocess.summary.json
```

Use a specific IDA batch executable:

```powershell
python analyzer/web_backend_binary_analyzer/preprocess_web_backend_binaries.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --recursive `
  --ida-batch "C:/Users/admin/Desktop/IDA Professional_9.1/idat.exe"
```

Reduce output size by skipping full pseudocode:

```powershell
python analyzer/web_backend_binary_analyzer/preprocess_web_backend_binaries.py `
  collector/output/unreadable_files/web_backend_sources/Linksys_e1200_v1.0.04.001_us `
  --recursive `
  --no-pseudocode
```

## Command-Line Options

- `input_path`
  Binary file or directory of binary candidates.
- `-o`, `--output-dir`
  Directory where `*.preprocessed.json` files are written.
- `--log-dir`
  Directory where per-binary IDA batch logs are written.
- `--ida-batch`
  Path to a batch-capable IDA executable such as `idat.exe`, `idat64.exe`,
  `ida.exe`, or `ida64.exe`.
- `--ida-script`
  IDA Python script used for export. Defaults to
  `ida_scripts/export_full_context.py`.
- `--recursive`
  Recurse into subdirectories when the input is a directory.
- `--exclude-object-files`
  Skip relocatable object files such as `.o`.
- `--timeout-seconds`
  Per-binary timeout for headless preprocessing.
- `--min-string-len`
  Minimum string length exported by the IDA script.
- `--no-pseudocode`
  Do not export full decompiled pseudocode for each function.
- `--no-disassembly`
  Do not export full disassembly for each function.
- `--no-reuse-existing-idb`
  Force IDA to open the original binary path instead of an existing `.i64` or
  `.idb`.
- `--summary-out`
  Optional output path for the batch summary JSON.

## Output Files

The script writes three kinds of output.

### 1. Per-binary preprocess artifacts

File naming:

```text
<relative.binary.path>.preprocessed.json
```

Examples:

- `httpd.preprocessed.json`
- `upnp.preprocessed.json`
- `login.o.preprocessed.json`

### 2. Per-binary IDA logs

File naming:

```text
<relative.binary.path>.ida.log
```

These logs are useful when IDA exits with a non-zero code or when a sample
needs special handling.

### 3. Batch summary JSON

If `--summary-out` is provided, the script also writes a JSON file describing
which binaries succeeded, failed, timed out, or produced partial results.

## Preprocess JSON Structure

The output artifact type is:

```json
"artifact_type": "web_backend_binary_preprocessed"
```

Top-level structure:

```json
{
  "version": "1.0",
  "artifact_type": "web_backend_binary_preprocessed",
  "input_type": "unreadable_web_backend_binary",
  "binary": {},
  "imports": [],
  "exports": [],
  "names": [],
  "strings": [],
  "functions": [],
  "callgraph_edges": [],
  "analysis_warnings": [],
  "summary": {}
}
```

## Field Meanings

### `binary`

Describes the binary itself.

Observed fields:

- `source_file`
  Original binary path.
- `idb_path`
  IDA input/database path used during export.
- `sha256`
  SHA-256 of the binary file.
- `size`
  Binary size in bytes.
- `format`
  IDA-recognized file format.
- `arch`
  Processor family string from IDA.
- `bits`
  Bitness reported by IDA.
- `endian`
  `little` or `big`.
- `entry`
  Entry address in hex.
- `segments`
  Segment list with start/end/size/permissions.

### `imports`

All imports enumerated from the binary.

Each row contains:

- `module`
- `name`
- `ordinal`
- `addr`

### `exports`

All exports or IDA entry records.

Each row contains:

- `index`
- `ordinal`
- `addr`
- `name`

### `names`

Named symbols known to IDA.

Each row contains:

- `addr`
- `name`

### `strings`

All exported strings that meet `--min-string-len`.

Each string record contains:

- `addr`
- `length`
- `type`
- `value`
- `xrefs`

Each string xref contains:

- `xref_addr`
- `function_addr`
- `function_name`
- `snippet`
- `xref_type`

### `functions`

This is the most important intermediate section. It preserves per-function
context before any Web-specific filtering.

Each function record contains:

- `addr`
  Function start address.
- `name`
  Function name as known by IDA.
- `start_ea`
  Function start address again in hex.
- `end_ea`
  Function end address in hex.
- `size`
  Function size in bytes.
- `prototype`
  IDA type/prototype string if available.
- `flags`
  Raw IDA function flags.
- `segment`
  Segment name containing the function.
- `callers`
  Incoming code references with callsites.
- `callees`
  Outgoing code references with callsites.
- `string_refs`
  Data references from the function to recognized strings.
- `import_refs`
  Calls from the function to imported APIs.
- `data_refs`
  Other named data references used by the function.
- `disassembly`
  Full per-instruction disassembly when not disabled.
- `pseudocode`
  Full decompiled pseudocode when not disabled and decompilation succeeds.
- `decompile_error`
  Error string when pseudocode export fails.

#### `callers`

Each row contains:

- `function_addr`
- `function_name`
- `callsite`
- `snippet`

#### `callees`

Each row contains:

- `function_addr`
- `function_name`
- `callsite`
- `snippet`

#### `string_refs`

Each row contains:

- `string_addr`
- `xref_addr`
- `snippet`

#### `import_refs`

Each row contains:

- `name`
- `module`
- `import_addr`
- `xref_addr`
- `snippet`

#### `data_refs`

Each row contains:

- `target_addr`
- `target_name`
- `xref_addr`
- `snippet`

#### `disassembly`

When enabled, each instruction row contains:

- `addr`
- `size`
- `bytes`
- `text`

### `callgraph_edges`

Global caller-to-callee edges across all discovered functions.

Each row contains:

- `caller`
- `caller_addr`
- `callee`
- `callee_addr`
- `callsite`

### `analysis_warnings`

Warnings produced during export, for example decompilation failures.

Typical fields include:

- `level`
- `kind`
- `function_addr`
- `function_name`
- `message`

### `summary`

Compact counts for quick inspection.

Observed fields:

- `import_count`
- `export_count`
- `name_count`
- `string_count`
- `function_count`
- `callgraph_edge_count`

## Failure Handling

This script contains several recovery behaviors to improve batch stability.

### Existing IDB reuse

By default, if a `.i64` or `.idb` already exists next to the binary, the script
tries to reuse it. This is usually faster.

### Access-denied recovery

If IDA cannot open an existing database because it is already in use, the
driver retries automatically:

1. retry with `-c` to force a fresh database
2. if the source path still conflicts, copy the binary into a temporary
   directory and preprocess it there in isolation

This behavior is especially useful when the same sample is open in GUI IDA.

### Partial results

If IDA returns a non-zero code but the JSON artifact still exists, the batch
status may be marked as `partial` instead of `failed`.

## Review Recommendations

When manually reviewing the intermediate output, the most useful sections are
usually:

- `functions`
- `strings`
- `imports`
- `callgraph_edges`
- `analysis_warnings`

If you want to understand what a function actually contains, inspect:

- `functions[].pseudocode`
- `functions[].disassembly`
- `functions[].string_refs`
- `functions[].import_refs`
- `functions[].callers`
- `functions[].callees`

## Relationship To Stage 2

This script does not emit fuzzing-oriented Web conclusions directly.

Instead, its output is meant to be consumed by:

[analyze_preprocessed_web_backend.py](G:\GPLFuzz\analyzer\web_backend_binary_analyzer\analyze_preprocessed_web_backend.py)

That second-stage analyzer reads the full intermediate context and derives:

- route candidates
- handler candidates
- parameters
- lightweight constraints
- config accesses
- sinks
- auth hints
- state hints
- response strings
