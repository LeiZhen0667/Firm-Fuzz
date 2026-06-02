# Skill: Web Backend Sources Parser Agent (Iteration Guide)

## 1. Purpose

Use this skill to incrementally improve `web_backend_sources_parser` so it can robustly extract reusable backend Web service facts from the given JSON input of readable GPL backend files.

This skill does not do vulnerability judging, payload generation, real-device probing, result filtering, endpoint ranking, or fuzz target selection.

## 2. Scope

Focus on stable extraction of:

- handlers / callbacks / dispatch entries
- routes / endpoints / CGI names
- route-to-handler mappings
- HTTP parameter reads
- parameter source locations (`query/body/cookie/header/env/unknown`)
- defaults, type hints, enum hints, length and format constraints
- config accesses (`nvram/uci/config/apmib` get/set/commit)
- sinks (`command/file/memory/network/config/state`)
- auth_hints / state_hints
- response strings / error strings / log strings / references
- evidence for every extracted fact

## 3. Core Principle for This Project

For this project stage, do:

1. run the parser on the given JSON input
2. compare source content vs extracted output
3. add missing generic extraction patterns
4. keep extraction results as complete facts

Do **not** do:

1. post-extraction judging/ranking/scoring
2. source-level filtering by perceived value
3. endpoint quality screening
4. vulnerability or exploitability evaluation
5. fuzzing payload generation
6. real-device probing
7. evaluator-like selection logic

Reason: evaluation, filtering, ranking, risk scoring, seed prioritization, and fuzz scheduling are handled later by dedicated evaluator / fusion / seed / fuzzer modules. The parser stage should preserve backend facts and evidence as completely as possible.

## 4. Execution Entry

```bash
python3 analyzer/web_backend_sources_parser/web_backend_sources_parser.py <input_json> -o <output_json>
```

Input is the given JSON file containing readable backend source candidate files.

The expected input structure is:

```json
{
  "version": "1.0",
  "input_type": "web_backend_sources",
  "files": [
    {
      "source_file": "...",
      "content": "..."
    }
  ]
}
```

The parser should read `files[].source_file` and `files[].content`. Do not require access to the original GPL worktree.

## 5. Expected Output

Write JSON to the `-o` path. The output should include extracted facts such as:

- `handlers`
- `routes`
- `route_mappings`
- `params`
- `constraints`
- `config_accesses`
- `sinks`
- `auth_hints`
- `state_hints`
- `strings`
- `references`
- `parse_warnings`
- `summary`

Every extracted object should include evidence when possible:

```json
{
  "source_file": "...",
  "parser": "...",
  "pattern": "...",
  "line": 0,
  "snippet": "..."
}
```

## 6. Per-Iteration Workflow (must follow)

1. Run the current script first. Do not modify code before seeing current output.
2. Inspect the given JSON input and parser output.
3. Compare `content` against extracted fields.
4. Summarize missed **generic** patterns.
5. Map each missed pattern to a local parser area:
   - `handler_parser`
   - `route_parser`
   - `param_read_parser`
   - `constraint_parser`
   - `config_access_parser`
   - `sink_parser`
   - `auth_state_parser`
   - `string_reference_parser`
   - `evidence_fusion`
6. Prefer rule/regex additions. Change Python only when rules are insufficient.
7. Keep the patch minimal and local. Do not rewrite the framework.
8. Run lightweight self-check and ensure JSON validity.
9. Report:
   - changed files
   - new generic patterns
   - improved fields
   - remaining extraction gaps for next iteration

## 7. Generic Pattern Policy

Add patterns only when they are reusable across firmware projects or common embedded Web backends.

Allowed patterns:

- common CGI / HTTP parameter getter functions
- common route / handler registration tables
- common dispatch key patterns such as `action`, `cmd`, `submit`, `page`, `handler`
- common C/C++ string and array initializer patterns
- common config access APIs
- common sink APIs
- common auth/session/token/password checks
- common state-changing operation names
- common response, error, and log string extraction
- common shell or backend helper call patterns

Do not add:

- vendor-specific hardcoding
- model-specific hardcoding
- absolute sample path hardcoding
- a rule matching only one observed file path
- a rule matching only one product endpoint
- logic that removes results because they look low value

If a pattern is uncertain but generic, keep it as a low-confidence extraction fact with evidence rather than filtering it out.

## 8. Pattern Areas

### 8.1 handler_parser

Extract backend handler declarations, callbacks, dispatch tables, and function names that may process Web requests.

Common patterns:

- handler registration arrays
- route-to-function tables
- `{ "url", handler_func }`
- `{ "action", "handler" }`
- `register_handler(...)`
- `websUrlHandlerDefine(...)`
- `websFormDefine(...)`
- `cgi_register(...)`
- function names ending in `_cgi`, `_handler`, `_asp`, `_form`, `_apply`, `_submit`

### 8.2 route_parser

Extract route, endpoint, CGI, ASP, and action strings from backend source.

Common patterns:

- `/goform/...`
- `/cgi-bin/...`
- `/api/...`
- `/HNAP1/`
- `*.cgi`
- `*.asp`
- `*.stm`
- route strings inside dispatch tables
- action/cmd/page values that select handlers
- redirect targets and response location headers

### 8.3 param_read_parser

Extract HTTP parameter names and parameter source locations.

Common patterns:

- `websGetVar(wp, "name", default)`
- `websGetVar2(...)`
- `cgiFormString("name", ...)`
- `cgiFormInteger("name", ...)`
- `getenv("QUERY_STRING")`
- `getenv("CONTENT_LENGTH")`
- `getenv("HTTP_COOKIE")`
- `getenv("REQUEST_METHOD")`
- `get_cgi("name")`
- `getVar("name")`
- `get_single("name")`
- `GetValue("name")`
- custom functions whose names contain `get`, `cgi`, `param`, `query`, `form`, `cookie`

### 8.4 constraint_parser

Extract local constraints around parameters.

Common patterns:

- `atoi(param)`, `atol`, `strtol`, `strtoul`
- `strlen(param) < N`, `strlen(param) > N`
- `sizeof(buffer)`
- `strcmp(param, "value")`
- `strncmp(param, "value", N)`
- `strcasecmp`
- `sscanf`
- `inet_addr`, `inet_aton`
- MAC/IP validation helper names
- null/empty checks
- min/max comparisons
- switch/case enum branches

### 8.5 config_access_parser

Extract configuration key reads/writes and their relation to parameters.

Common patterns:

- `nvram_get("key")`
- `nvram_safe_get("key")`
- `nvram_set("key", value)`
- `nvram_commit()`
- `uci_get`, `uci_set`, `uci_commit`
- `config_get`, `config_set`
- `apmib_get`, `apmib_set`
- `mib_get`, `mib_set`
- keys that appear near HTTP parameter reads
- defaults assigned from config keys

### 8.6 sink_parser

Extract sensitive backend operation points as facts.

Common sink categories:

- command: `system`, `popen`, `execl`, `execv`, `spawn`, backtick-like shell construction
- file: `fopen`, `open`, `unlink`, `remove`, `rename`, `chmod`, `chown`
- memory: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `memmove`, `gets`
- network: `socket`, `connect`, `send`, `recv`
- config/state: `nvram_commit`, `uci_commit`, reboot/restart/apply functions
- firmware: upgrade, restore, flash write, image validation functions

Do not infer a vulnerability from a sink. Only extract the sink fact and nearby evidence.

### 8.7 auth_state_parser

Extract authentication, authorization, session, token, and state-change hints.

Common patterns:

- `login`, `logout`, `auth`, `admin`, `privilege`, `permission`
- `password`, `passwd`, `pwd`
- `session`, `sid`, `cookie`, `token`, `csrf`, `nonce`
- `check_login`, `is_admin`, `auth_check`
- `apply`, `save`, `commit`, `reboot`, `restart`, `reset`, `restore`, `upgrade`
- redirects to login pages
- forbidden/unauthorized response strings

### 8.8 string_reference_parser

Extract backend strings useful for later response matching and pseudo-coverage.

Common patterns:

- error messages
- success messages
- log strings
- response body fragments
- redirect locations
- content-type strings
- HTML snippets emitted by backend code
- diagnostics and branch-specific messages

## 9. Constraints

- No vendor/model/sample hardcoding.
- No one-file special cases.
- No filtering/scoring/ranking/judging logic in extractor stage.
- No payload generation.
- No real-device probing.
- No destructive operations.
- Do not delete uncertain facts solely because they may be low value.
- Preserve extraction evidence.
- Keep output as complete extraction facts; let evaluator and fusion modules filter later.

## 10. Self-check Commands

```bash
python3 -m py_compile analyzer/web_backend_sources_parser/*.py analyzer/web_backend_sources_parser/parsers/*.py
python3 analyzer/web_backend_sources_parser/web_backend_sources_parser.py <input_json> -o /tmp/web_backend_sources_artifacts.json
python3 -m json.tool /tmp/web_backend_sources_artifacts.json > /dev/null
```

If the project does not yet have submodules under `parsers/`, compile the available parser files only:

```bash
python3 -m py_compile analyzer/web_backend_sources_parser/*.py
```

## 11. Change Report Format

After each iteration, report:

```text
Changed files:
New generic patterns:
Improved extracted fields:
Self-check result:
Remaining extraction gaps:
```

The report should describe extraction improvements only. Do not rank endpoint usefulness, do not filter results, and do not evaluate whether extracted objects are good fuzzing targets.
