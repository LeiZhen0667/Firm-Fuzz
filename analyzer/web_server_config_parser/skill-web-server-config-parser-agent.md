# Skill: Web Server Config Parser Agent (Iteration Guide)

## 1. Purpose

Use this skill to incrementally improve `web_server_config_parser` so it can robustly extract reusable Web server deployment knowledge from the given JSON input of readable GPL files.

This skill does not do vulnerability judging, payload generation, real-device probing, or post-extraction filtering.

## 2. Scope

Focus on stable extraction of:

- Web server type (`boa/httpd/goahead/lighttpd/nginx/busybox httpd/custom httpd`)
- listeners (`address/port/protocol`)
- document root / server root / web root
- alias / location / static directory mappings
- CGI mappings (`CGIPath`, `ScriptAlias`, `cgi-bin`, `*.cgi`, handler extension rules)
- auth rules (`auth directory`, `realm`, `password file`, `access control`)
- startup commands (`httpd`, `boa`, `goahead`, `lighttpd`, `nginx` command lines and config paths)
- config references (`include`, extra config files, referenced roots)
- routes / route prefixes derived from configuration
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
4. route usefulness evaluation
5. security risk evaluation
6. any evaluator-like selection logic

Reason: result evaluation, filtering, ranking, and seed prioritization are handled later by dedicated evaluator / fusion / seed modules. The parser stage should preserve facts and evidence as completely as possible.

## 4. Execution Entry

```bash
python3 analyzer/web_server_config_parser/web_server_config_parser.py <input_json> -o <output_json>
```

Input is the given JSON file containing readable Web server config candidate sources.

The expected input structure is:

```json
{
  "version": "1.0",
  "input_type": "web_server_config_sources",
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

- `servers`
- `listeners`
- `document_roots`
- `aliases`
- `cgi_mappings`
- `auth_rules`
- `startup_commands`
- `config_references`
- `routes`
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

1. Run current script first. Do not modify code before seeing current output.
2. Inspect the given JSON input and the parser output.
3. Compare `content` against extracted fields.
4. Summarize missed **generic** patterns.
5. Map each missed pattern to a local parser area:
   - `server_type_parser`
   - `listener_parser`
   - `root_alias_parser`
   - `cgi_mapping_parser`
   - `auth_rule_parser`
   - `startup_command_parser`
   - `config_reference_parser`
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

Add patterns only when they are reusable across firmware projects or common Web server configurations.

Allowed patterns:

- common Web server directives
- common startup command forms
- common CGI alias and handler forms
- common document root / server root directives
- common auth / password-file directives
- common include / config-reference syntax
- common shell command-line options for Web servers

Do not add:

- vendor-specific hardcoding
- model-specific hardcoding
- absolute sample path hardcoding
- a rule matching only one observed file path
- a rule matching only one product page or single route
- logic that removes results because they look low value

If a pattern is uncertain but generic, keep it as a low-confidence extraction fact with evidence rather than filtering it out.

## 8. Pattern Areas

### 8.1 server_type_parser

Extract Web server identity from config directives, filenames, comments, startup commands, and option names.

Common targets:

- `boa`
- `httpd`
- `busybox httpd`
- `goahead`
- `lighttpd`
- `nginx`
- custom `httpd` command names

### 8.2 listener_parser

Extract listening port, address, and protocol.

Common patterns:

- `Port 80`
- `Listen 80`
- `listen 0.0.0.0:80`
- `server.port = 80`
- `-p 80`
- `-p 0.0.0.0:80`
- `HTTP_PORT=80`

### 8.3 root_alias_parser

Extract document roots, server roots, aliases, and static directory mappings.

Common patterns:

- `DocumentRoot ...`
- `ServerRoot ...`
- `server.document-root = "..."`
- `root /www;`
- `alias.url += (...)`
- `Alias /url /path`
- `-h /www`

### 8.4 cgi_mapping_parser

Extract CGI-related URL and filesystem mappings.

Common patterns:

- `ScriptAlias /cgi-bin/ /path/cgi-bin/`
- `CGIPath /cgi-bin/`
- `AddHandler cgi-script .cgi`
- `cgi.assign = (...)`
- `fastcgi.server = (...)`
- `location /cgi-bin/`
- `*.cgi`
- command-line cgi root/options

### 8.5 auth_rule_parser

Extract authentication and access-control facts.

Common patterns:

- `AuthType`
- `AuthName`
- `AuthUserFile`
- `Require user`
- `allow/deny`
- `satisfy any/all`
- `realm`
- `userfile`
- `.htpasswd`
- basic-auth related options

### 8.6 startup_command_parser

Extract Web server process startup commands and their arguments from shell/init/config content.

Common patterns:

- `httpd -p ... -h ... -c ...`
- `boa -c ...`
- `goahead ...`
- `lighttpd -f ...`
- `nginx -c ... -p ...`
- environment variables used in these commands

### 8.7 config_reference_parser

Extract references to additional config files, include directives, roots, and scripts.

Common patterns:

- `include ...`
- `include_shell ...`
- `. /path/file`
- `source /path/file`
- `-c /path/config`
- `-f /path/config`

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
python3 -m py_compile analyzer/web_server_config_parser/*.py analyzer/web_server_config_parser/parsers/*.py
python3 analyzer/web_server_config_parser/web_server_config_parser.py <input_json> -o /tmp/web_server_config_artifacts.json
python3 -m json.tool /tmp/web_server_config_artifacts.json > /dev/null
```

If the project does not yet have submodules under `parsers/`, compile the available parser files only:

```bash
python3 -m py_compile analyzer/web_server_config_parser/*.py
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
