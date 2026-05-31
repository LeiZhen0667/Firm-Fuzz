# Skill: Web Frontend Parser Agent (Iteration Guide)

## 1. Purpose

Use this skill to incrementally improve `web_frontend_analyzer` so it can robustly extract reusable frontend interface knowledge from real firmware web files.

This skill does not do vulnerability judging, payload generation, or destructive probing.

## 2. Scope

Focus on stable extraction of:

- routes / methods
- params (`name/location/default/options`)
- constraints (`maxlength/minlength/pattern/required/readonly/disabled/enctype`)
- auth_hints / state_hints
- ui_context / template_vars / references

## 3. Core Principle for This Project

For this project stage, do:

1. discover and compare web content vs extracted output
2. add missing generic extraction patterns

Do **not** do:

1. post-extraction judging/ranking/scoring
2. source-level filtering by perceived value
3. endpoint quality screening
4. any evaluator-like selection logic

Reason: result evaluation and filtering are handled later by a dedicated evaluator module.

## 4. Execution Entry

```bash
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py <input> -o <output_json>
```

Input types:

- file path
- directory path
- JSON input (`--input-format json`)

## 5. Per-Iteration Workflow (must follow)

1. Run current script first (do not modify code first).
2. Compare source content vs extraction output.
3. Summarize missed **generic** patterns.
4. Map each pattern to module:
   - `html_form_parser`
   - `js_api_parser`
   - `template_parser`
   - `regex_route_miner`
   - `param_name_miner`
   - `ui_context_parser`
   - `auth_token_parser`
   - `evidence_fusion`
5. Prefer rule/regex additions; change code only when rules are insufficient.
6. Keep patch minimal and local (no framework rewrite).
7. Run lightweight self-check and ensure JSON validity.
8. Report:
   - changed files
   - new generic patterns
   - improved fields
   - remaining gaps for next iteration

## 6. Constraints

- No vendor/model/sample hardcoding.
- No one-page special cases.
- No filtering/scoring/ranking/judging logic in extractor stage.
- Keep output as complete extraction facts; let evaluator filter later.

## 7. Self-check Commands

```bash
python3 -m py_compile analyzer/web_frontend_analyzer/*.py
python3 analyzer/web_frontend_analyzer/web_frontend_analyzer.py <input> -o /tmp/frontend_artifacts.json
python3 -m json.tool /tmp/frontend_artifacts.json > /dev/null
```

