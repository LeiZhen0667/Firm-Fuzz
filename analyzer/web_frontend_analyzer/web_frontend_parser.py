#!/usr/bin/env python3
"""Parse web frontend files and emit normalized analyzer artifacts.

The parser is intentionally generic and vendor-agnostic.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit


FRONTEND_EXTENSIONS = {".html", ".htm", ".asp", ".stm", ".shtml", ".php"}
STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
}
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

AUTH_KEYWORDS = {
    "auth": "auth",
    "csrf": "csrf",
    "login": "login",
    "logout": "logout",
    "nonce": "nonce",
    "passwd": "password",
    "password": "password",
    "session": "session",
    "sid": "session",
    "token": "token",
    "cookie": "cookie",
}
STATE_KEYWORDS = {
    "apply": "apply",
    "commit": "save",
    "reboot": "reboot",
    "reset": "reset",
    "restart": "restart",
    "restore": "restore",
    "save": "save",
    "upgrade": "upgrade",
}


@dataclass
class Route:
    url: str
    method: str
    source: str
    ui_context: Optional[str] = None
    confidence: str = "medium"
    evidence: List[str] = field(default_factory=list)


@dataclass
class Param:
    name: str
    location: str
    inferred_type: str
    default: Optional[str]
    required: Optional[bool]
    options: List[str]
    route: Optional[str]
    source: str = "html_form_parser"
    confidence: str = "medium"
    evidence: List[str] = field(default_factory=list)


@dataclass
class Constraint:
    param: str
    kind: str
    value: str
    source: str
    confidence: str = "medium"
    evidence: List[str] = field(default_factory=list)


@dataclass
class Hint:
    kind: str
    value: str
    source: str
    confidence: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class TemplateVar:
    name: str
    function: str
    source: str
    confidence: str
    evidence: List[str] = field(default_factory=list)


class FrontendHTMLExtractor(HTMLParser):
    def __init__(self, source_file: Path):
        super().__init__(convert_charrefs=True)
        self.source_file = str(source_file)

        self.routes: List[Route] = []
        self.params: List[Param] = []
        self.constraints: List[Constraint] = []
        self.auth_hints: List[Hint] = []
        self.state_hints: List[Hint] = []
        self.sinks: List[dict] = []
        self.references: Set[str] = set()
        self.ui_context: Set[str] = set()

        self._current_form: Optional[Dict[str, str]] = None
        self._in_title = False
        self._title_chunks: List[str] = []
        self._text_capture_tag: Optional[str] = None
        self._text_capture_attrs: Dict[str, str] = {}
        self._text_capture_chunks: List[str] = []

        self._select_name: Optional[str] = None
        self._select_options: List[str] = []
        self._select_required = False
        self._select_disabled = False
        self._select_route: Optional[str] = None
        self._select_source = ""

    @property
    def title(self) -> Optional[str]:
        title = " ".join(part.strip() for part in self._title_chunks if part.strip()).strip()
        return title or None

    def handle_starttag(self, tag: str, attrs):
        raw_tag = tag
        tag = tag.lower()
        attr = {k.lower(): v for k, v in attrs}

        if tag == "title":
            self._in_title = True
            self._start_text_capture(tag, attr)

        if tag in {"h1", "h2", "h3", "label", "button", "option", "a", "li"}:
            self._start_text_capture(tag, attr)

        if tag == "form":
            action = (attr.get("action") or "").strip()
            method = (attr.get("method") or "GET").strip().upper()
            enctype = (attr.get("enctype") or "").strip().lower()

            if action:
                self.routes.append(
                    Route(
                        url=action,
                        method=method or "GET",
                        source="html_form_parser",
                        ui_context=self.title,
                        confidence="high",
                        evidence=[f"<form action={action!r} method={method or 'GET'!r}>"],
                    )
                )
                self.references.add(action)
                _add_query_params(
                    action,
                    self.params,
                    route=action,
                    source="html_form_parser",
                    confidence="high",
                    evidence=f"query string in form action {action!r}",
                )

            self._current_form = {
                "action": action or None,
                "method": method or "GET",
                "enctype": enctype,
            }

            if enctype:
                self.constraints.append(
                    Constraint(
                        param="*",
                        kind="content_type",
                        value=enctype,
                        source=f"form:{action or '<unknown>'}",
                        confidence="high",
                        evidence=[f"<form enctype={enctype!r}>"],
                    )
                )

        if tag in {"input", "textarea"}:
            self._handle_input_like(tag, attr)

        if tag == "select":
            self._select_name = (attr.get("name") or "").strip() or None
            self._select_options = []
            self._select_required = "required" in attr
            self._select_disabled = "disabled" in attr
            self._select_route = self._current_form["action"] if self._current_form else None
            self._select_source = _format_tag(raw_tag, attr, ["name", "required", "disabled"])

        if tag == "option" and self._select_name:
            option_value = (attr.get("value") or "").strip()
            if option_value:
                self._select_options.append(option_value)

        if tag in {"a", "iframe", "frame", "script", "link"}:
            link_attr = "src" if tag in {"iframe", "frame", "script"} else "href"
            if tag == "link":
                link_attr = "href"
            href = (attr.get(link_attr) or "").strip()
            if href and not href.startswith("#"):
                self.references.add(href)
                self._add_keyword_hints(href, f"{tag}:{href}", confidence="medium")

        if tag == "meta":
            content = (attr.get("content") or "").strip()
            if content:
                self._add_keyword_hints(content, _format_tag("meta", attr, ["name", "http-equiv", "content"]))

        if tag == "a":
            href = (attr.get("href") or "").strip()
            if href and not href.startswith("#"):
                self.references.add(href)
                if _looks_like_route(href):
                    self.routes.append(
                        Route(
                            url=href,
                            method="GET",
                            source="html_link_parser",
                            ui_context=self.title,
                            confidence="medium",
                            evidence=[f"<a href={href!r}>"],
                        )
                    )

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False

        if tag == "form":
            self._current_form = None

        if tag == "select" and self._select_name:
            self.params.append(
                Param(
                    name=self._select_name,
                    location="body",
                    inferred_type="enum" if self._select_options else "string",
                    default=None,
                    required=self._select_required,
                    options=list(dict.fromkeys(self._select_options)),
                    route=self._select_route,
                    source="html_form_parser",
                    confidence="high",
                    evidence=[self._select_source or f"<select name={self._select_name!r}>"],
                )
            )
            if self._select_options:
                self.constraints.append(
                    Constraint(
                        param=self._select_name,
                        kind="enum",
                        value="|".join(dict.fromkeys(self._select_options)),
                        source=f"select:{self._select_name}",
                        confidence="high",
                        evidence=[f"<option> values for select {self._select_name!r}"],
                    )
                )
            if self._select_required:
                self.constraints.append(
                    Constraint(
                        param=self._select_name,
                        kind="required",
                        value="true",
                        source=f"select:{self._select_name}",
                        confidence="high",
                        evidence=[self._select_source or f"<select name={self._select_name!r} required>"],
                    )
                )
            if self._select_disabled:
                self.constraints.append(
                    Constraint(
                        param=self._select_name,
                        kind="disabled",
                        value="true",
                        source=f"select:{self._select_name}",
                        confidence="high",
                        evidence=[self._select_source or f"<select name={self._select_name!r} disabled>"],
                    )
                )
            self._select_name = None
            self._select_options = []
            self._select_required = False
            self._select_disabled = False
            self._select_route = None
            self._select_source = ""

        if tag == self._text_capture_tag:
            text = _clean_text(" ".join(self._text_capture_chunks))
            if text:
                if tag == "title":
                    self.ui_context.add(f"title:{text}")
                elif tag in {"h1", "h2", "h3"}:
                    self.ui_context.add(f"heading:{text}")
                elif tag == "label":
                    label_for = self._text_capture_attrs.get("for")
                    suffix = f" for={label_for}" if label_for else ""
                    self.ui_context.add(f"label:{text}{suffix}")
                elif tag in {"button", "option", "a", "li"}:
                    self.ui_context.add(f"{tag}:{text}")
                self._add_keyword_hints(text, f"{tag} text:{text}", confidence="medium")
            self._text_capture_tag = None
            self._text_capture_attrs = {}
            self._text_capture_chunks = []

    def handle_data(self, data: str):
        if self._in_title:
            self._title_chunks.append(data)
        if self._text_capture_tag:
            self._text_capture_chunks.append(data)

    def _handle_input_like(self, tag: str, attr: Dict[str, str]):
        name = (attr.get("name") or "").strip()
        if not name:
            return

        input_type = (attr.get("type") or ("textarea" if tag == "textarea" else "text")).lower()
        default_value = attr.get("value")
        required = "required" in attr
        disabled = "disabled" in attr
        readonly = "readonly" in attr
        route = self._current_form["action"] if self._current_form else None

        inferred_type = self._infer_type(name=name, input_type=input_type)
        evidence = _format_tag(tag, attr, ["name", "type", "value", "maxlength", "pattern", "required", "disabled", "readonly"])

        param = Param(
            name=name,
            location="body" if self._current_form else "unknown",
            inferred_type=inferred_type,
            default=default_value,
            required=required,
            options=[],
            route=route,
            source="html_form_parser",
            confidence="high" if self._current_form else "medium",
            evidence=[evidence],
        )
        self.params.append(param)

        for attr_name, kind in [
            ("maxlength", "max_length"),
            ("minlength", "min_length"),
            ("min", "min"),
            ("max", "max"),
            ("pattern", "regex"),
        ]:
            attr_value = attr.get(attr_name)
            if attr_value:
                self.constraints.append(
                    Constraint(
                        param=name,
                        kind=kind,
                        value=attr_value,
                        source=f"input:{name}",
                        confidence="high",
                        evidence=[evidence],
                    )
                )

        for flag, kind in [(required, "required"), (disabled, "disabled"), (readonly, "readonly")]:
            if flag:
                self.constraints.append(
                    Constraint(
                        param=name,
                        kind=kind,
                        value="true",
                        source=f"input:{name}",
                        confidence="high",
                        evidence=[evidence],
                    )
                )

        lower_name = name.lower()
        if input_type == "hidden" and any(k in lower_name for k in ["token", "csrf", "nonce"]):
            self._add_hint(self.auth_hints, kind=_keyword_kind(lower_name, AUTH_KEYWORDS) or "token", value=name, source=f"input:{name}", confidence="high", evidence=evidence)
            self.constraints.append(
                Constraint(
                    param=name,
                    kind="security_token",
                    value="hidden_input",
                    source=f"input:{name}",
                    confidence="high",
                    evidence=[evidence],
                )
            )

        self._add_keyword_hints(name, f"param:{name}", confidence="high", evidence=evidence)
        if default_value:
            self._add_keyword_hints(default_value, f"default:{name}", confidence="medium", evidence=evidence)

    def _start_text_capture(self, tag: str, attrs: Dict[str, str]) -> None:
        self._text_capture_tag = tag
        self._text_capture_attrs = attrs
        self._text_capture_chunks = []

    def _add_keyword_hints(
        self,
        text: str,
        source: str,
        confidence: str = "medium",
        evidence: Optional[str] = None,
    ) -> None:
        lower_text = text.lower()
        auth_kind = _keyword_kind(lower_text, AUTH_KEYWORDS)
        if auth_kind:
            self._add_hint(self.auth_hints, auth_kind, text, source, confidence, evidence or text)
        state_kind = _keyword_kind(lower_text, STATE_KEYWORDS)
        if state_kind:
            self._add_hint(self.state_hints, state_kind, text, source, confidence, evidence or text)

    @staticmethod
    def _add_hint(
        hints: List[Hint],
        kind: str,
        value: str,
        source: str,
        confidence: str,
        evidence: str,
    ) -> None:
        hints.append(
            Hint(
                kind=kind,
                value=value,
                source=source,
                confidence=confidence,
                evidence=[evidence],
            )
        )

    @staticmethod
    def _infer_type(name: str, input_type: str) -> str:
        n = name.lower()

        if input_type in {"checkbox", "radio"}:
            return "bool_or_enum"
        if input_type in {"number", "range"}:
            return "int"
        if input_type == "password":
            return "sensitive_string"
        if input_type == "file":
            return "file"

        if any(k in n for k in ["ip", "addr"]):
            return "ipv4_or_host"
        if any(k in n for k in ["port", "mtu", "vlan", "channel", "timeout", "interval"]):
            return "int"
        if any(k in n for k in ["mac"]):
            return "mac"
        if any(k in n for k in ["enable", "disable", "onoff", "switch"]):
            return "bool_or_enum"

        return "string"


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _format_tag(tag: str, attrs: Dict[str, Optional[str]], keys: Iterable[str]) -> str:
    rendered = []
    for key in keys:
        if key in attrs:
            value = attrs[key]
            rendered.append(key if value is None else f"{key}={value!r}")
    suffix = (" " + " ".join(rendered)) if rendered else ""
    return f"<{tag}{suffix}>"


def _keyword_kind(text: str, keywords: Dict[str, str]) -> Optional[str]:
    for keyword, kind in keywords.items():
        if keyword == "sid" and not re.search(r"(^|[^a-z0-9])sid([^a-z0-9]|$)", text):
            continue
        if keyword in text:
            return kind
    return None


def _looks_like_static_asset(value: str) -> bool:
    clean = value.split("?", 1)[0].split("#", 1)[0].lower()
    return any(clean.endswith(ext) for ext in STATIC_EXTENSIONS)


def _looks_like_route(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    lower_value = value.lower()
    if lower_value.startswith(("http://", "https://", "mailto:", "javascript:")):
        return False
    if _looks_like_static_asset(value):
        return False
    if value.startswith(("/", "./", "../")):
        return True
    return bool(re.search(r"(?:^|[A-Za-z0-9_.-])[\w./-]+\.(?:cgi|asp|php|htm|html)(?:\?[^'\"\s<>]*)?$", value))


def _route_evidence_confidence(source: str) -> str:
    if source in {"html_form_parser", "js_api_parser"}:
        return "high"
    if source in {"html_link_parser", "js_object_route_miner", "regex_route_miner"}:
        return "medium"
    return "low"


def _normalize_method(method: Optional[str]) -> str:
    if not method:
        return "GET"
    method = method.strip().strip("'\"").upper()
    return method if method in HTTP_METHODS else "GET"


def _add_query_params(
    url: str,
    params: List[Param],
    route: Optional[str],
    source: str,
    confidence: str,
    evidence: str,
) -> None:
    query = urlsplit(url).query
    for name, value in parse_qsl(query, keep_blank_values=True):
        if _valid_param_name(name):
            params.append(
                Param(
                    name=name,
                    location="query",
                    inferred_type=FrontendHTMLExtractor._infer_type(name, "text"),
                    default=value,
                    required=None,
                    options=[],
                    route=route,
                    source=source,
                    confidence=confidence,
                    evidence=[evidence],
                )
            )


def _valid_param_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$", name))


def _split_object_fields(object_text: str) -> List[str]:
    fields = []
    for match in re.finditer(r"['\"]?([A-Za-z_][\w.-]*)['\"]?\s*:", object_text):
        name = match.group(1)
        if name.lower() not in {"url", "uri", "action", "endpoint", "method", "type", "data", "params", "payload"}:
            fields.append(name)
    return fields


def _add_urlencoded_params(
    text: str,
    params: List[Param],
    route: Optional[str],
    source: str,
    confidence: str,
    evidence: str,
) -> None:
    for match in re.finditer(r"(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]{0,63})=", text):
        name = match.group(1)
        if _valid_param_name(name):
            params.append(
                Param(
                    name=name,
                    location="body",
                    inferred_type=FrontendHTMLExtractor._infer_type(name, "text"),
                    default=None,
                    required=None,
                    options=[],
                    route=route,
                    source=source,
                    confidence=confidence,
                    evidence=[evidence],
                )
            )


def _extract_inline_script_refs(content: str) -> Set[str]:
    refs = set()
    patterns = [
        r"location\.(?:href|assign|replace)\s*(?:=|\()\s*['\"]([^'\"]+)['\"]",
        r"window\.open\(\s*['\"]([^'\"]+)['\"]",
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, content, flags=re.IGNORECASE):
            refs.add(m.group(1))
    return refs


def _extract_regex_routes(content: str, ui_context: Optional[str]) -> Tuple[List[Route], List[Param], Set[str]]:
    routes: List[Route] = []
    params: List[Param] = []
    refs: Set[str] = set()
    route_pattern = re.compile(
        r"""(?P<quote>['"])(?P<url>(?:/[\w./-]+|[\w.-]+\.(?:cgi|asp|php|stm|shtml|htm|html)|\./[\w./-]+|\.\./[\w./-]+)(?:\?[^'"]*)?)(?P=quote)""",
        re.IGNORECASE,
    )
    for match in route_pattern.finditer(content):
        url = match.group("url")
        if not _looks_like_route(url):
            continue
        evidence = match.group(0)
        refs.add(url)
        routes.append(
            Route(
                url=url,
                method="GET",
                source="regex_route_miner",
                ui_context=ui_context,
                confidence="low" if _looks_like_static_asset(url) else "medium",
                evidence=[evidence],
            )
        )
        _add_query_params(
            url,
            params,
            route=url,
            source="param_name_miner",
            confidence="medium",
            evidence=f"query string in route literal {url!r}",
        )
    return routes, params, refs


def _extract_js_api(content: str, ui_context: Optional[str]) -> Tuple[List[Route], List[Param], Set[str], List[Hint]]:
    routes: List[Route] = []
    params: List[Param] = []
    refs: Set[str] = set()
    hints: List[Hint] = []

    def add_route(url: str, method: str, source: str, evidence: str, confidence: str = "high") -> None:
        if not _looks_like_route(url):
            return
        refs.add(url)
        routes.append(
            Route(
                url=url,
                method=_normalize_method(method),
                source=source,
                ui_context=ui_context,
                confidence=confidence,
                evidence=[evidence],
            )
        )
        _add_query_params(
            url,
            params,
            route=url,
            source="param_name_miner",
            confidence=confidence,
            evidence=f"query string in JS route {url!r}",
        )
        _collect_keyword_hints(url, source, confidence, hints, evidence)

    for match in re.finditer(r"fetch\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*(\{.*?\}))?\s*\)", content, re.IGNORECASE | re.DOTALL):
        url = match.group(1)
        options = match.group(2) or ""
        method_match = re.search(r"['\"]?method['\"]?\s*:\s*['\"]([A-Za-z]+)['\"]", options, re.IGNORECASE)
        method = method_match.group(1) if method_match else "GET"
        add_route(url, method, "js_api_parser", _clean_text(match.group(0)))
        _extract_js_object_params(options, params, route=url, evidence=_clean_text(match.group(0)))
        _add_urlencoded_params(options, params, route=url, source="param_name_miner", confidence="medium", evidence=_clean_text(match.group(0)))

    for match in re.finditer(r"\.open\(\s*['\"]([A-Za-z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE):
        method, url = match.group(1), match.group(2)
        add_route(url, method, "js_api_parser", _clean_text(match.group(0)))

    for match in re.finditer(r"\$\.(post|get)\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*(\{.*?\}|['\"].*?['\"]))?", content, re.IGNORECASE | re.DOTALL):
        method, url = match.group(1).upper(), match.group(2)
        data = match.group(3) or ""
        evidence = _clean_text(match.group(0))
        add_route(url, method, "js_api_parser", evidence)
        _extract_js_object_params(data, params, route=url, evidence=evidence)
        _add_urlencoded_params(data, params, route=url, source="param_name_miner", confidence="medium", evidence=evidence)

    for match in re.finditer(r"\$\.ajax\(\s*(\{.*?\})\s*\)", content, re.IGNORECASE | re.DOTALL):
        obj = match.group(1)
        evidence = _clean_text(match.group(0))
        url_match = re.search(r"['\"]?url['\"]?\s*:\s*['\"]([^'\"]+)['\"]", obj, re.IGNORECASE)
        if not url_match:
            continue
        method_match = re.search(r"['\"]?(?:type|method)['\"]?\s*:\s*['\"]([A-Za-z]+)['\"]", obj, re.IGNORECASE)
        url = url_match.group(1)
        add_route(url, method_match.group(1) if method_match else "GET", "js_api_parser", evidence)
        _extract_js_object_params(obj, params, route=url, evidence=evidence)
        _add_urlencoded_params(obj, params, route=url, source="param_name_miner", confidence="medium", evidence=evidence)

    for match in re.finditer(r"['\"]?(?:url|uri|action|endpoint|cgi|submit|post)['\"]?\s*:\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE):
        url = match.group(1)
        add_route(url, "GET", "js_object_route_miner", _clean_text(match.group(0)), confidence="medium")

    for match in re.finditer(r"FormData\s*\([^)]*\)\.append\(\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE):
        _append_orphan_param(params, match.group(1), "body", "param_name_miner", "medium", _clean_text(match.group(0)))
    for match in re.finditer(r"\.append\(\s*['\"]([^'\"]+)['\"]\s*,", content, re.IGNORECASE):
        _append_orphan_param(params, match.group(1), "body", "param_name_miner", "medium", _clean_text(match.group(0)))

    return routes, params, refs, hints


def _extract_js_object_params(object_text: str, params: List[Param], route: Optional[str], evidence: str) -> None:
    for data_match in re.finditer(r"['\"]?(?:data|params|payload|query|postData)['\"]?\s*:\s*(\{.*?\})", object_text, re.IGNORECASE | re.DOTALL):
        for field_name in _split_object_fields(data_match.group(1)):
            _append_orphan_param(params, field_name, "body", "param_name_miner", "high", evidence, route=route)


def _append_orphan_param(
    params: List[Param],
    name: str,
    location: str,
    source: str,
    confidence: str,
    evidence: str,
    route: Optional[str] = None,
) -> None:
    if not _valid_param_name(name):
        return
    params.append(
        Param(
            name=name,
            location=location,
            inferred_type=FrontendHTMLExtractor._infer_type(name, "text"),
            default=None,
            required=None,
            options=[],
            route=route,
            source=source,
            confidence=confidence,
            evidence=[evidence],
        )
    )


def _extract_template_vars(content: str) -> Tuple[List[TemplateVar], List[Param]]:
    template_vars: List[TemplateVar] = []
    params: List[Param] = []
    func_pattern = re.compile(
        r"\b(nvram_get|nvram_safe_get|get_single|ej_get|asp_get|getCfg|query|config_get)\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )
    for match in func_pattern.finditer(content):
        function, name = match.group(1), match.group(2)
        evidence = _clean_text(match.group(0))
        template_vars.append(
            TemplateVar(
                name=name,
                function=function,
                source="template_parser",
                confidence="medium",
                evidence=[evidence],
            )
        )
        _append_orphan_param(params, name, "template", "template_parser", "low", evidence)

    expression_pattern = re.compile(r"(<%.*?%>|<\?.*?\?>|<!--#.*?-->|{{.*?}}|\$\{[^}]+})", re.DOTALL)
    for match in expression_pattern.finditer(content):
        expression = _clean_text(match.group(1))
        template_vars.append(
            TemplateVar(
                name=expression[:120],
                function="template_expression",
                source="template_parser",
                confidence="low",
                evidence=[expression],
            )
        )
    return template_vars, params


def _collect_keyword_hints(
    text: str,
    source: str,
    confidence: str,
    hints: List[Hint],
    evidence: str,
) -> None:
    lower_text = text.lower()
    auth_kind = _keyword_kind(lower_text, AUTH_KEYWORDS)
    if auth_kind:
        hints.append(Hint(auth_kind, text, source, confidence, [evidence]))
    state_kind = _keyword_kind(lower_text, STATE_KEYWORDS)
    if state_kind:
        hints.append(Hint(state_kind, text, source, confidence, [evidence]))


def _dedupe_routes(routes: List[Route]) -> List[dict]:
    route_map: Dict[Tuple[str, str], dict] = {}
    for route in routes:
        key = (route.url, route.method)
        current = route_map.get(key)
        candidate = asdict(route)
        if not current:
            route_map[key] = candidate
            continue
        current["source"] = "|".join(sorted(set(current["source"].split("|") + [route.source])))
        current["evidence"] = _merge_evidence(current.get("evidence", []), route.evidence)
        if CONFIDENCE_RANK[route.confidence] > CONFIDENCE_RANK[current.get("confidence", "low")]:
            current["confidence"] = route.confidence
        if not current.get("ui_context") and route.ui_context:
            current["ui_context"] = route.ui_context
    return list(route_map.values())


def _dedupe_params(params: List[Param]) -> List[dict]:
    param_map: Dict[Tuple[str, str, Optional[str]], dict] = {}
    for param in params:
        key = (param.name, param.location, param.route)
        current = param_map.get(key)
        candidate = asdict(param)
        if not current:
            param_map[key] = candidate
            continue
        current["source"] = "|".join(sorted(set(current["source"].split("|") + [param.source])))
        current["evidence"] = _merge_evidence(current.get("evidence", []), param.evidence)
        current["options"] = list(dict.fromkeys(current.get("options", []) + param.options))
        if current.get("default") is None and param.default is not None:
            current["default"] = param.default
        if current.get("required") is None and param.required is not None:
            current["required"] = param.required
        if CONFIDENCE_RANK[param.confidence] > CONFIDENCE_RANK[current.get("confidence", "low")]:
            current["confidence"] = param.confidence
    return list(param_map.values())


def _dedupe_constraints(constraints: List[Constraint]) -> List[dict]:
    constraint_map: Dict[Tuple[str, str, str], dict] = {}
    for constraint in constraints:
        key = (constraint.param, constraint.kind, constraint.value)
        current = constraint_map.get(key)
        candidate = asdict(constraint)
        if not current:
            constraint_map[key] = candidate
            continue
        current["source"] = "|".join(sorted(set(current["source"].split("|") + [constraint.source])))
        current["evidence"] = _merge_evidence(current.get("evidence", []), constraint.evidence)
        if CONFIDENCE_RANK[constraint.confidence] > CONFIDENCE_RANK[current.get("confidence", "low")]:
            current["confidence"] = constraint.confidence
    return list(constraint_map.values())


def _dedupe_hints(hints: List[Hint]) -> List[dict]:
    hint_map: Dict[Tuple[str, str, str], dict] = {}
    for hint in hints:
        key = (hint.kind, hint.value, hint.source)
        current = hint_map.get(key)
        candidate = asdict(hint)
        if not current:
            hint_map[key] = candidate
            continue
        current["evidence"] = _merge_evidence(current.get("evidence", []), hint.evidence)
        if CONFIDENCE_RANK[hint.confidence] > CONFIDENCE_RANK[current.get("confidence", "low")]:
            current["confidence"] = hint.confidence
    return list(hint_map.values())


def _dedupe_template_vars(template_vars: List[TemplateVar]) -> List[dict]:
    var_map: Dict[Tuple[str, str], dict] = {}
    for var in template_vars:
        key = (var.name, var.function)
        current = var_map.get(key)
        candidate = asdict(var)
        if not current:
            var_map[key] = candidate
            continue
        current["evidence"] = _merge_evidence(current.get("evidence", []), var.evidence)
        if CONFIDENCE_RANK[var.confidence] > CONFIDENCE_RANK[current.get("confidence", "low")]:
            current["confidence"] = var.confidence
    return list(var_map.values())


def _merge_evidence(left: List[str], right: List[str]) -> List[str]:
    return list(dict.fromkeys((left or []) + (right or [])))[:10]


def parse_frontend_file(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8", errors="ignore")

    parser = FrontendHTMLExtractor(path)
    parser.feed(raw)

    js_routes, js_params, js_refs, js_hints = _extract_js_api(raw, parser.title)
    regex_routes, regex_params, regex_refs = _extract_regex_routes(raw, parser.title)
    template_vars, template_params = _extract_template_vars(raw)

    for ref in _extract_inline_script_refs(raw):
        parser.references.add(ref)
        if _looks_like_route(ref):
            parser.routes.append(
                Route(
                    url=ref,
                    method="GET",
                    source="js_api_parser",
                    ui_context=parser.title,
                    confidence="medium",
                    evidence=[f"location/window route reference {ref!r}"],
                )
            )
    parser.routes.extend(js_routes)
    parser.routes.extend(regex_routes)
    parser.params.extend(js_params)
    parser.params.extend(regex_params)
    parser.params.extend(template_params)
    parser.references.update(js_refs)
    parser.references.update(regex_refs)
    parser.auth_hints.extend([h for h in js_hints if h.kind in set(AUTH_KEYWORDS.values())])
    parser.state_hints.extend([h for h in js_hints if h.kind in set(STATE_KEYWORDS.values())])
    parser.ui_context.add(f"page_filename:{path.name}")

    return {
        "source_file": str(path),
        "artifact_type": "html",
        "routes": _dedupe_routes(parser.routes),
        "params": _dedupe_params(parser.params),
        "constraints": _dedupe_constraints(parser.constraints),
        "auth_hints": _dedupe_hints(parser.auth_hints),
        "state_hints": _dedupe_hints(parser.state_hints),
        "ui_context": sorted(parser.ui_context),
        "template_vars": _dedupe_template_vars(template_vars),
        "sinks": parser.sinks,
        "references": sorted(parser.references),
    }


def discover_frontend_files(root: Path) -> List[Path]:
    return [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in FRONTEND_EXTENSIONS]


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse web frontend files into normalized analyzer artifacts")
    ap.add_argument("input", type=Path, help="Input file or directory")
    ap.add_argument("-o", "--output", type=Path, default=None, help="Output file path (JSON)")
    args = ap.parse_args()

    input_path = args.input
    files: List[Path]
    if input_path.is_file():
        files = [input_path]
    else:
        files = discover_frontend_files(input_path)

    artifacts = [parse_frontend_file(f) for f in files]

    out_text = json.dumps(artifacts, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
