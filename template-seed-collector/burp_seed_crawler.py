#!/usr/bin/env python3
"""
Safely crawl an emulated device web UI through Burp and build baseline seed
templates for later fuzzing or replay.

Default behavior:
- Sends all traffic through Burp's proxy.
- Performs GET-only crawling to avoid mutating device state.
- Extracts forms, links, scripts, and basic request templates.
- Saves raw page snapshots and structured seed manifests.

Optional behavior:
- Can execute a small number of JavaScript-rendered navigations with Selenium
  to expose pages that require client-side redirects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
except Exception:
    webdriver = None
    ChromeOptions = None
    ChromeService = None


DEFAULT_CONFIG = {
    "base_url": "http://192.168.2.1/",
    "proxy_url": "http://127.0.0.1:8080",
    "output_dir": "./device_seed_output",
    "max_pages": 80,
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) BurpSeedCrawler/1.0 Chrome/104 Safari/537.36",
    "use_selenium": False
}

SAFE_FORM_KEYWORDS = {
    "apply",
    "save",
    "reboot",
    "reset",
    "delete",
    "remove",
    "update",
    "upgrade",
    "submit",
    "connect",
    "disconnect",
    "restore",
    "wps",
    "clone"
}

SAFE_INPUT_TYPES = {
    "hidden",
    "text",
    "search",
    "select-one",
    "radio",
    "checkbox"
}


@dataclass
class CrawlRecord:
    url: str
    status_code: int
    content_type: str
    title: str
    links: List[str]
    forms: List[dict]
    scripts: List[str]
    snapshot_file: str


def slugify_url(url: str) -> str:
    parsed = urlparse(url)
    raw = f"{parsed.scheme}_{parsed.netloc}_{parsed.path}_{parsed.query}"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    return f"{safe[:120]}_{digest}.html"


def normalize_url(base_url: str, candidate: str) -> Optional[str]:
    if not candidate:
        return None
    candidate = candidate.strip()
    if candidate.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    absolute = urljoin(base_url, candidate)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    return parsed._replace(fragment="").geturl()


def is_same_host(target_host: str, url: str) -> bool:
    return urlparse(url).hostname == target_host


def looks_mutating_form(action: str, method: str, form_id: str, submit_names: Iterable[str]) -> bool:
    haystack = " ".join([action, method, form_id, *submit_names]).lower()
    return any(keyword in haystack for keyword in SAFE_FORM_KEYWORDS)


def form_to_template(page_url: str, form, form_index: int) -> dict:
    action = normalize_url(page_url, form.get("action") or page_url) or page_url
    method = (form.get("method") or "GET").upper()
    form_id = form.get("id") or form.get("name") or f"form_{form_index}"
    enctype = form.get("enctype") or "application/x-www-form-urlencoded"
    fields = []
    submit_names = []

    for elem in form.find_all(["input", "select", "textarea"]):
        tag_name = elem.name.lower()
        input_type = (elem.get("type") or tag_name).lower()
        name = elem.get("name")
        if not name:
            continue

        entry = {
            "name": name,
            "tag": tag_name,
            "type": input_type,
            "value": elem.get("value", "")
        }

        if tag_name == "select":
            options = []
            for option in elem.find_all("option"):
                options.append(
                    {
                        "value": option.get("value", ""),
                        "text": option.get_text(" ", strip=True),
                        "selected": option.has_attr("selected")
                    }
                )
            entry["options"] = options
        elif input_type in {"radio", "checkbox"}:
            entry["checked"] = elem.has_attr("checked")

        if input_type == "submit":
            submit_names.append(name)

        fields.append(entry)

    risky = looks_mutating_form(action, method, form_id, submit_names) or method != "GET"
    seed_values = {}
    for field in fields:
        ftype = field["type"]
        if ftype not in SAFE_INPUT_TYPES and field["tag"] != "textarea":
            continue
        if field["tag"] == "select":
            selected = next((opt["value"] for opt in field.get("options", []) if opt["selected"]), "")
            default_value = selected or (field.get("options") or [{"value": ""}])[0]["value"]
        elif ftype == "checkbox":
            default_value = field["value"] if field.get("checked") else ""
        else:
            default_value = field.get("value", "")
        seed_values[field["name"]] = default_value

    return {
        "page_url": page_url,
        "form_id": form_id,
        "action": action,
        "method": method,
        "enctype": enctype,
        "risky": risky,
        "fields": fields,
        "seed_values": seed_values
    }


def extract_page_data(page_url: str, html: str, target_host: str) -> Tuple[str, List[str], List[str], List[dict]]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    links = []
    seen_links: Set[str] = set()
    for tag_name, attr in (("a", "href"), ("frame", "src"), ("iframe", "src"), ("script", "src"), ("link", "href")):
        for tag in soup.find_all(tag_name):
            normalized = normalize_url(page_url, tag.get(attr))
            if normalized and is_same_host(target_host, normalized) and normalized not in seen_links:
                seen_links.add(normalized)
                links.append(normalized)

    scripts = [link for link in links if urlparse(link).path.endswith(".js")]
    forms = [form_to_template(page_url, form, idx) for idx, form in enumerate(soup.find_all("form"), start=1)]
    return title, links, scripts, forms


class BurpSeedCrawler:
    def __init__(
        self,
        base_url: str,
        proxy_url: str,
        output_dir: Path,
        max_pages: int,
        timeout: int,
        user_agent: str,
        use_selenium: bool
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.proxy_url = proxy_url
        self.output_dir = output_dir
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent
        self.use_selenium = use_selenium
        self.target_host = urlparse(self.base_url).hostname or ""
        self.snapshots_dir = self.output_dir / "snapshots"
        self.records: List[CrawlRecord] = []
        self.endpoint_templates: Dict[str, dict] = {}

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.session.verify = False
        self.session.proxies.update({"http": self.proxy_url, "https": self.proxy_url})
        self.chrome_binary = os.environ.get("CHROME_BINARY", "/usr/bin/google-chrome")
        self.chromedriver_path = os.environ.get("CHROMEDRIVER_PATH", "/usr/local/bin/chromedriver")

    def fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[warn] GET failed for {url}: {exc}", file=sys.stderr)
            return None

    def fetch_with_selenium(self, url: str) -> Optional[Tuple[str, str]]:
        if not self.use_selenium or webdriver is None or ChromeOptions is None or ChromeService is None:
            return None

        options = ChromeOptions()
        options.binary_location = self.chrome_binary
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument(f"--proxy-server={self.proxy_url}")
        options.add_argument(f"--user-agent={self.user_agent}")

        try:
            service = ChromeService(self.chromedriver_path)
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(self.timeout)
            driver.get(url)
            time.sleep(1.5)
            html = driver.page_source
            current_url = driver.current_url
            driver.quit()
            return current_url, html
        except Exception as exc:
            print(f"[warn] Selenium fetch failed for {url}: {exc}", file=sys.stderr)
            return None

    def save_snapshot(self, url: str, html: str) -> str:
        filename = slugify_url(url)
        path = self.snapshots_dir / filename
        path.write_text(html, encoding="utf-8", errors="ignore")
        return str(path.relative_to(self.output_dir))

    def build_endpoint_templates(self, url: str, forms: List[dict]) -> None:
        parsed = urlparse(url)
        path = parsed.path or "/"
        query_params = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        key = f"GET {path}"
        self.endpoint_templates.setdefault(
            key,
            {
                "method": "GET",
                "path": path,
                "query_params": sorted(set(query_params)),
                "source_urls": []
            }
        )
        self.endpoint_templates[key]["source_urls"].append(url)

        for form in forms:
            action_parsed = urlparse(form["action"])
            action_path = action_parsed.path or "/"
            action_key = f"{form['method']} {action_path}"
            self.endpoint_templates.setdefault(
                action_key,
                {
                    "method": form["method"],
                    "path": action_path,
                    "query_params": [],
                    "form_field_names": [],
                    "risky": form["risky"],
                    "source_urls": []
                }
            )
            current = self.endpoint_templates[action_key]
            current["source_urls"].append(form["page_url"])
            current["risky"] = current.get("risky", False) or form["risky"]
            names = [field["name"] for field in form["fields"]]
            current["form_field_names"] = sorted(set(current.get("form_field_names", []) + names))

    def crawl(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

        queue = deque([self.base_url])
        visited: Set[str] = set()

        while queue and len(visited) < self.max_pages:
            current = queue.popleft()
            if current in visited or not is_same_host(self.target_host, current):
                continue

            response = self.fetch(current)
            html = None
            final_url = current
            status_code = 0
            content_type = ""

            if response is not None:
                final_url = response.url
                status_code = response.status_code
                content_type = response.headers.get("Content-Type", "")
                html = response.text

            prefer_browser = current == self.base_url or current.endswith("/index.asp")
            if prefer_browser or not html or "text/html" not in content_type.lower():
                rendered = self.fetch_with_selenium(current)
                if rendered:
                    final_url, html = rendered
                    content_type = content_type or "text/html"

            if not html:
                visited.add(current)
                continue

            visited.add(current)
            title, links, scripts, forms = extract_page_data(final_url, html, self.target_host)
            snapshot_file = self.save_snapshot(final_url, html)
            self.records.append(
                CrawlRecord(
                    url=final_url,
                    status_code=status_code,
                    content_type=content_type,
                    title=title,
                    links=links,
                    forms=forms,
                    scripts=scripts,
                    snapshot_file=snapshot_file
                )
            )
            self.build_endpoint_templates(final_url, forms)

            for link in links:
                if link not in visited:
                    queue.append(link)

    def write_outputs(self) -> None:
        records_json = []
        seed_templates = []
        for record in self.records:
            records_json.append(
                {
                    "url": record.url,
                    "status_code": record.status_code,
                    "content_type": record.content_type,
                    "title": record.title,
                    "links": record.links,
                    "scripts": record.scripts,
                    "forms": record.forms,
                    "snapshot_file": record.snapshot_file
                }
            )
            for form in record.forms:
                seed_templates.append(
                    {
                        "kind": "form_template",
                        "target": form["action"],
                        "method": form["method"],
                        "risky": form["risky"],
                        "source_page": form["page_url"],
                        "form_id": form["form_id"],
                        "seed_values": form["seed_values"]
                    }
                )

        endpoints = []
        for item in self.endpoint_templates.values():
            item["source_urls"] = sorted(set(item["source_urls"]))
            endpoints.append(item)
        endpoints.sort(key=lambda item: (item["method"], item["path"]))

        summary = {
            "base_url": self.base_url,
            "proxy_url": self.proxy_url,
            "generated_at": int(time.time()),
            "page_count": len(records_json),
            "endpoint_count": len(endpoints),
            "form_template_count": len(seed_templates),
            "pages": records_json,
            "endpoints": endpoints
        }

        (self.output_dir / "crawl_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        (self.output_dir / "seed_templates.json").write_text(
            json.dumps(seed_templates, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        with (self.output_dir / "seed_templates.jsonl").open("w", encoding="utf-8") as handle:
            for item in seed_templates:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")

        report_lines = [
            f"Base URL: {self.base_url}",
            f"Proxy URL: {self.proxy_url}",
            f"Pages crawled: {len(records_json)}",
            f"Endpoints discovered: {len(endpoints)}",
            f"Form templates: {len(seed_templates)}",
            "",
            "Top endpoints:"
        ]
        for endpoint in endpoints[:20]:
            risky_flag = " risky" if endpoint.get("risky") else ""
            report_lines.append(f"- {endpoint['method']} {endpoint['path']}{risky_flag}")
        (self.output_dir / "README_seeds.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def load_config(config_path: Optional[str]) -> dict:
    if not config_path:
        return {}
    path = Path(config_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Config file must contain a JSON object.")
    return data


def resolve_option(args: argparse.Namespace, config: dict, cli_name: str, config_name: str):
    value = getattr(args, cli_name)
    if value is not None:
        return value
    if config_name in config:
        return config[config_name]
    return DEFAULT_CONFIG[config_name]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crawl a device UI through Burp and generate baseline fuzz seeds.")
    parser.add_argument("--config", help="Path to a JSON config file.")
    parser.add_argument("--base-url", help="Target base URL.")
    parser.add_argument("--proxy-url", help="Burp proxy URL.")
    parser.add_argument("--output-dir", help="Directory for generated seeds.")
    parser.add_argument("--max-pages", type=int, help="Maximum number of HTML pages to crawl.")
    parser.add_argument("--timeout", type=int, help="Per-request timeout in seconds.")
    parser.add_argument("--user-agent", help="User-Agent used for HTTP requests and optional browser automation.")
    selenium_group = parser.add_mutually_exclusive_group()
    selenium_group.add_argument("--use-selenium", action="store_true", help="Use headless Chrome for JS-aware crawling.")
    selenium_group.add_argument("--no-selenium", action="store_true", help="Disable Selenium even if config enables it.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    if args.use_selenium:
        use_selenium = True
    elif args.no_selenium:
        use_selenium = False
    else:
        use_selenium = config.get("use_selenium", DEFAULT_CONFIG["use_selenium"])

    crawler = BurpSeedCrawler(
        base_url=resolve_option(args, config, "base_url", "base_url"),
        proxy_url=resolve_option(args, config, "proxy_url", "proxy_url"),
        output_dir=Path(resolve_option(args, config, "output_dir", "output_dir")).expanduser().resolve(),
        max_pages=resolve_option(args, config, "max_pages", "max_pages"),
        timeout=resolve_option(args, config, "timeout", "timeout"),
        user_agent=resolve_option(args, config, "user_agent", "user_agent"),
        use_selenium=use_selenium
    )
    crawler.crawl()
    crawler.write_outputs()
    print(
        json.dumps(
            {
                "base_url": crawler.base_url,
                "output_dir": str(crawler.output_dir),
                "pages": len(crawler.records),
                "endpoint_templates": len(crawler.endpoint_templates)
            },
            ensure_ascii=False
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
