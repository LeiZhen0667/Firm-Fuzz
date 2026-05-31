#!/usr/bin/env python3
"""Optional safe route probe adapter for frontend analyzer.

This module intentionally performs only non-destructive requests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class ProbeResult:
    url: str
    method: str
    status_code: int
    redirect_target: Optional[str]
    response_length: int
    auth_required: bool
    error: Optional[str]


def probe_route(
    base_url: str,
    route: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 3.0,
) -> Dict[str, object]:
    """Probe a route with safe methods only (`GET`/`HEAD`)."""
    method = method.upper()
    if method not in {"GET", "HEAD"}:
        raise ValueError("dynamic_probe_adapter only allows GET/HEAD")

    target = f"{base_url.rstrip('/')}/{route.lstrip('/')}"
    req = Request(target, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = getattr(resp, "status", 200)
            auth_required = status in {401, 403}
            result = ProbeResult(
                url=target,
                method=method,
                status_code=status,
                redirect_target=resp.geturl() if resp.geturl() != target else None,
                response_length=len(body),
                auth_required=auth_required,
                error=None,
            )
            return asdict(result)
    except HTTPError as exc:
        result = ProbeResult(
            url=target,
            method=method,
            status_code=exc.code,
            redirect_target=None,
            response_length=0,
            auth_required=exc.code in {401, 403},
            error=str(exc),
        )
        return asdict(result)
    except URLError as exc:
        result = ProbeResult(
            url=target,
            method=method,
            status_code=0,
            redirect_target=None,
            response_length=0,
            auth_required=False,
            error=str(exc),
        )
        return asdict(result)
