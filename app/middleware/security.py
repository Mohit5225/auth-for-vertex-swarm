"""Security headers and lightweight rate limiting for auth endpoints."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Not wired by default — enable separately after OAuth login is verified."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if request.url.path.startswith("/oauth"):
            response.headers.setdefault(
                "Content-Security-Policy",
                (
                    "default-src 'none'; "
                    "script-src 'self'; "
                    "style-src 'unsafe-inline'; "
                    f"connect-src 'self' {settings.neon_auth_base_url.rstrip('/')}; "
                    "img-src 'none'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none';"
                ),
            )
        return response


def rate_limit_for_path(path: str) -> int | None:
    """Return per-minute request cap for a path, or None if unlimited."""
    if path == "/oauth/start":
        return settings.rate_limit_start_per_minute
    if path == "/oauth/token":
        return settings.rate_limit_token_per_minute
    if path in {"/oauth/refresh", "/api/v1/auth/refresh"}:
        return settings.rate_limit_refresh_per_minute
    if path in {"/oauth/complete-login", "/oauth/fail-login"}:
        return settings.rate_limit_start_per_minute
    if path == "/api/v1/auth/exchange":
        return settings.rate_limit_token_per_minute
    return None


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory per-IP sliding window for auth endpoints only."""

    def __init__(self, app) -> None:
        super().__init__(app)
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def _client_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not settings.rate_limit_enabled:
            return await call_next(request)

        max_requests = rate_limit_for_path(request.url.path)
        if max_requests is None:
            return await call_next(request)

        window_seconds = max(1, settings.rate_limit_window_seconds)
        now = time.monotonic()
        key = f"{self._client_ip(request)}:{request.url.path}"
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= max_requests:
            retry_after = max(1, int(window_seconds - (now - bucket[0])) if bucket else window_seconds)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)
        return await call_next(request)
