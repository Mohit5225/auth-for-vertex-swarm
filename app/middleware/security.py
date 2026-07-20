"""Security headers and lightweight rate limiting for auth endpoints."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings

_AUTH_RATE_LIMIT_PATHS = (
    "/oauth/start",
    "/oauth/token",
    "/oauth/refresh",
    "/oauth/complete-login",
    "/oauth/fail-login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/exchange",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
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
                    "script-src 'self' 'unsafe-inline' https://esm.sh; "
                    "style-src 'unsafe-inline'; "
                    f"connect-src 'self' {settings.neon_auth_base_url.rstrip('/')} https://esm.sh; "
                    "img-src 'none'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none';"
                ),
            )
        return response


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
  """Simple in-memory per-IP rate limiter for auth endpoints."""

  def __init__(self, app, *, max_requests: int, window_seconds: int) -> None:
      super().__init__(app)
      self.max_requests = max_requests
      self.window_seconds = window_seconds
      self._hits: dict[str, deque[float]] = defaultdict(deque)

  def _client_ip(self, request: Request) -> str:
      forwarded = request.headers.get("X-Forwarded-For", "")
      if forwarded:
          return forwarded.split(",")[0].strip()
      if request.client and request.client.host:
          return request.client.host
      return "unknown"

  def _should_limit(self, path: str) -> bool:
      return any(path == prefix or path.startswith(f"{prefix}/") for prefix in _AUTH_RATE_LIMIT_PATHS)

  async def dispatch(self, request: Request, call_next: Callable) -> Response:
      if not self._should_limit(request.url.path):
          return await call_next(request)

      now = time.monotonic()
      key = f"{self._client_ip(request)}:{request.url.path}"
      bucket = self._hits[key]
      while bucket and now - bucket[0] > self.window_seconds:
          bucket.popleft()

      if len(bucket) >= self.max_requests:
          return JSONResponse(
              status_code=429,
              content={"detail": "Too many requests. Please try again shortly."},
          )

      bucket.append(now)
      return await call_next(request)
