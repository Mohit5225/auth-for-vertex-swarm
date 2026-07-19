"""Short-lived authorization-code storage for the VS Code OAuth flow."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import secrets
from typing import Any

from nats.js.errors import KeyNotFoundError, KeyValueError, BadRequestError

from app.db.nats_db import get_js_kv

LOGIN_TRANSACTION_TTL_SECONDS = 5 * 60
AUTHORIZATION_CODE_TTL_SECONDS = 2 * 60


class OAuthCodeError(Exception):
    """Raised when an OAuth transaction or authorization code is invalid."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _expiry(seconds: int) -> str:
    return (_utc_now() + timedelta(seconds=seconds)).isoformat()


async def _put(bucket: str, ttl: int, prefix: str, payload: dict[str, Any]) -> str:
    identifier = secrets.token_urlsafe(32)
    kv = await get_js_kv(bucket, ttl=ttl)
    await kv.create(f"{prefix}.{identifier}", json.dumps(payload).encode("utf-8"))
    return identifier


async def _consume(bucket: str, prefix: str, identifier: str) -> dict[str, Any]:
    """Read-and-delete with NATS KV optimistic concurrency for one-time use."""
    if not identifier:
        raise OAuthCodeError("Missing OAuth transaction")

    key = f"{prefix}.{identifier}"
    try:
        kv = await get_js_kv(bucket)
        entry = await kv.get(key)
        # The expected revision makes this atomic across service instances: only one
        # request can consume a given record.
        await kv.delete(key, last=entry.revision)
        payload = json.loads(entry.value.decode("utf-8"))
    except (KeyNotFoundError, KeyValueError, BadRequestError, json.JSONDecodeError) as exc:
        raise OAuthCodeError("OAuth transaction is invalid, expired, or already used") from exc

    expires_at = payload.get("expires_at")
    try:
        if not isinstance(expires_at, str) or datetime.fromisoformat(expires_at) <= _utc_now():
            raise OAuthCodeError("OAuth transaction has expired")
    except ValueError as exc:
        raise OAuthCodeError("OAuth transaction expiry is invalid") from exc
    return payload


async def create_login_transaction(*, redirect_uri: str, state: str, code_challenge: str) -> str:
    return await _put(
        "oauth_login_transactions",
        LOGIN_TRANSACTION_TTL_SECONDS,
        "login",
        {
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "expires_at": _expiry(LOGIN_TRANSACTION_TTL_SECONDS),
        },
    )


async def consume_login_transaction(transaction_id: str) -> dict[str, Any]:
    return await _consume("oauth_login_transactions", "login", transaction_id)


async def create_authorization_code(
    *,
    redirect_uri: str,
    code_challenge: str,
    user_id: str,
    email: str,
    role: str,
) -> str:
    return await _put(
        "oauth_authorization_codes",
        AUTHORIZATION_CODE_TTL_SECONDS,
        "code",
        {
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "user_id": user_id,
            "email": email,
            "role": role,
            "expires_at": _expiry(AUTHORIZATION_CODE_TTL_SECONDS),
        },
    )


async def consume_authorization_code(code: str) -> dict[str, Any]:
    return await _consume("oauth_authorization_codes", "code", code)
