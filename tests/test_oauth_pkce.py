"""Focused unit tests for the extension authorization-code exchange."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.api.v1 import oauth


class OAuthPkceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.verifier = "v" * 43
        self.redirect_uri = "http://127.0.0.1:43123/callback"
        self.code_data = {
            "redirect_uri": self.redirect_uri,
            "code_challenge": oauth._pkce_challenge(self.verifier),
            "user_id": "user-1",
            "email": "user@example.test",
            "role": "authenticated",
        }

    async def test_code_exchange_requires_matching_pkce_verifier(self) -> None:
        request = oauth.AuthorizationCodeTokenRequest(
            code="one-time-code",
            code_verifier=self.verifier,
            redirect_uri=self.redirect_uri,
        )
        token_pair = SimpleNamespace(
            access_token="access",
            refresh_token="refresh",
            token_type="Bearer",
            access_expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )

        with patch.object(oauth, "consume_authorization_code", AsyncMock(return_value=self.code_data)), patch.object(
            oauth, "issue_extension_token_pair", AsyncMock(return_value=token_pair)
        ):
            response = await oauth.oauth_token_exchange(request)

        self.assertEqual(response.access_token, "access")
        self.assertEqual(response.refresh_token, "refresh")

    async def test_code_exchange_rejects_wrong_pkce_verifier(self) -> None:
        request = oauth.AuthorizationCodeTokenRequest(
            code="one-time-code",
            code_verifier="w" * 43,
            redirect_uri=self.redirect_uri,
        )

        with patch.object(oauth, "consume_authorization_code", AsyncMock(return_value=self.code_data)):
            with self.assertRaises(HTTPException) as context:
                await oauth.oauth_token_exchange(request)

        self.assertEqual(context.exception.status_code, 400)

    def test_loopback_redirect_must_be_exact(self) -> None:
        self.assertEqual(oauth._validate_loopback_redirect_uri(self.redirect_uri), self.redirect_uri)
        for invalid_uri in (
            "https://127.0.0.1:43123/callback",
            "http://localhost:43123/callback",
            "http://127.0.0.1:43123/not-callback",
            "http://127.0.0.1:43123/callback?next=bad",
        ):
            with self.assertRaises(ValueError):
                oauth._validate_loopback_redirect_uri(invalid_uri)


if __name__ == "__main__":
    unittest.main()
