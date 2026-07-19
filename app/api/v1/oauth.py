import base64
import hashlib
import hmac
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.core.config import settings
from app.auth.app_token_service import AppTokenError, rotate_extension_refresh_token, issue_extension_token_pair, revoke_extension_refresh_token
from app.auth.core import verify_neon_auth_jwt, NeonAuthVerificationError
from app.schemas.auth import AuthRefreshRequest, AuthRefreshResponse, AuthLogoutRequest
from app.auth.oauth_code_service import (
    OAuthCodeError,
    consume_authorization_code,
    consume_login_transaction,
    create_authorization_code,
    create_login_transaction,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oauth", tags=["oauth"])

_PKCE_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


def _validate_loopback_redirect_uri(value: str) -> str:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("redirect_uri has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != "/callback"
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("redirect_uri must be http://127.0.0.1:<port>/callback")
    return value


def _append_query(uri: str, **params: str) -> str:
    parsed = urlparse(uri)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(params)
    return urlunparse(parsed._replace(query=urlencode(query)))


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")


def _oauth_callback_url(request: Request) -> str:
    """Resolve the hosted OAuth callback URL (Neon returns here after Google sign-in)."""
    configured_base = settings.public_base_url.strip().rstrip("/")
    if configured_base:
        return f"{configured_base}/oauth/callback"
    return f"{str(request.base_url).rstrip('/')}/oauth/callback"


@router.get("/start")
async def oauth_start(
    request: Request,
    redirect_uri: str = Query(..., description="Extension loopback callback URL"),
    state: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
):
    try:
        redirect_uri = _validate_loopback_redirect_uri(redirect_uri)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if not _STATE_RE.fullmatch(state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state")
    if code_challenge_method != "S256" or not _PKCE_CHALLENGE_RE.fullmatch(code_challenge):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PKCE S256 is required")

    try:
        transaction_id = await create_login_transaction(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
        )
    except Exception as exc:
        logger.exception("Failed to create OAuth login transaction")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Auth storage unavailable: {exc}",
        ) from exc
    
    # Dynamically determine the backend's callback URL based on where the app is deployed
    backend_callback_url = _oauth_callback_url(request)
    
    neon_callback_url = _append_query(backend_callback_url, transaction=transaction_id)
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Starting Login...</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #0d1117; color: #c9d1d9; }}
        </style>
    </head>
    <body>
        <h2>Redirecting to Secure Login...</h2>
        <script type="module">
            import {{ createAuthClient }} from "https://esm.sh/better-auth/client?bundle";
            
            const authClient = createAuthClient({{
                baseURL: "{settings.neon_auth_base_url}",
                fetchOptions: {{ credentials: "include" }},
            }});
            
            authClient.signIn.social({{
                provider: "google",
                callbackURL: "{neon_callback_url}"
            }}).catch(err => {{
                document.body.innerHTML = "Failed to start login: " + err.message;
            }});
        </script>
    </body>
    </html>
    """
    
    logger.info("Serving SDK-based OAuth start page")
    return HTMLResponse(content=html)
@router.get("/callback")
async def oauth_callback(request: Request):
    """
    Handles the redirect back from Neon.
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authenticating...</title>
        <script type="module">
            import {{ createAuthClient }} from "https://esm.sh/better-auth/client?bundle";
            
            const authClient = createAuthClient({{
                baseURL: "{settings.neon_auth_base_url}",
                fetchOptions: {{ credentials: "include" }},
            }});

            window.onload = async function() {{
                const params = new URLSearchParams(window.location.search);
                const error = params.get('error');
                const transaction = params.get('transaction');

                if (error) {{
                    const res = await fetch('/oauth/fail-login', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ transaction }})
                    }});
                    const resData = await res.json();
                    if (resData.redirect_url) {{
                        window.location.href = resData.redirect_url;
                    }} else {{
                        document.body.textContent = "Authentication failed: " + error;
                    }}
                    return;
                }}

                if (!transaction) {{
                    document.body.textContent = "Authentication failed: missing login transaction.";
                    return;
                }}

                try {{
                    // Ask Neon Auth for the JWT string
                    const {{ data, error: tokenError }} = await authClient.token();
                    
                    if (tokenError || !data?.token) {{
                        document.body.innerHTML = "Authentication failed. Could not retrieve token from Neon.";
                        return;
                    }}

                    // The browser supplies the Neon session to the hosted service.
                    // The service returns only a short-lived authorization code URL;
                    // extension access and refresh tokens never enter this redirect.
                    const res = await fetch('/oauth/complete-login', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ token: data.token, transaction }})
                    }});
                    const resData = await res.json();
                    
                    if (resData.redirect_url) {{
                        window.location.href = resData.redirect_url;
                    }} else {{
                        document.body.innerHTML = "Failed to exchange token: " + (resData.detail || "Unknown error");
                    }}
                }} catch (err) {{
                    document.body.innerHTML = "Failed to communicate with server: " + err;
                }}
            }}
        </script>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #0d1117; color: #c9d1d9; }}
        </style>
    </head>
    <body>
        <h2>Finishing Authentication...</h2>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


class CompleteLoginRequest(BaseModel):
    token: str
    transaction: str


class FailedLoginRequest(BaseModel):
    transaction: str | None = None


@router.post("/fail-login")
async def oauth_fail_login(req: FailedLoginRequest):
    """End a failed browser login at the matching extension callback."""
    try:
        transaction = await consume_login_transaction(req.transaction or "")
        return {"redirect_url": _append_query(
            transaction["redirect_uri"],
            error="Authentication failed in the browser.",
            state=transaction["state"],
        )}
    except (OAuthCodeError, KeyError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

@router.post("/complete-login")
async def oauth_complete_login(req: CompleteLoginRequest):
    """Verify the Neon session and create a single-use PKCE-bound code."""
    try:
        neon_claims = await verify_neon_auth_jwt(req.token)
        user_id = neon_claims.get("sub")
        if not isinstance(user_id, str) or not user_id:
            raise NeonAuthVerificationError("Neon token missing user id")
        email = neon_claims.get("email", "")
        role = neon_claims.get("role", "authenticated")

        transaction = await consume_login_transaction(req.transaction)
        authorization_code = await create_authorization_code(
            redirect_uri=transaction["redirect_uri"],
            code_challenge=transaction["code_challenge"],
            user_id=user_id,
            email=email if isinstance(email, str) else "",
            role=role if isinstance(role, str) and role else "authenticated"
        )
        return {"redirect_url": _append_query(
            transaction["redirect_uri"], code=authorization_code, state=transaction["state"]
        )}
    except (NeonAuthVerificationError, OAuthCodeError, KeyError, ValueError) as exc:
        logger.error(f"Failed implicit exchange: {exc}")
        raise HTTPException(status_code=400, detail=str(exc))


class AuthorizationCodeTokenRequest(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str


@router.post("/token", response_model=AuthRefreshResponse)
async def oauth_token_exchange(req: AuthorizationCodeTokenRequest):
    """Exchange a one-time authorization code for the extension token pair."""
    try:
        redirect_uri = _validate_loopback_redirect_uri(req.redirect_uri)
        if not _VERIFIER_RE.fullmatch(req.code_verifier):
            raise ValueError("Invalid PKCE verifier")
        code_data = await consume_authorization_code(req.code)
        if not hmac.compare_digest(code_data["redirect_uri"], redirect_uri):
            raise ValueError("redirect_uri does not match the authorization code")
        if not hmac.compare_digest(code_data["code_challenge"], _pkce_challenge(req.code_verifier)):
            raise ValueError("PKCE verification failed")
        token_pair = await issue_extension_token_pair(
            user_id=code_data["user_id"],
            email=code_data["email"],
            role=code_data["role"],
        )
    except (AppTokenError, OAuthCodeError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    from datetime import datetime, timezone
    expires_in = max(0, int((token_pair.access_expires_at - datetime.now(timezone.utc)).total_seconds()))
    return AuthRefreshResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        token_type=token_pair.token_type,
        expires_in=expires_in,
        expires_at=token_pair.access_expires_at,
    )


@router.post("/refresh")
async def oauth_refresh(req: AuthRefreshRequest):
    """
    Alias for /api/v1/auth/refresh exactly where the extension expects it.
    """
    try:
        token_pair = await rotate_extension_refresh_token(req.refresh_token)
        from datetime import datetime, timezone
        
        def _seconds_until(expires_at: datetime) -> int:
            return max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds()))

        return AuthRefreshResponse(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            token_type=token_pair.token_type,
            expires_in=_seconds_until(token_pair.access_expires_at),
            expires_at=token_pair.access_expires_at,
        )
    except AppTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.post("/logout")
async def oauth_logout(req: AuthLogoutRequest):
    """
    Revokes the provided refresh token so it cannot be used again.
    """
    if req.refresh_token:
        try:
            await revoke_extension_refresh_token(req.refresh_token)
        except Exception as exc:
            logger.error(f"Error during token revocation: {exc}")
    
    from app.schemas.auth import AuthLogoutResponse
    return AuthLogoutResponse()
