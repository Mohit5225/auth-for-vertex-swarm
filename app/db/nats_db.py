import logging
import os
import tempfile
from typing import Optional

from nats.aio.client import Client as NATS
from nats.js.api import KeyValueConfig
from nats.js.errors import BucketNotFoundError

logger = logging.getLogger(__name__)

_nats_client: Optional[NATS] = None


def _normalize_creds_content(content: str) -> str:
    """Render .env imports often store multiline creds with literal \\n escapes."""
    text = content.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
    if "\\n" in text:
        text = text.replace("\\n", "\n")
    return text.strip()


async def setup_nats(url: str, creds_file: Optional[str] = None, creds_content: Optional[str] = None) -> None:
    """Initialize the global NATS client."""
    global _nats_client
    if _nats_client is not None:
        return

    _nats_client = NATS()

    # If running on Render, we might pass the file content directly via an env variable.
    # nats-py requires a file path, so we write the content to a temporary file.
    if creds_content and creds_content.strip():
        normalized = _normalize_creds_content(creds_content)
        fd, temp_creds_path = tempfile.mkstemp(suffix=".creds")
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(normalized)
            if not normalized.endswith("\n"):
                f.write("\n")
        creds_file = temp_creds_path

    try:
        if creds_file and creds_file.strip():
            await _nats_client.connect(url, user_credentials=creds_file.strip())
        else:
            await _nats_client.connect(url)
        logger.info(f"Connected to NATS at {url}")
    except Exception as e:
        logger.error(f"Failed to connect to NATS at {url}: {e}")
        _nats_client = None
        raise


async def close_nats() -> None:
    """Close the global NATS client."""
    global _nats_client
    if _nats_client is not None:
        await _nats_client.close()
        _nats_client = None


def get_nats_client() -> NATS:
    """Get the active NAQS client."""
    if _nats_client is None:
        raise RuntimeError("NATS client is not initialized. Call setup_nats() first.")
    return _nats_client


async def get_js_kv(bucket: str, ttl: Optional[int] = None):
    """
    Get or create a JetStream KeyValue store bucket.
    If ttl is provided (in seconds), it applies to the bucket.
    """
    nc = get_nats_client()
    js = nc.jetstream()
    try:
        return await js.key_value(bucket)
    except BucketNotFoundError:
        # Synadia Free Tier requires max_bytes to be explicitly set
        config = KeyValueConfig(
            bucket=bucket,
            max_bytes=5 * 1024 * 1024  # 5MB is plenty for tokens
        )
        if ttl is not None:
            config.ttl = ttl
        return await js.create_key_value(config)
