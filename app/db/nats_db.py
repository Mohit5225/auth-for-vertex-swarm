import logging
from typing import Optional

from nats.aio.client import Client as NATS
from nats.js.api import KeyValueConfig
from nats.js.errors import BucketNotFoundError

logger = logging.getLogger(__name__)

_nats_client: Optional[NATS] = None


async def setup_nats(url: str) -> None:
    """Initialize the global NATS client."""
    global _nats_client
    if _nats_client is not None:
        return

    _nats_client = NATS()
    try:
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
        config = KeyValueConfig(bucket=bucket)
        if ttl is not None:
            config.ttl = ttl
        return await js.create_key_value(config)
