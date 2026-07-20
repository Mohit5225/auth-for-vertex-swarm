import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core.config import settings
from app.db.nats_db import setup_nats, get_js_kv, close_nats
from app.auth.oauth_code_service import create_login_transaction


async def main() -> None:
    print("nats_url", settings.nats_url)
    print("creds_file", repr(settings.nats_creds_file))
    print("creds_content_len", len(settings.nats_creds_content or ""))
    try:
        await setup_nats(
            settings.nats_url,
            creds_file=settings.nats_creds_file or None,
            creds_content=settings.nats_creds_content or None,
        )
        print("connect: OK")
        txn = await create_login_transaction(
            redirect_uri="http://127.0.0.1:50322/callback",
            state="a" * 32,
            code_challenge="a" * 43,
        )
        print("create_login_transaction: OK", txn[:12], "...")
    except Exception as exc:
        print("FAIL:", type(exc).__name__, exc)
        raise
    finally:
        await close_nats()


if __name__ == "__main__":
    asyncio.run(main())
