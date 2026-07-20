"""Download pinned Neon Auth browser bundles into app/static/oauth/."""
from __future__ import annotations

import urllib.request
from pathlib import Path

NEON_AUTH_VERSION = "0.4.2-beta"
STATIC_DIR = Path(__file__).resolve().parents[1] / "app" / "static" / "oauth"
ASSETS = {
    "neon-auth-bundle.mjs": f"https://esm.sh/@neondatabase/auth@{NEON_AUTH_VERSION}/es2022/auth.bundle.mjs",
    "neon-auth-adapters.mjs": f"https://esm.sh/@neondatabase/auth@{NEON_AUTH_VERSION}/es2022/vanilla/adapters.bundle.mjs",
}


def main() -> None:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    for filename, url in ASSETS.items():
        target = STATIC_DIR / filename
        print(f"Fetching {url} -> {target}")
        urllib.request.urlretrieve(url, target)
        print(f"  wrote {target.stat().st_size} bytes")


if __name__ == "__main__":
    main()
