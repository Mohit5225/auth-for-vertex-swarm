"""API v1 routes.

Submodules are imported directly by app.main (auth, oauth).
Do not eagerly import tools/endpoints here — tools pulls in Redis.
"""

__all__ = ["auth", "oauth", "endpoints", "tools"]
