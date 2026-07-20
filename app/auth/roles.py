"""Map upstream Neon roles to application roles we actually honor."""

ALLOWED_APP_ROLES = frozenset({"authenticated", "admin"})


def normalize_app_role(neon_role: object) -> str:
    """Never pass through unknown Neon roles — default to authenticated."""
    if isinstance(neon_role, str) and neon_role in ALLOWED_APP_ROLES:
        return neon_role
    return "authenticated"
