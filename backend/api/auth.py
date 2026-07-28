"""Optional shared-secret gate for the JSON API.

There is no user model, no session, no login flow -- Sysmon Hunter is a
single-operator console, not a multi-tenant service. What it needs is not
authentication so much as a way to stop being wide open the moment it is
reachable from anywhere broader than the machine it runs on (the server
binds 0.0.0.0 by default). A shared API key, checked on every JSON endpoint,
is the smallest thing that closes that gap without inventing accounts for a
tool that has exactly one user.

Left unset (the default), `require_api_key` is a no-op and every request
passes -- a fresh checkout works with zero configuration. Set
HUNTER_API_KEY and every router wired up with this dependency in main.py
starts requiring a matching `X-API-Key` header.

The frontend side of this lives in frontend/static/common.js, which wraps
`window.fetch` so the console prompts for the key once (on the first 401)
and remembers it in localStorage, rather than every page needing its own
auth-handling code.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, status

from backend.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency: enforce X-API-Key only if HUNTER_API_KEY is set.

    Comparison is a plain string equality, not constant-time. That trade-off
    is deliberate: constant-time comparison defends against timing attacks
    from a remote adversary probing a secret over many requests, which is a
    threat model for a public multi-user service, not a single shared secret
    on a console one person runs for themselves.
    """
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing or invalid X-API-Key header",
        )
