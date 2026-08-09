import asyncio
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.config import settings

log = logging.getLogger(__name__)
router = APIRouter()

# RFC 6455 close code for "the endpoint received a message that violates its
# policy" -- the standard code for a rejected-auth WebSocket close, same
# family as an HTTP 401/403 for a normal request.
_WS_POLICY_VIOLATION = 1008


class ConnectionManager:
    """Tracks connected console sessions and broadcasts live detections."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        log.info("Console connected (%d active)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._clients:
            return
        dead: list[WebSocket] = []
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._clients)


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Accept a console's live connection.

    The `require_api_key` dependency every other router gets (see
    backend/api/auth.py) cannot attach here: browsers cannot set a custom
    header on a WebSocket handshake, only on a `fetch()`. The same shared
    secret travels as a `?key=` query parameter instead -- the one channel a
    WebSocket handshake actually has. Checked, and rejected, before
    `.accept()`: closing an unaccepted socket makes Starlette fail the
    handshake itself (the client sees a failed upgrade, not a socket that
    briefly opened and was immediately closed), matching how every JSON
    router in main.py rejects a bad key with the connection never having
    succeeded in the first place.

    Left unset (the default), this is a no-op and every connection is
    accepted -- the same "off by default" contract `require_api_key` uses.
    """
    if settings.api_key and ws.query_params.get("key") != settings.api_key:
        await ws.close(code=_WS_POLICY_VIOLATION)
        return
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)
