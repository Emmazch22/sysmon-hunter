"""backend/api/ws.py -- the console's live WebSocket feed.

The API-key gate every JSON router gets from `require_api_key` cannot attach
to a WebSocket handshake (browsers cannot set a custom header there), so the
same shared secret travels as a `?key=` query parameter instead. These pin
down the one behavior that matters: an unset key still means open (the
existing default, unchanged), and a set key makes the handshake itself fail
without a matching `?key=`, not just an accepted-then-silent socket.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.config import settings


class TestWebSocketAuth:
    def test_connects_with_no_key_configured(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "")
        from backend.main import app

        with TestClient(app) as client, client.websocket_connect("/ws") as ws:
            ws.close()

    def test_rejects_missing_key_when_configured(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cr3t")
        from backend.main import app

        with TestClient(app) as client:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("/ws"):
                    pass

    def test_rejects_wrong_key_when_configured(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cr3t")
        from backend.main import app

        with TestClient(app) as client:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("/ws?key=wrong"):
                    pass

    def test_accepts_matching_key_when_configured(self, tmp_db, monkeypatch) -> None:
        monkeypatch.setattr(settings, "api_key", "s3cr3t")
        from backend.main import app

        with TestClient(app) as client, client.websocket_connect("/ws?key=s3cr3t") as ws:
            ws.close()
