import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Anonymous Containers Relay", version="0.1.0")


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, WebSocket] = {}
        self.lock = asyncio.Lock()

    async def register(self, username: str, websocket: WebSocket) -> tuple[bool, Optional[str]]:
        async with self.lock:
            if username in self.active_connections:
                return False, "username-already-in-use"
            self.active_connections[username] = websocket
        return True, None

    async def unregister(self, username: str) -> None:
        async with self.lock:
            self.active_connections.pop(username, None)

    async def list_peers(self, exclude: Optional[str] = None) -> List[str]:
        async with self.lock:
            peers = list(self.active_connections.keys())
        if exclude:
            return [peer for peer in peers if peer != exclude]
        return peers

    async def broadcast_text(self, message: str, *, exclude: Optional[str] = None) -> None:
        async with self.lock:
            targets = [
                (peer, ws)
                for peer, ws in self.active_connections.items()
                if peer != exclude
            ]
        if not targets:
            return

        to_remove: List[str] = []
        awaitables = []
        for peer, websocket in targets:
            awaitables.append(self._send_text_safe(peer, websocket, message, to_remove))
        await asyncio.gather(*awaitables, return_exceptions=True)

        for peer in to_remove:
            await self.unregister(peer)

    async def _send_text_safe(
        self, peer: str, websocket: WebSocket, message: str, to_remove: List[str]
    ) -> None:
        try:
            await websocket.send_text(message)
        except Exception:
            to_remove.append(peer)

    async def broadcast_system(self, content: str, *, exclude: Optional[str] = None) -> None:
        payload = json.dumps(
            {
                "type": "system",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "message": content,
            }
        )
        await self.broadcast_text(payload, exclude=exclude)

    async def relay(self, sender: str, raw_payload: str) -> None:
        await self.broadcast_text(raw_payload, exclude=sender)


manager = ConnectionManager()


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    username: Optional[str] = None
    try:
        initial = await websocket.receive_json()
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid-registration-packet")
        return

    if initial.get("type") != "register" or "username" not in initial:
        await websocket.send_json(
            {"type": "error", "message": "registration-required"}
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="registration-required")
        return

    username = str(initial["username"]).strip()
    if not username:
        await websocket.send_json({"type": "error", "message": "invalid-username"})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid-username")
        return

    accepted, reason = await manager.register(username, websocket)
    if not accepted:
        await websocket.send_json({"type": "error", "message": reason})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=reason)
        return

    try:
        peers = await manager.list_peers(exclude=username)
        await websocket.send_json(
            {
                "type": "welcome",
                "peers": peers,
                "server": "anonymous-containers",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )
        await manager.broadcast_system(f"{username} joined", exclude=username)

        while True:
            data = await websocket.receive_text()
            await manager.relay(username, data)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="internal-error")
    finally:
        if username:
            await manager.unregister(username)
            await manager.broadcast_system(f"{username} left", exclude=username)
