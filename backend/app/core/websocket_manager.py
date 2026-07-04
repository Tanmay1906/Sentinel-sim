import asyncio
from typing import Set
from fastapi import WebSocket
from loguru import logger

class ConnectionManager:
    """
    Manages SOC analyst sessions. Designed for injection into app.state.
    """
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("New dashboard session linked.")

    async def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("Dashboard session unlinked.")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return

        failed_connections = []
        tasks = [self._send_safe(ws, message, failed_connections) 
                 for ws in self.active_connections]
        
        await asyncio.gather(*tasks)

        for dead_ws in failed_connections:
            await self.disconnect(dead_ws)

    async def _send_safe(self, ws: WebSocket, message: dict, failed: list):
        try:
            await ws.send_json(message)
        except Exception:
            failed.append(ws)