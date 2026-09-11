import json
from typing import Dict, List
from fastapi import WebSocket

class InvestigationWSManager:
    def __init__(self):
        # Maps investigation_id to list of active WebSockets
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, ws: WebSocket, investigation_id: str):
        await ws.accept()
        if investigation_id not in self.active_connections:
            self.active_connections[investigation_id] = []
        self.active_connections[investigation_id].append(ws)

    def disconnect(self, ws: WebSocket, investigation_id: str):
        if investigation_id in self.active_connections:
            if ws in self.active_connections[investigation_id]:
                self.active_connections[investigation_id].remove(ws)
            if not self.active_connections[investigation_id]:
                del self.active_connections[investigation_id]

    async def broadcast(self, investigation_id: str, event_type: str, data: dict):
        if investigation_id in self.active_connections:
            message = {
                "event_type": event_type,
                "data": data
            }
            json_msg = json.dumps(message)
            for connection in self.active_connections[investigation_id]:
                await connection.send_text(json_msg)

ws_manager = InvestigationWSManager()
