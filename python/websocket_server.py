from fastapi import FastAPI, WebSocket
import json
import time

app = FastAPI()

# เก็บ WebSocket Client
clients = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)

    try:
        while True:
            await websocket.send_text(json.dumps({"status": "Monitoring..."}))
            time.sleep(5)
    except:
        clients.remove(websocket)
