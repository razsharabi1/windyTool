"""
PE Distribution Server
======================
FastAPI + WebSocket server that pushes PE binaries to authenticated agents.
Transport is secured with mTLS — only agents holding a certificate signed by
the private CA are allowed to connect.

Requirements:
    pip install fastapi uvicorn[standard] websockets

Run:
    uvicorn server:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile  ../certs/server.key \
        --ssl-certfile ../certs/server.crt \
        --ssl-ca-certs ../certs/ca.crt
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI()

# ---------------------------------------------------------------------------
# In-memory registry of connected agents
# key = agent_id (taken from the TLS CN field)
# value = WebSocket
# ---------------------------------------------------------------------------
connected_agents: Dict[str, WebSocket] = {}


def get_agent_id(websocket: WebSocket) -> str:
    """
    Extract the agent identity from the TLS client certificate CN.
    uvicorn / starlette exposes client cert info in the connection scope
    when --ssl-ca-certs is configured and the client sends a cert.
    Falls back to the client IP if no cert is available (useful in dev).
    """
    ssl_object = websocket.scope.get("ssl")
    if ssl_object:
        peer_cert = ssl_object.getpeercert()
        if peer_cert:
            for field in peer_cert.get("subject", []):
                for key, value in field:
                    if key == "commonName":
                        return value
    # Fallback: use client IP
    client = websocket.scope.get("client")
    return f"{client[0]}:{client[1]}" if client else "unknown"


@app.websocket("/agent")
async def agent_endpoint(websocket: WebSocket):
    await websocket.accept()

    agent_id = get_agent_id(websocket)
    connected_agents[agent_id] = websocket
    log.info(f"Agent connected: {agent_id}  (total={len(connected_agents)})")

    try:
        # Keep the connection alive — wait for messages from the agent
        # (heartbeats, status reports, test results, etc.)
        while True:
            message = await websocket.receive_text()
            log.info(f"[{agent_id}] → {message}")

    except WebSocketDisconnect:
        log.info(f"Agent disconnected: {agent_id}")
    finally:
        connected_agents.pop(agent_id, None)


# ---------------------------------------------------------------------------
# REST endpoints — used by you (the operator) to push PEs to agents
# ---------------------------------------------------------------------------

@app.post("/push/{agent_id}")
async def push_pe_to_agent(agent_id: str, pe_path: str):
    """
    Push a PE file to a specific connected agent.
    Body param pe_path: path to the .exe / .dll on the server filesystem.

    Example:
        curl -k -X POST "https://localhost:8443/push/agent-001?pe_path=/tmp/test.exe"
    """
    ws = connected_agents.get(agent_id)
    if ws is None:
        return {"error": f"Agent '{agent_id}' is not connected"}

    pe_data = Path(pe_path).read_bytes()
    log.info(f"Pushing {len(pe_data)} bytes to agent '{agent_id}'")

    # Send a JSON header first so the agent knows what's coming
    await ws.send_json({
        "type": "pe_push",
        "size": len(pe_data),
        "filename": Path(pe_path).name,
    })

    # Then send the raw binary
    await ws.send_bytes(pe_data)
    log.info(f"Push complete → {agent_id}")
    return {"status": "sent", "bytes": len(pe_data)}


@app.post("/broadcast")
async def broadcast_pe(pe_path: str):
    """Push the same PE to ALL currently connected agents."""
    if not connected_agents:
        return {"error": "No agents connected"}

    pe_data = Path(pe_path).read_bytes()
    header = {
        "type": "pe_push",
        "size": len(pe_data),
        "filename": Path(pe_path).name,
    }

    results = {}
    for agent_id, ws in list(connected_agents.items()):
        try:
            await ws.send_json(header)
            await ws.send_bytes(pe_data)
            results[agent_id] = "sent"
            log.info(f"Broadcast → {agent_id} ({len(pe_data)} bytes)")
        except Exception as e:
            results[agent_id] = f"error: {e}"

    return {"bytes": len(pe_data), "results": results}


@app.get("/agents")
async def list_agents():
    """Return a list of currently connected agent IDs."""
    return {"agents": list(connected_agents.keys())}