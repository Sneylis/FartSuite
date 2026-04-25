import asyncio
import json
import logging
import os
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import Session, select
from sqlalchemy import text
from typing import Optional
import httpx
import websockets

from bd import create_db_and_tables, engine, get_session, Project, Capture, Packet
import config

app = FastAPI(title="FartSuite")
log = logging.getLogger("fartsuite")

# capture_id -> list of browser WebSocket clients
client_ws: dict[int, list[WebSocket]] = {}
# capture_id -> asyncio Task (agent stream reader)
capture_tasks: dict[int, asyncio.Task] = {}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    # Migrate existing DBs that pre-date the packets_count column
    with engine.connect() as conn:
        try:
            conn.execute(text(
                "ALTER TABLE capture ADD COLUMN packets_count INTEGER NOT NULL DEFAULT 0"
            ))
            conn.commit()
        except Exception:
            pass  # column already exists


# ── Request schemas ───────────────────────────────────────────

class ProjectIn(BaseModel):
    name: str
    description: Optional[str] = None


class CaptureIn(BaseModel):
    interface: str
    filter_ip: Optional[str] = None


# ── Projects ──────────────────────────────────────────────────

@app.post("/api/projects/")
def create_project(body: ProjectIn, session: Session = Depends(get_session)):
    project = Project(name=body.name, description=body.description)
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@app.get("/api/projects/")
def list_projects(session: Session = Depends(get_session)):
    return session.exec(select(Project)).all()


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


# ── Agent probe ───────────────────────────────────────────────

@app.get("/api/agent/check")
async def check_agent():
    async with httpx.AsyncClient() as client:
        try:
            sr = await client.get(f"{config.AGENT_URL}/status", timeout=3.0)
            ir = await client.get(f"{config.AGENT_URL}/interfaces", timeout=3.0)
            return {"status": sr.json(), "interfaces": ir.json()}
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Agent unavailable: {e}")


# ── Agent stream receiver ─────────────────────────────────────

async def receive_from_agent(capture_id: int):
    """Connects to agent WebSocket and forwards packets to browser clients + DB."""
    agent_ws_url = (
        config.AGENT_URL.replace("http://", "ws://").replace("https://", "wss://")
        + f"/ws/capture/{capture_id}"
    )
    try:
        async with websockets.connect(agent_ws_url, ping_interval=None, ping_timeout=None) as ws:
            log.info(f"[capture {capture_id}] connected to agent WS")
            async for raw in ws:
                try:
                    data = json.loads(raw)
                except Exception:
                    continue

                with Session(engine) as db:
                    capture = db.get(Capture, capture_id)
                    if capture:
                        capture.packets_count = (capture.packets_count or 0) + 1
                        db.add(capture)
                    db.add(Packet(
                        capture_id=capture_id,
                        timestamp=data.get("timestamp", 0),
                        length=data.get("length", 0),
                        protocol=data.get("protocol"),
                        src_ip=data.get("src_ip"),
                        dst_ip=data.get("dst_ip"),
                        src_port=data.get("src_port"),
                        dst_port=data.get("dst_port"),
                        data=data.get("data"),
                    ))
                    db.commit()

                dead: list[WebSocket] = []
                for c in client_ws.get(capture_id, []):
                    try:
                        await c.send_json(data)
                    except Exception:
                        dead.append(c)
                for d in dead:
                    if capture_id in client_ws:
                        try:
                            client_ws[capture_id].remove(d)
                        except ValueError:
                            pass

    except asyncio.CancelledError:
        raise  # must propagate so asyncio.Task.cancel() works correctly
    except Exception as e:
        log.error(f"[capture {capture_id}] agent WS error: {e}")
    finally:
        capture_tasks.pop(capture_id, None)
        with Session(engine) as db:
            capture = db.get(Capture, capture_id)
            if capture and capture.status != "stopped":
                capture.status = "stopped"
                db.add(capture)
                db.commit()
        for c in client_ws.pop(capture_id, []):
            try:
                await c.close()
            except Exception:
                pass
        log.info(f"[capture {capture_id}] stream ended")


# ── Captures ──────────────────────────────────────────────────

@app.post("/api/projects/{project_id}/captures/")
async def start_capture(
    project_id: int,
    body: CaptureIn,
    session: Session = Depends(get_session),
):
    if not session.get(Project, project_id):
        raise HTTPException(status_code=404, detail="Project not found")

    capture = Capture(
        project_id=project_id,
        interface=body.interface,
        filter_ip=body.filter_ip,
        status="starting",
    )
    session.add(capture)
    session.commit()
    session.refresh(capture)

    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                f"{config.AGENT_URL}/start_capture",
                json={
                    "interface": body.interface,
                    "target_ip": body.filter_ip or "",
                    "capture_id": capture.id,
                },
                timeout=5.0,
            )
        except Exception as e:
            capture.status = "error"
            session.add(capture)
            session.commit()
            raise HTTPException(status_code=503, detail=f"Agent error: {e}")

    capture.status = "running"
    session.add(capture)
    session.commit()
    session.refresh(capture)

    # Server connects to agent's WebSocket as a background task
    task = asyncio.create_task(receive_from_agent(capture.id))
    capture_tasks[capture.id] = task

    return capture


@app.get("/api/projects/{project_id}/captures/")
def list_captures(project_id: int, session: Session = Depends(get_session)):
    return session.exec(
        select(Capture).where(Capture.project_id == project_id)
    ).all()


@app.post("/api/captures/{capture_id}/stop")
async def stop_capture(capture_id: int, session: Session = Depends(get_session)):
    capture = session.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    capture.status = "stopped"
    session.add(capture)
    session.commit()

    # Tell agent to stop (closes pcap → closes channel → closes WS → task exits)
    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                f"{config.AGENT_URL}/stop_capture",
                json={"capture_id": capture_id},
                timeout=3.0,
            )
        except Exception:
            pass

    # Cancel the background task and wait briefly for it to clean up
    task = capture_tasks.pop(capture_id, None)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    # Force-close any remaining browser WebSocket connections
    for c in client_ws.pop(capture_id, []):
        try:
            await c.close()
        except Exception:
            pass

    return {"status": "stopped"}


@app.get("/api/captures/{capture_id}/packets/")
def get_packets(
    capture_id: int,
    skip: int = 0,
    limit: int = 500,
    session: Session = Depends(get_session),
):
    return session.exec(
        select(Packet)
        .where(Packet.capture_id == capture_id)
        .offset(skip)
        .limit(limit)
    ).all()


@app.delete("/api/captures/{capture_id}")
async def delete_capture(capture_id: int, session: Session = Depends(get_session)):
    capture = session.get(Capture, capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    # Stop running capture first
    if capture.status == "running":
        task = capture_tasks.pop(capture_id, None)
        if task and not task.done():
            task.cancel()
        async with httpx.AsyncClient() as client:
            try:
                await client.post(
                    f"{config.AGENT_URL}/stop_capture",
                    json={"capture_id": capture_id},
                    timeout=2.0,
                )
            except Exception:
                pass
        for c in client_ws.pop(capture_id, []):
            try:
                await c.close()
            except Exception:
                pass

    # Bulk-delete packets (faster than loading each row)
    from sqlalchemy import delete as sql_delete
    session.execute(sql_delete(Packet).where(Packet.capture_id == capture_id))
    session.delete(capture)
    session.commit()

    return {"deleted": True, "capture_id": capture_id}


# ── Browser WebSocket ─────────────────────────────────────────

@app.websocket("/ws/client/{capture_id}")
async def ws_client(capture_id: int, websocket: WebSocket):
    """Browser connects here to receive live packet stream."""
    await websocket.accept()
    client_ws.setdefault(capture_id, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        if capture_id in client_ws:
            try:
                client_ws[capture_id].remove(websocket)
            except ValueError:
                pass


# ── UI ────────────────────────────────────────────────────────

@app.get("/")
async def serve_ui():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
