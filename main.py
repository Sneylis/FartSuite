import asyncio
import json
import logging
import os
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlmodel import Session, select
from sqlalchemy import text, or_, and_
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
    with engine.connect() as conn:
        for ddl in [
            "ALTER TABLE capture ADD COLUMN packets_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE packet ADD COLUMN payload TEXT",
            "ALTER TABLE packet ADD COLUMN seq_num INTEGER",
        ]:
            try:
                conn.execute(text(ddl))
                conn.commit()
            except Exception:
                pass


# ── Request schemas ───────────────────────────────────────────

class ProjectIn(BaseModel):
    name: str
    description: Optional[str] = None


class CaptureIn(BaseModel):
    interface: str
    filter_ip: Optional[str] = None


class AnalyzeRequest(BaseModel):
    capture_id: int
    stream_key: str
    context: Optional[str] = None


class ResponderRequest(BaseModel):
    target_ip: str
    target_port: int
    hex_data: str
    timeout: float = 10.0


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
                        payload=data.get("payload"),
                        seq_num=data.get("seq_num"),
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
        raise
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

    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                f"{config.AGENT_URL}/stop_capture",
                json={"capture_id": capture_id},
                timeout=3.0,
            )
        except Exception:
            pass

    task = capture_tasks.pop(capture_id, None)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

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

    from sqlalchemy import delete as sql_delete
    session.execute(sql_delete(Packet).where(Packet.capture_id == capture_id))
    session.delete(capture)
    session.commit()

    return {"deleted": True, "capture_id": capture_id}


# ── TCP Streams ───────────────────────────────────────────────

@app.get("/api/captures/{capture_id}/streams")
def list_streams(capture_id: int, session: Session = Depends(get_session)):
    packets = session.exec(
        select(Packet)
        .where(Packet.capture_id == capture_id)
        .where(Packet.src_ip.isnot(None))
        .order_by(Packet.timestamp)
    ).all()

    streams: dict[str, dict] = {}
    for pkt in packets:
        if not pkt.src_ip or not pkt.src_port:
            continue
        ep1 = f"{pkt.src_ip}:{pkt.src_port}"
        ep2 = f"{pkt.dst_ip}:{pkt.dst_port}"
        key = "__".join(sorted([ep1, ep2]))
        if key not in streams:
            streams[key] = {
                "key": key,
                "protocol": pkt.protocol,
                "endpoint_a": min(ep1, ep2),
                "endpoint_b": max(ep1, ep2),
                "packet_count": 0,
                "payload_bytes": 0,
                "first_seen": pkt.timestamp,
            }
        streams[key]["packet_count"] += 1
        if pkt.payload:
            streams[key]["payload_bytes"] += len(pkt.payload) // 2

    return sorted(streams.values(), key=lambda s: s["first_seen"])


@app.get("/api/captures/{capture_id}/stream")
def get_stream(
    capture_id: int,
    key: str,
    session: Session = Depends(get_session),
):
    parts = key.split("__")
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid stream key")

    ep_a, ep_b = parts
    try:
        ip_a, port_a = ep_a.rsplit(":", 1)
        ip_b, port_b = ep_b.rsplit(":", 1)
        port_a_int, port_b_int = int(port_a), int(port_b)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid stream key format")

    packets = session.exec(
        select(Packet)
        .where(Packet.capture_id == capture_id)
        .where(or_(
            and_(Packet.src_ip == ip_a, Packet.src_port == port_a_int,
                 Packet.dst_ip == ip_b, Packet.dst_port == port_b_int),
            and_(Packet.src_ip == ip_b, Packet.src_port == port_b_int,
                 Packet.dst_ip == ip_a, Packet.dst_port == port_a_int),
        ))
        .order_by(Packet.timestamp)
    ).all()

    segments = []
    for pkt in packets:
        src_ep = f"{pkt.src_ip}:{pkt.src_port}"
        direction = "c2s" if src_ep == ep_a else "s2c"
        segments.append({
            "direction": direction,
            "timestamp": pkt.timestamp,
            "length": pkt.length,
            "payload_hex": pkt.payload or "",
            "seq_num": pkt.seq_num,
        })

    return {
        "key": key,
        "endpoint_a": ep_a,
        "endpoint_b": ep_b,
        "segments": segments,
    }


# ── AI Analysis (SSE streaming) ───────────────────────────────

def _build_prompt(segments: list[dict], stream_key: str, context: str | None) -> str:
    lines = [
        "You are an expert binary network protocol reverse-engineer.",
        "Analyze the following raw TCP/UDP stream captured from a custom binary protocol.",
        "",
        f"Stream: {stream_key}",
        "Legend: → = endpoint_a→endpoint_b,  ← = endpoint_b→endpoint_a",
        "",
    ]

    shown = 0
    for seg in segments:
        hex_data = seg.get("payload_hex", "")
        if not hex_data:
            continue
        direction = "→" if seg["direction"] == "c2s" else "←"
        rows = [hex_data[i:i+32] for i in range(0, min(len(hex_data), 1024), 32)]
        lines.append(f"{direction} {' '.join(rows)}")
        shown += 1
        if shown >= 60:
            lines.append("... (truncated)")
            break

    if shown == 0:
        lines.append("(no payload data — packets may carry no application-layer data)")

    lines += [
        "",
        "Please provide a detailed analysis:",
        "1. Identify message boundaries and delimiter/length-prefix patterns",
        "2. Find magic bytes, fixed headers, version fields, protocol identifiers",
        "3. Identify command codes, opcodes, or message type fields",
        "4. Detect TLV, LV, fixed-record, or other encoding patterns",
        "5. Propose a field-by-field schema with offsets, sizes, and likely data types",
        "6. Note any strings, timestamps, checksums, or recognizable values",
        "7. Summarize the likely purpose and flow of this protocol exchange",
    ]

    if context:
        lines += ["", f"Additional context: {context}"]

    return "\n".join(lines)


@app.post("/api/ai/analyze")
async def ai_analyze(body: AnalyzeRequest, session: Session = Depends(get_session)):
    parts = body.stream_key.split("__")
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid stream key")
    ep_a, ep_b = parts
    try:
        ip_a, port_a = ep_a.rsplit(":", 1)
        ip_b, port_b = ep_b.rsplit(":", 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid stream key format")

    packets = session.exec(
        select(Packet)
        .where(Packet.capture_id == body.capture_id)
        .where(or_(
            and_(Packet.src_ip == ip_a, Packet.src_port == int(port_a),
                 Packet.dst_ip == ip_b, Packet.dst_port == int(port_b)),
            and_(Packet.src_ip == ip_b, Packet.src_port == int(port_b),
                 Packet.dst_ip == ip_a, Packet.dst_port == int(port_a)),
        ))
        .order_by(Packet.timestamp)
    ).all()

    segments = [
        {
            "direction": "c2s" if f"{p.src_ip}:{p.src_port}" == ep_a else "s2c",
            "payload_hex": p.payload or "",
        }
        for p in packets
    ]

    prompt = _build_prompt(segments, body.stream_key, body.context)

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    f"{config.OLLAMA_URL}/api/generate",
                    json={"model": config.AI_MODEL, "prompt": prompt, "stream": True},
                ) as resp:
                    if resp.status_code != 200:
                        yield f"data: {json.dumps({'error': f'Ollama returned {resp.status_code}'})}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("response", "")
                            if token:
                                yield f"data: {json.dumps({'token': token})}\n\n"
                            if chunk.get("done"):
                                yield "data: [DONE]\n\n"
                                return
                        except Exception:
                            pass
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Responder ─────────────────────────────────────────────────

@app.post("/api/responder/send")
async def responder_send(body: ResponderRequest):
    try:
        raw = bytes.fromhex(
            body.hex_data.replace(" ", "").replace("\n", "").replace("\r", "")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex: {e}")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(body.target_ip, body.target_port),
            timeout=5.0,
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Connection failed: {e}")

    try:
        writer.write(raw)
        await writer.drain()
        response = b""
        try:
            response = await asyncio.wait_for(reader.read(65535), timeout=body.timeout)
        except asyncio.TimeoutError:
            pass
        return {
            "sent_bytes": len(raw),
            "response_hex": response.hex(),
            "response_length": len(response),
        }
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── Browser WebSocket ─────────────────────────────────────────

@app.websocket("/ws/client/{capture_id}")
async def ws_client(capture_id: int, websocket: WebSocket):
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
