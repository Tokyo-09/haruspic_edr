from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import __version__
from .auth import get_db, hash_token, new_token, require_admin, require_agent, require_enrollment_token
from .db import Agent, AgentCommand, Alert, Event, init_db
from .schemas import (
    AgentOut,
    AlertOut,
    AlertPatch,
    CommandAck,
    CommandCreate,
    CommandOut,
    EnrollRequest,
    EnrollResponse,
    EventOut,
    IngestRequest,
    IngestResponse,
)
from .policy import TelemetryPolicy, load_policy, save_policy
from .settings import settings
from .limits import RequestLimitsMiddleware

UPDATES_DIR = Path(getattr(settings, "updates_dir", "./data/updates"))

app = FastAPI(
    title="Spire EDR",
    version=__version__,
    description="Telemetry, alerts and response API for SpireAV endpoints",
)

app.add_middleware(RequestLimitsMiddleware, max_bytes=settings.max_request_bytes, concurrent=settings.max_concurrent_requests)

STATIC_DIR = Path(__file__).parent / "static"


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    UPDATES_DIR.mkdir(parents=True, exist_ok=True)


def _parse_payload(raw: str) -> dict:
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {"value": value}
    except json.JSONDecodeError:
        return {"raw": raw}


def _agent_out(row: Agent) -> AgentOut:
    return AgentOut(
        id=row.id,
        hostname=row.hostname,
        os_name=row.os_name,
        arch=row.arch,
        agent_version=row.agent_version,
        last_seen_at=row.last_seen_at,
        enrolled_at=row.enrolled_at,
        status=_freshness(row.last_seen_at),
    )


def _freshness(last_seen: datetime) -> str:
    now = datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    delta = now - last_seen
    if delta <= timedelta(minutes=2):
        return "online"
    if delta <= timedelta(minutes=15):
        return "stale"
    return "offline"


def _command_out(row: AgentCommand) -> CommandOut:
    return CommandOut(
        id=row.id,
        agent_id=row.agent_id,
        command_type=row.command_type,
        payload=_parse_payload(row.payload),
        status=row.status,
        result=_parse_payload(row.result) if row.result else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _maybe_alert(db: Session, agent_id: str, event_type: str, severity: str, event_id: str, payload: dict) -> None:
    if event_type not in {"detection", "scan_result"} and severity not in {"high", "critical"}:
        return
    if event_type == "scan_result" and payload.get("verdict") in {None, "clean"}:
        return
    title = payload.get("malware_name") or payload.get("verdict") or event_type
    path = payload.get("path")
    if path:
        title = f"{title}: {path}"
    db.add(
        Alert(
            agent_id=agent_id,
            event_id=event_id,
            title=str(title)[:255],
            severity=severity,
            status="open",
        )
    )


def _update_candidates(name: str) -> list[Path]:
    return [
        UPDATES_DIR / name,
        Path("data") / name,
        Path("data") / "updates" / name,
        Path("server") / "data" / name,
        Path("server") / "data" / "updates" / name,
    ]


def _update_file(name: str) -> FileResponse:
    for path in _update_candidates(name):
        if path.is_file():
            return FileResponse(path.resolve(), filename=name)
    checked = [str(path.resolve()) for path in _update_candidates(name)]
    raise HTTPException(
        status_code=404,
        detail={"missing": name, "looked_in": checked},
    )


@app.get("/manifest.json")
def update_manifest() -> FileResponse:
    return _update_file("manifest.json")


@app.get("/manifest.sig")
def update_signature() -> FileResponse:
    return _update_file("manifest.sig")


@app.get("/database.db")
def signature_db() -> FileResponse:
    return _update_file("database.db")


@app.get("/yara.zip")
def yara_pack() -> FileResponse:
    return _update_file("yara.zip")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "spire-edr", "version": __version__}


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return '<meta http-equiv="refresh" content="0; url=/console">'


@app.get("/console")
def console():
    page = STATIC_DIR / "console.html"
    if page.exists():
        return FileResponse(page)
    return HTMLResponse("<h1>Spire EDR</h1><p>console.html missing</p>")


@app.post("/v1/agents/enroll", response_model=EnrollResponse)
def enroll(
    body: EnrollRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_enrollment_token),
) -> EnrollResponse:
    token = new_token()
    if body.agent_id is not None:
        raise HTTPException(status_code=409, detail="Enrollment cannot replace an existing identity")
    agent_id = new_token()

    db.add(
        Agent(
            id=agent_id,
            hostname=body.hostname,
            os_name=body.os_name,
            arch=body.arch,
            agent_version=body.agent_version,
            token_hash=hash_token(token),
        )
    )
    db.commit()
    return EnrollResponse(agent_id=agent_id, agent_token=token)


@app.post("/v1/telemetry/ingest", response_model=IngestResponse)
def ingest(
    body: IngestRequest,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> IngestResponse:
    accepted = 0
    duplicates = 0
    now = datetime.now(timezone.utc)
    agent.last_seen_at = now
    agent.status = "online"

    incoming_ids = [item.id for item in body.events]
    existing = {
        row.event_id
        for row in db.query(Event.event_id).filter(Event.event_id.in_(incoming_ids)).all()
    }

    for item in body.events:
        if item.id in existing:
            duplicates += 1
            continue
        db.add(
            Event(
                event_id=item.id,
                agent_id=agent.id,
                ts=item.ts,
                event_type=item.type,
                severity=item.severity,
                payload=json.dumps(item.data, ensure_ascii=False),
            )
        )
        _maybe_alert(db, agent.id, item.type, item.severity, item.id, item.data)
        existing.add(item.id)
        accepted += 1

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="duplicate event id") from exc
    return IngestResponse(accepted=accepted, duplicates=duplicates)


@app.post("/v1/agents/heartbeat")
def heartbeat(agent: Agent = Depends(require_agent), db: Session = Depends(get_db)) -> dict[str, str]:
    agent.last_seen_at = datetime.now(timezone.utc)
    agent.status = "online"
    db.commit()
    return {"status": "ok", "agent_id": agent.id}


@app.get("/v1/agents/commands", response_model=list[CommandOut])
def pull_commands(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> list[CommandOut]:
    rows = (
        db.query(AgentCommand)
        .filter(AgentCommand.agent_id == agent.id, or_(
            AgentCommand.status == "queued",
            and_(AgentCommand.status == "sent", AgentCommand.updated_at < datetime.now(timezone.utc) - timedelta(minutes=5)),
        ))
        .order_by(AgentCommand.created_at.asc())
        .limit(20)
        .all()
    )
    now = datetime.now(timezone.utc)
    for row in rows:
        row.status = "sent"
        row.updated_at = now
    db.commit()
    return [_command_out(row) for row in rows]


@app.post("/v1/agents/commands/{command_id}/ack")
def ack_command(
    command_id: str,
    body: CommandAck,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    row = db.get(AgentCommand, command_id)
    if row is None or row.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="command not found")
    row.status = body.status
    row.result = json.dumps(body.result, ensure_ascii=False)
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok"}


@app.get("/v1/agents", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db), _: None = Depends(require_admin)) -> list[AgentOut]:
    return [_agent_out(row) for row in db.query(Agent).order_by(Agent.last_seen_at.desc()).all()]


@app.get("/v1/agents/{agent_id}", response_model=AgentOut)
def get_agent(agent_id: str, db: Session = Depends(get_db), _: None = Depends(require_admin)) -> AgentOut:
    row = db.get(Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="agent not found")
    return _agent_out(row)


@app.get("/v1/events", response_model=list[EventOut])
def list_events(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
    agent_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[EventOut]:
    q = db.query(Event)
    if agent_id:
        q = q.filter(Event.agent_id == agent_id)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    if severity:
        q = q.filter(Event.severity == severity)
    rows = q.order_by(Event.ts.desc()).limit(limit).all()
    return [
        EventOut(
            event_id=row.event_id,
            agent_id=row.agent_id,
            ts=row.ts,
            event_type=row.event_type,
            severity=row.severity,
            payload=_parse_payload(row.payload),
            received_at=row.received_at,
        )
        for row in rows
    ]


@app.get("/v1/alerts", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
    status: str | None = None,
    agent_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AlertOut]:
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if agent_id:
        q = q.filter(Alert.agent_id == agent_id)
    rows = q.order_by(Alert.created_at.desc()).limit(limit).all()
    return [
        AlertOut(
            id=row.id,
            agent_id=row.agent_id,
            event_id=row.event_id,
            title=row.title,
            severity=row.severity,
            status=row.status,
            created_at=row.created_at,
        )
        for row in rows
    ]


@app.patch("/v1/alerts/{alert_id}", response_model=AlertOut)
def patch_alert(
    alert_id: int,
    body: AlertPatch,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
) -> AlertOut:
    row = db.get(Alert, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")
    row.status = body.status
    db.commit()
    return AlertOut(
        id=row.id,
        agent_id=row.agent_id,
        event_id=row.event_id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        created_at=row.created_at,
    )


@app.post("/v1/agents/{agent_id}/commands", response_model=CommandOut)
def create_command(
    agent_id: str,
    body: CommandCreate,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
) -> CommandOut:
    if db.get(Agent, agent_id) is None:
        raise HTTPException(status_code=404, detail="agent not found")
    row = AgentCommand(
        id=new_token(),
        agent_id=agent_id,
        command_type=body.command_type,
        payload=json.dumps(body.payload, ensure_ascii=False),
        status="queued",
    )
    db.add(row)
    db.commit()
    return _command_out(row)


@app.get("/v1/agents/{agent_id}/commands", response_model=list[CommandOut])
def list_agent_commands(
    agent_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
) -> list[CommandOut]:
    rows = (
        db.query(AgentCommand)
        .filter(AgentCommand.agent_id == agent_id)
        .order_by(AgentCommand.created_at.desc())
        .limit(50)
        .all()
    )
    return [_command_out(row) for row in rows]


@app.get("/v1/stats")
def stats(db: Session = Depends(get_db), _: None = Depends(require_admin)) -> dict:
    agents = db.query(Agent).all()
    online = sum(1 for agent in agents if _freshness(agent.last_seen_at) == "online")
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    events = db.query(Event).count()
    return {
        "agents": len(agents),
        "online": online,
        "open_alerts": open_alerts,
        "events": events,
    }


@app.get("/v1/policy", response_model=TelemetryPolicy)
def get_policy(_: None = Depends(require_admin)) -> TelemetryPolicy:
    return load_policy()


@app.put("/v1/policy", response_model=TelemetryPolicy)
def put_policy(body: TelemetryPolicy, _: None = Depends(require_admin)) -> TelemetryPolicy:
    return save_policy(body)


@app.get("/v1/runtime/policy", response_model=TelemetryPolicy)
def agent_policy(_: Agent = Depends(require_agent)) -> TelemetryPolicy:
    return load_policy()


app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")
