from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

import json
from pydantic import BaseModel, Field, field_validator


EventType = str


class EnrollRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=64)
    arch: str = Field(min_length=1, max_length=32)
    agent_version: str = "0.2.0"
    agent_id: str | None = None


class EnrollResponse(BaseModel):
    agent_id: str
    agent_token: str
    ingest_url: str = "/v1/telemetry/ingest"
    heartbeat_interval_secs: int = 30
    policy_url: str = "/v1/policy"


class TelemetryEvent(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    ts: datetime
    type: EventType = Field(min_length=1, max_length=64)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def bounded_data(cls, value):
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) > 240 * 1024:
            raise ValueError("Event data exceeds 240 KiB")
        return value


class IngestRequest(BaseModel):
    schema_version: Literal[1] = 1
    events: list[TelemetryEvent] = Field(min_length=1, max_length=1000)


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int = 0


class AgentOut(BaseModel):
    id: str
    hostname: str
    os_name: str
    arch: str
    agent_version: str
    last_seen_at: datetime
    enrolled_at: datetime
    status: str


class EventOut(BaseModel):
    event_id: str
    agent_id: str
    ts: datetime
    event_type: str
    severity: str
    payload: dict[str, Any]
    received_at: datetime


class AlertOut(BaseModel):
    id: int
    agent_id: str
    event_id: str
    title: str
    severity: str
    status: str
    created_at: datetime


class AlertPatch(BaseModel):
    status: Literal["open", "ack", "closed"]


class CommandCreate(BaseModel):
    command_type: Literal["collect_inventory", "scan_path", "ping"]
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value):
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) > 16 * 1024:
            raise ValueError("Command payload exceeds 16 KiB")
        return value


class CommandOut(BaseModel):
    id: str
    agent_id: str
    command_type: str
    payload: dict[str, Any]
    status: str
    result: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class CommandAck(BaseModel):
    status: Literal["acked", "failed"]
    result: dict[str, Any] = Field(default_factory=dict)
