from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class TelemetryPolicy(BaseModel):
    send_heartbeat: bool = True
    send_host_info: bool = True
    send_file_events: bool = False
    send_clean_scans: bool = False
    send_detections: bool = True
    send_command_results: bool = True
    file_event_sample_percent: int = Field(default=10, ge=0, le=100)
    heartbeat_interval_secs: int = Field(default=30, ge=5, le=3600)
    max_batch: int = Field(default=100, ge=1, le=1000)


POLICY_PATH = Path("data/policy.json")


def load_policy() -> TelemetryPolicy:
    if POLICY_PATH.is_file():
        try:
            return TelemetryPolicy.model_validate_json(POLICY_PATH.read_text())
        except Exception:
            pass
    policy = TelemetryPolicy()
    save_policy(policy)
    return policy


def save_policy(policy: TelemetryPolicy) -> TelemetryPolicy:
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_PATH.write_text(policy.model_dump_json(indent=2))
    return policy
