"""Explicit, read-only design preview. Never used on a live connection."""
from datetime import datetime, timedelta, timezone


def snapshot():
    now = datetime.now(timezone.utc)
    hosts = [("FINANCE-WS01", "windows", "online"), ("DEV-LINUX02", "linux", "online"),
             ("DESIGN-WS04", "windows", "online"), ("BACKUP-SRV", "linux", "offline"),
             ("OPS-LAPTOP", "windows", "online"), ("API-PROD01", "linux", "online")]
    agents = [dict(id=f"demo-agent-{i}", hostname=name, os_name=osname, arch="x86_64", agent_version="0.2.0",
                   last_seen_at=(now-timedelta(minutes=2 if status=="online" else 125)).isoformat(),
                   enrolled_at=(now-timedelta(days=12)).isoformat(), status=status) for i,(name,osname,status) in enumerate(hosts)]
    names = ["Подозрительный исполняемый файл", "Совпадение с правилом YARA", "Обнаружена известная сигнатура", "Подозрительный файл в загрузках"]
    alerts = [dict(id=i+1, agent_id=agents[i%6]["id"], event_id=f"demo-event-{i}", title=names[i%4],
                   severity=["high","medium","high","low"][i%4], status="open" if i<3 else "closed",
                   created_at=(now-timedelta(hours=i*7, minutes=12)).isoformat()) for i in range(18)]
    events = [dict(event_id=a["event_id"], agent_id=a["agent_id"], ts=a["created_at"], received_at=a["created_at"],
                   event_type="detection", severity=a["severity"], payload={"path":"C:\\Users\\analyst\\Downloads\\sample.exe", "mode":"observe", "demo":True}) for a in alerts]
    return {"stats":{"agents":6,"online":5,"open_alerts":3,"events":18}, "agents":agents,"alerts":alerts,"events":events}
