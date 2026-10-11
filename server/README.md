> Для установки сервера и агентов используйте [мастер Spire Setup](../docs/installation.md).

> Изменение запуска: подписанные feed, отдельное реагирование и лимиты ресурсов описаны в [инструкции второго этапа](../docs/signed-updates-and-response.md). Неподписанные обновления больше не устанавливаются; сканирование по умолчанию работает в observe.

# SpireAV Telemetry Server

Python ingest API для агента `spired`. Стек: FastAPI + SQLAlchemy + SQLite, запуск через [uv](https://docs.astral.sh/uv/).

## Быстрый старт

```bash
cd server
uv sync
export SPIRE_ENROLLMENT_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SPIRE_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run uvicorn spire_server.main:app --app-dir src --host 127.0.0.1 --port 8080
```

Сервер слушает `http://127.0.0.1:8080`. OpenAPI: `/docs`.

## API

| Метод | Путь | Auth | Назначение |
| --- | --- | --- | --- |
| POST | `/v1/agents/enroll` | `X-Enrollment-Token` | Регистрация агента, выдача `agent_token` |
| POST | `/v1/telemetry/ingest` | `Bearer <agent_token>` | Пакет событий |
| POST | `/v1/agents/heartbeat` | `Bearer <agent_token>` | Keepalive |
| GET | `/v1/agents` | `Bearer <admin_token>` | Список хостов |
| GET | `/v1/events` | `Bearer <admin_token>` | Лента телеметрии |

Пример ingest:

```json
{
  "schema_version": 1,
  "events": [
    {
      "id": "11111111-1111-1111-1111-111111111111",
      "ts": "2026-09-18T22:00:00Z",
      "type": "file_event",
      "severity": "info",
      "data": { "path": "/tmp/sample.bin", "action": "create" }
    }
  ]
}
```

Типы событий: `heartbeat`, `host_info`, `file_event`, `scan_result`, `detection`, `command_result`.

Консоль: http://127.0.0.1:8080/console

| Метод | Путь | Назначение |
| --- | --- | --- |
| GET | `/v1/alerts` | Алерты |
| PATCH | `/v1/alerts/{id}` | `open` / `ack` / `closed` |
| POST | `/v1/agents/{id}/commands` | `ping`, `collect_inventory`, `scan_path` |
| GET | `/v1/stats` | Счётчики флота |

Коммерческий контур: `docs/architecture-edr.md`. Продукт: `docs/PRODUCT.md`.
