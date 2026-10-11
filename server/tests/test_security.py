"""Regression tests use an isolated database and no running service."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_state = tempfile.TemporaryDirectory(prefix="spire-server-tests-")
os.environ["SPIRE_ADMIN_TOKEN"] = "test-admin-" + "a" * 40
os.environ["SPIRE_ENROLLMENT_TOKEN"] = "test-enroll-" + "b" * 40
os.environ["SPIRE_DATABASE_URL"] = "sqlite:///" + _state.name + "/test.db"

from fastapi import HTTPException
from pydantic import ValidationError
from spire_server import main
from spire_server.db import Base, engine, SessionLocal, Agent, AgentCommand, Event
from spire_server.schemas import EnrollRequest, CommandCreate, IngestRequest
from spire_server.settings import Settings


class SecurityTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        self.db = SessionLocal()
        self.identity = main.enroll(EnrollRequest(hostname="host", os_name="linux", arch="x86_64"), self.db, None)
        self.agent = self.db.get(Agent, self.identity.agent_id)

    def tearDown(self):
        self.db.close()

    def test_enrollment_cannot_replace_identity(self):
        old_hash = self.agent.token_hash
        with self.assertRaises(HTTPException) as caught:
            main.enroll(EnrollRequest(hostname="other", os_name="linux", arch="x", agent_id=self.agent.id), self.db, None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.agent.token_hash, old_hash)

    def test_shell_is_rejected(self):
        with self.assertRaises(ValidationError):
            CommandCreate(command_type="run", payload={"command": "anything"})

    def test_unsafe_secrets_are_rejected(self):
        for token in ("", "dev-admin-token", "short"):
            with self.assertRaises(ValidationError):
                Settings(admin_token=token)

    def test_duplicate_within_batch_and_retry_are_idempotent(self):
        event = dict(id="event-1", ts=datetime.now(timezone.utc), type="detection", severity="high", data={})
        body = IngestRequest(events=[event, event])
        first = main.ingest(body, self.agent, self.db)
        self.assertEqual((first.accepted, first.duplicates), (1, 1))
        second = main.ingest(body, self.agent, self.db)
        self.assertEqual((second.accepted, second.duplicates), (0, 2))
        self.assertEqual(self.db.query(Event).count(), 1)

    def test_command_is_redelivered_after_lease_expires(self):
        command = main.create_command(self.agent.id, CommandCreate(command_type="ping"), self.db, None)
        self.assertEqual(len(main.pull_commands(self.agent, self.db)), 1)
        self.assertEqual(main.pull_commands(self.agent, self.db), [])
        row = self.db.get(AgentCommand, command.id)
        row.updated_at = datetime.now(timezone.utc) - timedelta(minutes=6)
        self.db.commit()
        self.assertEqual(main.pull_commands(self.agent, self.db)[0].id, command.id)

    def test_batch_limit(self):
        with self.assertRaises(ValidationError):
            IngestRequest(events=[])


if __name__ == "__main__":
    unittest.main()
