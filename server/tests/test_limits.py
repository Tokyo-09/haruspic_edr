import asyncio
import unittest
from spire_server.limits import RequestLimitsMiddleware


class RequestLimitTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, chunks, headers=(), cap=8):
        messages = []
        calls = []
        chunks = iter(chunks)

        async def receive():
            return next(chunks)

        async def send(message):
            messages.append(message)

        async def app(scope, receive, send):
            calls.append(await receive())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        await RequestLimitsMiddleware(app, max_bytes=cap)({"type":"http", "headers":list(headers)}, receive, send)
        return messages[0]["status"], calls

    async def test_chunked_overflow_rejected_before_application(self):
        status, calls = await self.invoke([
            {"type":"http.request", "body":b"12345", "more_body":True},
            {"type":"http.request", "body":b"6789", "more_body":False},
        ])
        self.assertEqual(status,413)
        self.assertEqual(calls,[])

    async def test_declared_oversize_rejected_without_reading(self):
        status, calls = await self.invoke([], [(b"content-length", b"999")])
        self.assertEqual((status,calls),(413,[]))

    async def test_exact_limit_body_is_replayed(self):
        status, calls = await self.invoke([
            {"type":"http.request", "body":b"1234", "more_body":True},
            {"type":"http.request", "body":b"5678", "more_body":False},
        ])
        self.assertEqual(status,200)
        self.assertEqual(calls[0]["body"],b"12345678")

    async def test_concurrency_limit_has_no_unbounded_wait_queue(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def app(scope, receive, send):
            entered.set()
            await release.wait()
        async def receive():
            return {"type":"http.request", "body":b"", "more_body":False}
        messages = []
        async def send(message):
            messages.append(message)
        middleware=RequestLimitsMiddleware(app,concurrent=1)
        first=asyncio.create_task(middleware({"type":"http"},receive,send))
        await entered.wait()
        try:
            await middleware({"type":"http"},receive,send)
            self.assertEqual(messages[0]["status"],429)
        finally:
            release.set()
            await first

    async def test_slow_request_times_out(self):
        async def receive():
            await asyncio.sleep(1)
        async def app(*args):
            self.fail("Application must not receive an incomplete body")
        messages=[]
        async def send(message):
            messages.append(message)
        await RequestLimitsMiddleware(app,timeout=0.01)({"type":"http"},receive,send)
        self.assertEqual(messages[0]["status"],408)
