"""Enforce request budgets before JSON parsing, including chunked bodies."""
import asyncio
from starlette.responses import JSONResponse


class RequestLimitsMiddleware:
    def __init__(self, app, max_bytes=2 * 1024 * 1024, concurrent=16, timeout=10):
        self.app = app
        self.max_bytes = max_bytes
        self.semaphore = asyncio.Semaphore(concurrent)
        self.timeout = timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.semaphore.locked():
            return await JSONResponse({"detail": "request capacity reached"}, status_code=429)(scope, receive, send)
        async with self.semaphore:
            headers = dict(scope.get("headers", []))
            try:
                length = int(headers.get(b"content-length", b"0"))
                if length < 0:
                    raise ValueError
            except ValueError:
                return await JSONResponse({"detail": "invalid Content-Length"}, status_code=400)(scope, receive, send)
            if length > self.max_bytes:
                return await JSONResponse({"detail": "request too large"}, status_code=413)(scope, receive, send)
            body = bytearray()
            try:
                async with asyncio.timeout(self.timeout):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        chunk = message.get("body", b"")
                        if len(body) + len(chunk) > self.max_bytes:
                            return await JSONResponse({"detail": "request too large"}, status_code=413)(scope, receive, send)
                        body.extend(chunk)
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                return await JSONResponse({"detail": "request body timeout"}, status_code=408)(scope, receive, send)
            delivered = False

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
