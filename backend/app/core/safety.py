import threading
from urllib.parse import urlsplit

from fastapi import HTTPException
from starlette.responses import JSONResponse


class LocalSafetyMiddleware:
    """Bound request bodies before multipart parsing or temporary-file spooling."""
    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self.upload_slot = threading.BoundedSemaphore(1)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        method, path = scope["method"], scope["path"]
        upload = method == "POST" and path == "/api/captures"
        limit = self.settings.max_upload_bytes + 65536 if upload else 262144

        async def reject(status, detail):
            return await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)

        if method not in ("GET", "HEAD", "OPTIONS") and headers.get(b"origin"):
            try:
                origin = urlsplit(headers[b"origin"].decode("ascii"))
                valid = origin.scheme in ("http", "https") and origin.hostname in ("localhost", "127.0.0.1", "testserver")
            except (ValueError, UnicodeError):
                valid = False
            if not valid:
                return await reject(403, "Cross-origin writes are not permitted")
        if b"content-length" in headers:
            try:
                length = int(headers[b"content-length"])
                if length < 0:
                    return await reject(400, "Invalid Content-Length")
                if length > limit:
                    return await reject(413, "Request exceeds size limit")
            except ValueError:
                return await reject(400, "Invalid Content-Length")
        if upload and not self.upload_slot.acquire(blocking=False):
            return await reject(429, "Another capture upload is in progress")
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > limit:
                    raise HTTPException(413, "Streamed request exceeds size limit")
            return message

        async def secured_send(message):
            if message["type"] == "http.response.start":
                message["headers"] += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
                                        (b"cache-control", b"no-store"),
                                        (b"x-frame-options", b"DENY")]
                if not path.startswith(("/api/", "/docs", "/redoc")):
                    message["headers"].append((b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"))
            await send(message)
        try:
            await self.app(scope, bounded_receive, secured_send)
        finally:
            if upload:
                self.upload_slot.release()
