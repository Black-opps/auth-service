import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter.
    Replace with Redis later for production.
    """

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.clients = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host

        current_time = time.time()
        window_start = current_time - 60

        if client_ip not in self.clients:
            self.clients[client_ip] = []

        # remove expired timestamps
        self.clients[client_ip] = [
            ts for ts in self.clients[client_ip] if ts > window_start
        ]

        if len(self.clients[client_ip]) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
            )

        self.clients[client_ip].append(current_time)

        return await call_next(request)
