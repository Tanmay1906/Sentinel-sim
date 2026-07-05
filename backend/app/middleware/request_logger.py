"""
HTTP Middleware for logging structured request details and latency metrics.
"""
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
# pyrefly: ignore [missing-import]
from loguru import logger

class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """
    HTTP Middleware that logs structured request and response details,
    including HTTP method, path, status code, and latency.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()
        method = request.method
        path = request.url.path
        
        logger.debug(f"Incoming request: {method} {path}")
        
        response: Response = await call_next(request)
        
        duration = time.perf_counter() - start_time
        status_code = response.status_code
        
        logger.info(
            f"HTTP {status_code} | {method} {path} | Latency: {duration:.4f}s"
        )
        return response
