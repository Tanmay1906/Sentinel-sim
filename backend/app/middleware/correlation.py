import uuid
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Ensures every request has a unique ID for log tracing.
    """
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # Inject request_id into the logging context
        with logger.contextualize(request_id=request_id):
            response: Response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response