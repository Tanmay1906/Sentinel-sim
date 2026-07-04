
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.websocket_manager import ConnectionManager
from app.middleware.correlation import CorrelationIdMiddleware

# Setup Logging
setup_logging()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description=settings.PROJECT_DESCRIPTION,
    # Documentation enabled only in development/local
    docs_url=settings.API_V1_STR + "/docs" if settings.is_dev else None,
    redoc_url=settings.API_V1_STR + "/redoc" if settings.is_dev else None,
)

# Initialize and attach the WebSocket Manager to app state
app.state.ws_manager = ConnectionManager()

# Middlewares
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info(f"System Mode: {settings.ENVIRONMENT}")
    logger.info("Control Plane Ready.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.warning("System shutting down.")