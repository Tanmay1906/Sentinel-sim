from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from loguru import logger

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.websocket_manager import ConnectionManager
from app.middleware.correlation import CorrelationIdMiddleware
from app.middleware.request_logger import RequestLoggerMiddleware

# Import API Routers
from app.api.routes.health import router as health_router
from app.api.routes.simulation import router as simulation_router
from app.api.routes.detections import router as detections_router
from app.api.routes.statistics import router as statistics_router

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
app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Versioned Routes
app.include_router(health_router, prefix=settings.API_V1_STR, tags=["Health"])
app.include_router(simulation_router, prefix=settings.API_V1_STR, tags=["Simulation"])
app.include_router(detections_router, prefix=settings.API_V1_STR, tags=["Detections"])
app.include_router(statistics_router, prefix=settings.API_V1_STR, tags=["Statistics"])

@app.on_event("startup")
async def startup_event():
    logger.info(f"System Mode: {settings.ENVIRONMENT}")
    logger.info("Control Plane Ready.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.warning("System shutting down.")