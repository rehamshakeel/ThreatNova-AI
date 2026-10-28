"""FastAPI API routers package."""

from app.routers.health import router as health_router
from app.routers.investigations import router as investigations_router
from app.routers.findings import router as findings_router
from app.routers.alerts import router as alerts_router
from app.routers.indicators import router as indicators_router
from app.routers.ai import router as ai_router

__all__ = [
    "health_router",
    "investigations_router",
    "findings_router",
    "alerts_router",
    "indicators_router",
    "ai_router",
]
