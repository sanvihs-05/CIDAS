"""CIDAS daemon entry point.

Builds the FastAPI application with lifespan management, CORS restricted to
localhost origins, a request-timing middleware, and the main API router.
Run directly with ``python -m daemon.main`` or via the ``cidas-daemon`` script.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .auth import get_or_create_token
from .config import get_settings
from .database import init_db
from .router import router
from .utils.logger import get_logger

log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI):  # type: ignore[type-arg]
    settings = get_settings()
    log.info("CIDAS daemon starting on %s:%s", settings.daemon_host, settings.daemon_port)
    get_or_create_token()  # ensure ~/.cidas/daemon.token exists before any client calls
    await init_db()
    yield
    log.info("CIDAS daemon shutting down")


app = FastAPI(
    title="CIDAS Daemon",
    description="Pre-install npm package security screening",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1",
        "http://localhost",
        "vscode-webview://*",
    ],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _timing_middleware(request: Request, call_next) -> Response:  # type: ignore[type-arg]
    t0 = time.perf_counter()
    response: Response = await call_next(request)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    response.headers["X-CIDAS-Latency-Ms"] = f"{elapsed_ms:.1f}"
    log.debug("%s %s → %s in %.1f ms", request.method, request.url.path, response.status_code, elapsed_ms)
    return response


app.include_router(router, prefix="/api/v1")

_static_dir = Path(__file__).parent / "static"
app.mount("/dashboard", StaticFiles(directory=str(_static_dir), html=True), name="dashboard")


def start() -> None:
    """Entry point used by the ``cidas-daemon`` console script."""
    settings = get_settings()
    uvicorn.run(
        "daemon.main:app",
        host=settings.daemon_host,
        port=settings.daemon_port,
        log_level=settings.log_level,
        reload=False,
    )


if __name__ == "__main__":
    start()
