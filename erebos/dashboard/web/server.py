"""Web dashboard server using Starlette + SSE.

VT-Spec ID-01: Default bind to 127.0.0.1 only.
VT-Spec DoS-01: SSE connection cap at 10 with heartbeat timeout.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from sse_starlette.sse import EventSourceResponse

from erebos.dashboard.data_layer import DashboardDataLayer

logger = logging.getLogger(__name__)

# VT-Spec DoS-01: Max concurrent SSE connections
MAX_SSE_CONNECTIONS = 10
SSE_HEARTBEAT_SECONDS = 30
SSE_TIMEOUT_SECONDS = 60

# Track active SSE connections
_active_sse_connections = 0
_sse_lock = threading.Lock()

STATIC_DIR = Path(__file__).parent / "static"


def _get_data_layer() -> DashboardDataLayer:
    return DashboardDataLayer()


# ── API Routes ──────────────────────────────────────────────────────────


async def api_snapshot(request: Request) -> JSONResponse:
    """Get current dashboard snapshot."""
    scan_id = request.query_params.get("scan_id")
    data_layer = _get_data_layer()
    snapshot = data_layer.get_snapshot(scan_id)
    return JSONResponse(json.loads(snapshot.model_dump_json()))


async def api_findings(request: Request) -> JSONResponse:
    """Get all findings for a scan."""
    scan_id = request.query_params.get("scan_id")
    data_layer = _get_data_layer()
    findings = data_layer.get_findings(scan_id)
    return JSONResponse([json.loads(f.model_dump_json()) for f in findings])


async def api_scans(request: Request) -> JSONResponse:
    """List all available scans."""
    data_layer = _get_data_layer()
    scans = data_layer.list_scans()
    return JSONResponse(scans)


async def api_events(request: Request) -> EventSourceResponse:
    """SSE endpoint for live dashboard updates.

    VT-Spec DoS-01: Connection cap + heartbeat timeout.
    """
    global _active_sse_connections

    with _sse_lock:
        if _active_sse_connections >= MAX_SSE_CONNECTIONS:
            return JSONResponse(
                {"error": "Too many SSE connections", "max": MAX_SSE_CONNECTIONS},
                status_code=429,
            )
        _active_sse_connections += 1

    scan_id = request.query_params.get("scan_id")

    async def event_generator():
        global _active_sse_connections
        data_layer = _get_data_layer()
        bus_offset = 0
        last_activity = time.monotonic()

        try:
            while True:
                # VT-Spec DoS-01: Timeout stale connections
                if time.monotonic() - last_activity > SSE_TIMEOUT_SECONDS:
                    logger.info("SSE connection timed out due to inactivity")
                    break

                # Send snapshot update
                snapshot = data_layer.get_snapshot(scan_id)
                yield {
                    "event": "snapshot",
                    "data": snapshot.model_dump_json(),
                }
                last_activity = time.monotonic()

                # Send new bus events
                events, bus_offset = data_layer.tail_bus_from(bus_offset, scan_id)
                for event in events:
                    yield {
                        "event": "bus",
                        "data": event.model_dump_json(),
                    }
                    last_activity = time.monotonic()

                # Heartbeat
                await asyncio.sleep(2)

        finally:
            with _sse_lock:
                _active_sse_connections -= 1

    return EventSourceResponse(event_generator())


async def index(request: Request) -> HTMLResponse:
    """Serve the dashboard HTML."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text())
    return HTMLResponse("<h1>Erebos Dashboard</h1><p>Static files not found.</p>")


# ── App Factory ─────────────────────────────────────────────────────────


def create_app() -> Starlette:
    """Create the Starlette web dashboard application."""
    routes = [
        Route("/", index),
        Route("/api/snapshot", api_snapshot),
        Route("/api/findings", api_findings),
        Route("/api/scans", api_scans),
        Route("/api/events", api_events),
    ]

    # Mount static files if directory exists
    if STATIC_DIR.exists():
        routes.append(Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"))

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["GET"],
            allow_headers=["*"],
        ),
    ]

    return Starlette(routes=routes, middleware=middleware)


def run_web(
    host: str = "127.0.0.1",
    port: int = 8484,
    open_browser: bool = True,
) -> None:
    """Start the web dashboard server.

    VT-Spec ID-01: Default bind to 127.0.0.1.
    Emits warning if non-localhost binding is used.
    """
    import click
    import uvicorn

    # VT-Spec ID-01: Security warning for non-localhost binding
    if host not in ("127.0.0.1", "localhost", "::1"):
        click.secho(
            f"⚠️  WARNING: Binding to {host} exposes scan findings to the network. "
            "Consider using 127.0.0.1 (default) or adding authentication.",
            fg="yellow",
            bold=True,
            err=True,
        )

    click.echo(f"🌐 Erebos Dashboard: http://{host}:{port}")
    click.echo("   Press Ctrl+C to stop\n")

    if open_browser and host in ("127.0.0.1", "localhost", "::1"):
        import webbrowser

        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="warning")
