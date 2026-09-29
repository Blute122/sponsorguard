"""Vercel entrypoint: the SponsorGuard API and the built web UI on one domain.

  * /api/*  -> the FastAPI app from api/main.py, unchanged (so /api/analyze is
               its /analyze route). Mounted first, so it always wins.
  * /*      -> the Vite build in web/dist. Vercel promotes StaticFiles mounts to
               its CDN, so page loads never touch the Python function.

Serving both from one origin means the browser never makes a cross-origin
request, so api/main.py's localhost-only CORS list needs no production entry.

Local dev is unchanged: run `uvicorn api.main:app` and `npm run dev` as the
README describes. This module only needs web/dist to exist (`npm run build`).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.main import app as api_app

WEB_DIST = Path(__file__).parent / "web" / "dist"

# The outer app only routes; the API's own OpenAPI docs stay at /api/docs.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/api", api_app)
app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")
