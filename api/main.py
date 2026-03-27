"""
api/main.py
-----------
Application entry point.  Contains only:
  - lifespan (startup / shutdown)
  - FastAPI app creation + CORS middleware
  - Router registrations

All route definitions live in api/routes.py and api/websocket.py.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router as api_router
from api.websocket import router as websocket_router
from db.session import init_db
from detection.service import detection_service
from nlp.model import load_model
from simulator.generator import event_stream_service


@asynccontextmanager
async def lifespan(_: FastAPI):
    await asyncio.to_thread(init_db)
    await asyncio.to_thread(detection_service.initialize, 5000)
    await asyncio.to_thread(load_model)
    await event_stream_service.start()
    try:
        yield
    finally:
        await event_stream_service.stop()


app = FastAPI(title="SENTINEL AI-SOC", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(websocket_router)
app.include_router(api_router)
