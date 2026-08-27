from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import load_settings
from app.database import Database
from app.logging import configure_logging

configure_logging()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()
    database = Database(settings.database_url)
    await database.connect()
    application.state.database = database
    try:
        yield
    finally:
        await database.close()


app = FastAPI(
    title="E2E Secure File Transfer System API",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
