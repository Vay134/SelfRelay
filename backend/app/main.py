from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.adapters import create_auth_gateway
from app.auth import InMemoryAccountStore, OtpBootstrapService, RepositoryAccountStore, router
from app.config import load_settings
from app.database import Database
from app.logging import configure_logging
from app.repositories import AccountRepository

configure_logging()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()
    auth_gateway = create_auth_gateway(settings.app_env, settings.auth_adapter)
    database = Database(settings.database_url)
    await database.connect()
    application.state.database = database
    application.state.settings = settings
    application.state.auth_gateway = auth_gateway
    account_store = (
        InMemoryAccountStore()
        if settings.app_env == "test"
        else RepositoryAccountStore(AccountRepository(database))
    )
    auth_service = OtpBootstrapService(auth_gateway, account_store)
    application.state.otp_service = auth_service
    application.state.auth_service = auth_service
    try:
        yield
    finally:
        await database.close()


app = FastAPI(
    title="E2E Secure File Transfer System API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
