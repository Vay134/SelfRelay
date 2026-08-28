from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI

from app.adapters import create_auth_gateway, create_turn_credential_provider
from app.auth import (
    InMemoryAccountStore,
    OtpBootstrapService,
    RateLimiter,
    RepositoryAccountStore,
    router,
)
from app.config import load_settings
from app.database import Database
from app.device_auth import DeviceAuthService
from app.device_auth import router as device_router
from app.logging import configure_logging
from app.pairings import (
    PairingApprovalService,
    PairingApprovalStore,
    PairingEnrollmentService,
    PairingRequestService,
)
from app.pairings import router as pairing_router
from app.presence import PresenceManager, WebSocketTicketService
from app.presence import router as presence_router
from app.repositories import (
    AccountRepository,
    DeviceChallengeRepository,
    DeviceRepository,
    InMemoryDeviceChallengeRepository,
    InMemoryDeviceRepository,
    InMemoryPairingRequestRepository,
    InMemorySecurityEventRepository,
    InMemoryTransferRequestRepository,
    InMemoryWebSocketTicketRepository,
    PairingRequestRepository,
    PersistentRateLimiter,
    RateLimitBucketRepository,
    SecurityEventRepository,
    SessionRepository,
    TransferRequestRepository,
    WebSocketTicketRepository,
)
from app.security import ConfiguredCORSMiddleware
from app.session_api import SessionAuthenticator, SessionIssuer
from app.session_api import router as session_router
from app.sessions import InMemorySessionRepository, SessionService
from app.transfers import TransferService
from app.transfers import router as transfer_router
from app.turn import TurnCredentialService
from app.turn import router as turn_router

configure_logging()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()
    auth_gateway = create_auth_gateway(settings.app_env, settings.auth_adapter)
    turn_credential_provider = create_turn_credential_provider(
        settings.app_env,
        settings.turn_adapter,
        turn_key_id=settings.cloudflare_turn_key_id,
        api_token=settings.cloudflare_turn_api_token,
    )
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
    rate_limiter = (
        RateLimiter(secret=b"test-rate-limit-secret")
        if settings.app_env == "test"
        else PersistentRateLimiter(
            RateLimitBucketRepository(database),
            settings.rate_limit_secret.encode("utf-8"),
        )
    )
    auth_service = OtpBootstrapService(
        auth_gateway,
        account_store,
        rate_limiter=rate_limiter,
    )
    session_repository = (
        InMemorySessionRepository() if settings.app_env == "test" else SessionRepository(database)
    )
    session_service = SessionService(session_repository)
    device_repository = (
        InMemoryDeviceRepository(session_repository, account_store)
        if settings.app_env == "test"
        else DeviceRepository(database)
    )
    challenge_repository = (
        InMemoryDeviceChallengeRepository(device_repository)
        if settings.app_env == "test"
        else DeviceChallengeRepository(database)
    )
    pairing_repository = (
        InMemoryPairingRequestRepository(device_repository, session_repository)
        if settings.app_env == "test"
        else PairingRequestRepository(database)
    )
    security_event_repository = (
        InMemorySecurityEventRepository()
        if settings.app_env == "test"
        else SecurityEventRepository(database)
    )
    websocket_ticket_repository = (
        InMemoryWebSocketTicketRepository(session_repository)
        if settings.app_env == "test"
        else WebSocketTicketRepository(database)
    )
    transfer_repository = (
        InMemoryTransferRequestRepository(device_repository)
        if settings.app_env == "test"
        else TransferRequestRepository(database)
    )
    presence_manager = PresenceManager(
        device_repository,
        session_repository,
        transfer_repository,
    )
    device_auth_service = DeviceAuthService(
        account_store,
        device_repository,
        challenge_repository,
        session_service,
        bootstrap_consumer=auth_service.consume_bootstrap,
        bootstrap_peeker=auth_service.peek_bootstrap,
    )
    application.state.otp_service = auth_service
    application.state.auth_service = auth_service
    application.state.rate_limiter = rate_limiter
    application.state.session_repository = session_repository
    application.state.session_service = session_service
    application.state.session_authenticator = SessionAuthenticator(session_repository)
    application.state.session_issuer = SessionIssuer(session_service)
    application.state.websocket_ticket_repository = websocket_ticket_repository
    application.state.websocket_ticket_service = WebSocketTicketService(websocket_ticket_repository)
    application.state.presence_manager = presence_manager
    application.state.transfer_repository = transfer_repository
    transfer_service = TransferService(
        transfer_repository,
        presence_manager,
        device_repository,
    )
    application.state.transfer_service = transfer_service
    application.state.turn_credential_provider = turn_credential_provider
    application.state.turn_credential_service = TurnCredentialService(
        turn_credential_provider,
        transfer_service,
        device_repository,
        rate_limiter,
    )
    application.state.device_repository = device_repository
    application.state.device_challenge_repository = challenge_repository
    application.state.pairing_repository = pairing_repository
    application.state.security_event_repository = security_event_repository
    application.state.pairing_request_service = PairingRequestService(
        account_store,
        pairing_repository,
        rate_limiter=rate_limiter,
        security_event_store=security_event_repository,
    )
    application.state.pairing_approval_service = PairingApprovalService(
        account_store,
        device_repository,
        cast(PairingApprovalStore, pairing_repository),
        rate_limiter=rate_limiter,
        security_event_store=security_event_repository,
    )
    application.state.pairing_enrollment_service = PairingEnrollmentService(
        account_store,
        device_repository,
        cast(PairingApprovalStore, pairing_repository),
        session_service,
    )
    application.state.device_auth_service = device_auth_service
    try:
        yield
    finally:
        await presence_manager.close_all()
        await database.close()


app = FastAPI(
    title="E2E Secure File Transfer System API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(ConfiguredCORSMiddleware)

app.include_router(router)
app.include_router(session_router)
app.include_router(device_router)
app.include_router(pairing_router)
app.include_router(presence_router)
app.include_router(transfer_router)
app.include_router(turn_router)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
