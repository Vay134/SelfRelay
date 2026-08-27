"""Core private-schema repository boundary."""

from .accounts import AccountRepository, AppUserRepository
from .challenges import (
    ChallengeRepository,
    DeviceChallengeRepository,
    InMemoryDeviceChallengeRepository,
)
from .cleanup import (
    DEFAULT_CLEANUP_BATCH_SIZE,
    MAX_CLEANUP_BATCH_SIZE,
    CleanupRepository,
    ExpiryCleanupRepository,
)
from .devices import DeviceRepository, InMemoryDeviceRepository, TrustedDeviceRepository
from .models import (
    AccountRecord,
    AppUserRecord,
    DeviceChallengeRecord,
    DeviceRecord,
    PairingRequestRecord,
    RateLimitBucketRecord,
    SecurityEventRecord,
    SessionRecord,
    TransferRequestRecord,
    WebSocketTicketRecord,
)
from .pairings import PairingRepository, PairingRequestRepository
from .rate_limits import PersistentRateLimiter, RateLimitBucketRepository, RateLimitRepository
from .security_events import SecurityEventLogRepository, SecurityEventRepository
from .sessions import SessionRepository
from .transfers import TransferRepository, TransferRequestRepository
from .websocket_tickets import WebSocketTicketRepository, WebsocketTicketRepository

__all__ = [
    "AccountRecord",
    "AccountRepository",
    "AppUserRecord",
    "AppUserRepository",
    "ChallengeRepository",
    "CleanupRepository",
    "DEFAULT_CLEANUP_BATCH_SIZE",
    "DeviceChallengeRecord",
    "DeviceChallengeRepository",
    "InMemoryDeviceChallengeRepository",
    "DeviceRecord",
    "DeviceRepository",
    "ExpiryCleanupRepository",
    "MAX_CLEANUP_BATCH_SIZE",
    "PairingRepository",
    "PairingRequestRecord",
    "PairingRequestRepository",
    "RateLimitBucketRecord",
    "RateLimitBucketRepository",
    "RateLimitRepository",
    "PersistentRateLimiter",
    "SecurityEventLogRepository",
    "SecurityEventRecord",
    "SecurityEventRepository",
    "SessionRecord",
    "SessionRepository",
    "InMemoryDeviceRepository",
    "TransferRepository",
    "TransferRequestRecord",
    "TransferRequestRepository",
    "TrustedDeviceRepository",
    "WebSocketTicketRecord",
    "WebSocketTicketRepository",
    "WebsocketTicketRepository",
]
