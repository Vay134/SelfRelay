from __future__ import annotations

from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.security import (
    MAX_HTTP_REQUEST_BYTES,
    REQUEST_BODY_TOO_LARGE_MESSAGE,
    RequestBodyLimitMiddleware,
)


def _client(max_body_bytes: int = MAX_HTTP_REQUEST_BYTES) -> tuple[TestClient, list[int]]:
    handled: list[int] = []
    application = FastAPI()
    application.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=max_body_bytes)

    @application.post("/echo")
    async def echo(payload: dict[str, str]) -> dict[str, int]:
        handled.append(len(payload.get("value", "")))
        return {"size": len(payload.get("value", ""))}

    return TestClient(application), handled


def test_bodies_within_the_limit_reach_the_endpoint() -> None:
    client, handled = _client(max_body_bytes=1024)

    response = client.post("/echo", json={"value": "a" * 16})

    assert response.status_code == 200
    assert response.json() == {"size": 16}
    assert handled == [16]


def test_declared_oversized_bodies_are_rejected_before_the_endpoint_runs() -> None:
    client, handled = _client(max_body_bytes=256)

    response = client.post("/echo", json={"value": "a" * 512})

    assert response.status_code == 413
    assert response.json() == {"detail": REQUEST_BODY_TOO_LARGE_MESSAGE}
    assert handled == []


def test_streamed_oversized_bodies_are_rejected_without_a_declared_length() -> None:
    client, handled = _client(max_body_bytes=256)

    def chunks() -> Iterator[bytes]:
        for _ in range(8):
            yield b"a" * 64

    response = client.post(
        "/echo",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": REQUEST_BODY_TOO_LARGE_MESSAGE}
    assert handled == []


def test_unparsable_content_length_is_rejected() -> None:
    client, handled = _client(max_body_bytes=256)

    response = client.post(
        "/echo",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "not-a-number"},
    )

    assert response.status_code == 413
    assert handled == []


def test_rejection_does_not_disclose_the_configured_limit() -> None:
    client, _ = _client(max_body_bytes=256)

    response = client.post("/echo", json={"value": "a" * 512})

    assert "256" not in response.text
