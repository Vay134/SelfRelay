from fastapi import FastAPI

from app.logging import configure_logging

configure_logging()

app = FastAPI(
    title="E2E Secure File Transfer System API",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
