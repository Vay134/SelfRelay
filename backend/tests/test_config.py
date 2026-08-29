import pytest

from app.config import ConfigurationError, Settings, load_settings


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "APP_ENV": "test",
        "APP_ORIGIN": "http://localhost:5173",
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": "postgresql://localhost:5432/e2e_secure_file_transfer",
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
    }
    values.update(overrides)
    return values


def test_load_settings_returns_typed_values() -> None:
    settings = load_settings(_environment(LOG_LEVEL="debug"))

    assert isinstance(settings, Settings)
    assert settings.app_env == "test"
    assert settings.app_origin == "http://localhost:5173"
    assert settings.api_origin == "http://localhost:8000"
    assert settings.database_url == "postgresql://localhost:5432/e2e_secure_file_transfer"
    assert settings.log_level == "DEBUG"
    assert settings.auth_adapter == "fake"
    assert settings.turn_adapter == "fake"
    assert settings.cloudflare_turn_key_id is None
    assert settings.cloudflare_turn_api_token is None


@pytest.mark.parametrize("value", ["", "staging", "prod", "developmental"])
def test_invalid_app_environment_is_rejected(value: str) -> None:
    with pytest.raises(ConfigurationError, match="APP_ENV"):
        load_settings(_environment(APP_ENV=value))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("APP_ORIGIN", "localhost:5173"),
        ("APP_ORIGIN", "https://app.example.test/path"),
        ("APP_ORIGIN", "https://app.example.test?query=1"),
        ("API_ORIGIN", "ftp://api.example.test"),
        # secretlint-disable
        ("API_ORIGIN", "https://user:password@api.example.test"),
        # secretlint-enable
        ("API_ORIGIN", "https://api.example.test:bad"),
    ],
)
def test_invalid_origins_are_rejected(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError, match=name):
        load_settings(_environment(**{name: value}))


def test_origin_trailing_slash_is_normalized() -> None:
    settings = load_settings(
        _environment(APP_ORIGIN="https://app.example.test/", API_ORIGIN="https://api.example.test/")
    )

    assert settings.app_origin == "https://app.example.test"
    assert settings.api_origin == "https://api.example.test"


@pytest.mark.parametrize(
    "value",
    ["", "http://database.example.test", "postgresql://", "postgresql://db.example.test:bad"],
)
def test_invalid_database_urls_are_rejected(value: str) -> None:
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        load_settings(_environment(DATABASE_URL=value))


@pytest.mark.parametrize("value", ["TRACE", "VERBOSE", "", "123"])
def test_invalid_log_level_is_rejected(value: str) -> None:
    with pytest.raises(ConfigurationError, match="LOG_LEVEL"):
        load_settings(_environment(LOG_LEVEL=value))


@pytest.mark.parametrize("name", ["AUTH_ADAPTER", "TURN_ADAPTER"])
def test_invalid_adapter_is_rejected(name: str) -> None:
    with pytest.raises(ConfigurationError, match=name):
        load_settings(_environment(**{name: "unknown"}))


@pytest.mark.parametrize(
    ("name", "value"),
    [("AUTH_ADAPTER", "fake"), ("TURN_ADAPTER", "fake")],
)
def test_fake_adapters_are_rejected_in_production(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError, match="fake adapters"):
        load_settings(_environment(APP_ENV="production", **{name: value}))


def test_real_adapters_are_allowed_in_production() -> None:
    settings = load_settings(
        _environment(
            APP_ENV="production",
            AUTH_ADAPTER="supabase",
            TURN_ADAPTER="cloudflare",
            SUPABASE_URL="https://project.supabase.co",
            SUPABASE_PUBLISHABLE_KEY="sb_publishable_test_key",
            CLOUDFLARE_TURN_KEY_ID="turn-key-id",
            CLOUDFLARE_TURN_API_TOKEN="turn-api-token",
        )
    )

    assert settings.app_env == "production"
    assert settings.auth_adapter == "supabase"
    assert settings.turn_adapter == "cloudflare"
    assert settings.cloudflare_turn_key_id == "turn-key-id"
    assert settings.cloudflare_turn_api_token == "turn-api-token"


def test_disabled_turn_adapter_is_allowed_in_production_without_turn_secrets() -> None:
    settings = load_settings(
        _environment(
            APP_ENV="production",
            AUTH_ADAPTER="supabase",
            TURN_ADAPTER="disabled",
            SUPABASE_URL="https://project.supabase.co",
            SUPABASE_PUBLISHABLE_KEY="sb_publishable_test_key",
        )
    )

    assert settings.turn_adapter == "disabled"
    assert settings.cloudflare_turn_key_id is None
    assert settings.cloudflare_turn_api_token is None


@pytest.mark.parametrize("name", ["CLOUDFLARE_TURN_KEY_ID", "CLOUDFLARE_TURN_API_TOKEN"])
def test_cloudflare_turn_adapter_requires_server_credentials(name: str) -> None:
    provided = {
        "CLOUDFLARE_TURN_KEY_ID": "turn-key-id",
        "CLOUDFLARE_TURN_API_TOKEN": "turn-api-token",
    }
    provided.pop(name)
    with pytest.raises(ConfigurationError, match=name):
        load_settings(_environment(TURN_ADAPTER="cloudflare", **provided))


def test_cloudflare_turn_secret_values_must_not_be_empty() -> None:
    with pytest.raises(ConfigurationError, match="CLOUDFLARE_TURN_API_TOKEN"):
        load_settings(
            _environment(
                TURN_ADAPTER="cloudflare",
                CLOUDFLARE_TURN_KEY_ID="turn-key-id",
                CLOUDFLARE_TURN_API_TOKEN=" ",
            )
        )
