import pytest

from app.config import ConfigurationError, Settings, load_settings


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "APP_ENV": "test",
        "APP_ORIGIN": "http://localhost:5173",
        "API_ORIGIN": "http://localhost:8000",
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
    assert settings.log_level == "DEBUG"
    assert settings.auth_adapter == "fake"
    assert settings.turn_adapter == "fake"


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
        ("API_ORIGIN", "https://user:password@api.example.test"),
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
        )
    )

    assert settings.app_env == "production"
    assert settings.auth_adapter == "supabase"
    assert settings.turn_adapter == "cloudflare"
