"""F-C5 regression: production refuses unsafe secrets at startup; token TTLs.

E-023 evidence: ``ENVIRONMENT=production`` with the public default secrets
started and served health 200; ``ENVIRONMENT`` was never read.
"""

from __future__ import annotations

import pytest

from app.core.config import (
    DEV_IDENTITY_ACTION_TOKEN_SECRET_KEY,
    DEV_JWT_SECRET_KEY,
    InsecureConfigurationError,
    Settings,
    validate_runtime_settings,
)

STRONG_JWT = "j" * 24 + "Q7v-91xLm2Zp"
STRONG_ACTION = "a" * 24 + "Kd83-pq0Wz7R"


def _settings(**values) -> Settings:
    return Settings(_env_file=None, **values)


def test_production_with_default_secrets_does_not_start(monkeypatch) -> None:
    import app.main as main_module

    # Patch the settings object create_app() actually reads.
    active = main_module.settings
    monkeypatch.setattr(active, "ENVIRONMENT", "production")
    monkeypatch.setattr(active, "JWT_SECRET_KEY", DEV_JWT_SECRET_KEY)
    monkeypatch.setattr(
        active,
        "CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY",
        DEV_IDENTITY_ACTION_TOKEN_SECRET_KEY,
    )

    with pytest.raises(InsecureConfigurationError) as exc_info:
        main_module.create_app()

    message = str(exc_info.value)
    assert "JWT_SECRET_KEY" in message
    assert "CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY" in message
    assert DEV_JWT_SECRET_KEY not in message


@pytest.mark.parametrize(
    ("jwt_secret", "action_secret", "expected"),
    [
        ("", STRONG_ACTION, "JWT_SECRET_KEY is empty"),
        ("short-but-random-91", STRONG_ACTION, "JWT_SECRET_KEY is shorter than 32"),
        ("change-me-in-production-use-a-long-random-string", STRONG_ACTION, "JWT_SECRET_KEY is a public default"),
        (STRONG_JWT, "x" * 10, "CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY is shorter than 32"),
        (STRONG_JWT, STRONG_JWT, "must differ"),
    ],
)
def test_production_rejects_weak_secrets(jwt_secret: str, action_secret: str, expected: str) -> None:
    config = _settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY=jwt_secret,
        CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY=action_secret,
    )
    with pytest.raises(InsecureConfigurationError) as exc_info:
        validate_runtime_settings(config)
    assert expected in str(exc_info.value)
    if jwt_secret:
        assert jwt_secret not in str(exc_info.value)


def test_production_with_strong_secrets_starts() -> None:
    validate_runtime_settings(_settings(
        ENVIRONMENT="Production",
        JWT_SECRET_KEY=STRONG_JWT,
        CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY=STRONG_ACTION,
    ))


@pytest.mark.parametrize("environment", ["development", "test", "staging"])
def test_non_production_keeps_dev_defaults(environment: str) -> None:
    validate_runtime_settings(_settings(ENVIRONMENT=environment))


def test_production_rejects_debug() -> None:
    config = _settings(
        ENVIRONMENT="production",
        DEBUG=True,
        JWT_SECRET_KEY=STRONG_JWT,
        CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY=STRONG_ACTION,
    )
    with pytest.raises(InsecureConfigurationError, match="DEBUG must be false"):
        validate_runtime_settings(config)


def test_token_lifetimes() -> None:
    defaults = _settings()
    # ADR-0003 refresh/session lifetime; access stays 15 days until every client refreshes.
    assert defaults.REFRESH_TOKEN_EXPIRE_DAYS == 30
    assert defaults.access_token_expire_seconds == 15 * 24 * 60 * 60
    assert _settings(ACCESS_TOKEN_EXPIRE_MINUTES=15).access_token_expire_seconds == 900
    with pytest.raises(InsecureConfigurationError, match="must not exceed"):
        validate_runtime_settings(_settings(ACCESS_TOKEN_EXPIRE_DAYS=31))
    with pytest.raises(InsecureConfigurationError, match="must be positive"):
        validate_runtime_settings(_settings(ACCESS_TOKEN_EXPIRE_MINUTES=0))
