from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent
_ENV_FILES = (
    str(_BACKEND_ROOT / ".env"),
    str(_REPO_ROOT / ".env"),
)


class Settings(BaseSettings):
    APP_NAME: str = "kyrox-core"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/kyrox_core"

    JWT_SECRET_KEY: str = "dev-insecure-change-me-use-env-in-production-32b"
    JWT_ALGORITHM: str = "HS256"
    # Access JWT lifetime in days (Fair CRM session alignment).
    ACCESS_TOKEN_EXPIRE_DAYS: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 15

    # Purpose-separated read-only credential for product background workers to
    # query canonical organization lifecycle eligibility. Never reuse user JWTs
    # or provider credentials for this contract. No default secret is accepted:
    # unset, short or dev-insecure values make the endpoints fail closed (503).
    CORE_PRODUCT_LIFECYCLE_TOKEN: str | None = None
    # Purpose-separated product worker -> platform in-app delivery credential.
    CORE_PRODUCT_NOTIFICATION_TOKEN: str | None = None

    # OL09-B purpose-separated Core -> FAIR CRM suspension-security delivery.
    # No default secret is accepted: deployments must explicitly configure the
    # same value on Core and FAIR CRM.
    FAIR_CRM_BASE_URL: str = "http://localhost:8001"
    FAIR_CRM_CORE_LIFECYCLE_SIGNAL_TOKEN: str | None = None
    CORE_JOB_DISPATCH_INTERVAL_SECONDS: float = 5.0

    # Dedicated secret for reconstructable, hash-only persisted identity action
    # tokens used by asynchronous identity-email delivery.
    CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY: str = (
        "dev-insecure-identity-action-token-secret-change-me"
    )
    CORE_IDENTITY_ACTION_TOKEN_TTL_HOURS: int = 24
    CORE_IDENTITY_PASSWORD_RESET_TTL_MINUTES: int = 60
    CORE_IDENTITY_PASSWORD_RESET_COOLDOWN_SECONDS: int = 60
    CORE_IDENTITY_ACTIVATION_URL_TEMPLATE: str = (
        "http://localhost:3000/activate?token={token}"
    )
    CORE_IDENTITY_PASSWORD_RESET_URL_TEMPLATE: str = (
        "http://localhost:3000/reset-password?token={token}"
    )

    # Core-owned identity/platform email. These credentials are deliberately
    # separate from product/tenant mail accounts such as FAIR CRM providers.
    CORE_EMAIL_PROVIDER: str = "log"
    CORE_EMAIL_FROM: str | None = None
    CORE_SMTP_HOST: str | None = None
    CORE_SMTP_PORT: int = 587
    CORE_SMTP_USERNAME: str | None = None
    CORE_SMTP_PASSWORD: str | None = None
    CORE_SMTP_STARTTLS: bool = True
    CORE_SMTP_SSL: bool = False
    CORE_SMTP_TIMEOUT_SECONDS: float = 10.0

    model_config = SettingsConfigDict(
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
