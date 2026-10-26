from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_ROOT.parent
_ENV_FILES = (
    str(_BACKEND_ROOT / ".env"),
    str(_REPO_ROOT / ".env"),
)


DEV_JWT_SECRET_KEY = "dev-insecure-change-me-use-env-in-production-32b"
DEV_IDENTITY_ACTION_TOKEN_SECRET_KEY = "dev-insecure-identity-action-token-secret-change-me"
PRODUCTION_ENVIRONMENTS = frozenset({"production", "prod"})
MIN_SECRET_LENGTH = 32
# Public defaults (this repository, Fair CRM, .env.example files) are never
# acceptable in production, whatever their length.
_KNOWN_PUBLIC_SECRETS = frozenset({
    DEV_JWT_SECRET_KEY,
    DEV_IDENTITY_ACTION_TOKEN_SECRET_KEY,
    "change-me-in-production-use-a-long-random-string",
})
_INSECURE_MARKERS = ("dev-insecure", "change-me", "changeme")


class Settings(BaseSettings):
    APP_NAME: str = "kyrox-core"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/kyrox_core"

    JWT_SECRET_KEY: str = DEV_JWT_SECRET_KEY
    JWT_ALGORITHM: str = "HS256"
    # Access JWT lifetime. ADR-0003 targets 15 minutes, but the embedded FAIR
    # Stand editor keeps the access token it was mounted with and never
    # refreshes (SECURITY_PROGRAM F-C5), so the default stays at 15 days.
    # ACCESS_TOKEN_EXPIRE_MINUTES, when set, overrides the day value (e.g. 15
    # once every client refreshes on 401). Fair CRM must use the same lifetime.
    ACCESS_TOKEN_EXPIRE_DAYS: int = 15
    ACCESS_TOKEN_EXPIRE_MINUTES: int | None = None
    # Refresh token lifetime and absolute session lifetime (ADR-0003: 30 days).
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

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
    CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY: str = DEV_IDENTITY_ACTION_TOKEN_SECRET_KEY
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

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() in PRODUCTION_ENVIRONMENTS

    @property
    def access_token_expire_seconds(self) -> int:
        if self.ACCESS_TOKEN_EXPIRE_MINUTES is not None:
            return self.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        return self.ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

    model_config = SettingsConfigDict(
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


class InsecureConfigurationError(RuntimeError):
    """Startup refused: the configuration is unsafe for this environment."""


def _secret_problem(value: str | None) -> str | None:
    if value is None or not value.strip():
        return "empty"
    if value in _KNOWN_PUBLIC_SECRETS or any(marker in value.lower() for marker in _INSECURE_MARKERS):
        return "a public default"
    if len(value) < MIN_SECRET_LENGTH:
        return f"shorter than {MIN_SECRET_LENGTH} characters"
    return None


def validate_runtime_settings(config: Settings) -> None:
    """Fail fast at startup (SECURITY_PROGRAM F-C5). Secret values are never echoed."""
    problems: list[str] = []
    if config.ACCESS_TOKEN_EXPIRE_MINUTES is not None and config.ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
        problems.append("ACCESS_TOKEN_EXPIRE_MINUTES must be positive")
    if config.ACCESS_TOKEN_EXPIRE_DAYS <= 0 or config.REFRESH_TOKEN_EXPIRE_DAYS <= 0:
        problems.append("token lifetimes must be positive")
    elif config.access_token_expire_seconds > config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60:
        problems.append("access token lifetime must not exceed REFRESH_TOKEN_EXPIRE_DAYS")

    if config.is_production:
        for name in ("JWT_SECRET_KEY", "CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY"):
            problem = _secret_problem(getattr(config, name))
            if problem is not None:
                problems.append(f"{name} is {problem}")
        if config.JWT_SECRET_KEY == config.CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY:
            problems.append("JWT_SECRET_KEY and CORE_IDENTITY_ACTION_TOKEN_SECRET_KEY must differ")
        if config.DEBUG:
            problems.append("DEBUG must be false")

    if problems:
        raise InsecureConfigurationError(
            f"Refusing to start (ENVIRONMENT={config.ENVIRONMENT!r}): " + "; ".join(problems)
        )


settings = Settings()
