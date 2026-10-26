from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TokenPolicy:
    access_token_expire_seconds: int
    refresh_token_expire_days: int

    def __post_init__(self) -> None:
        if self.access_token_expire_seconds <= 0 or self.refresh_token_expire_days <= 0:
            raise ValueError("Token lifetimes must be positive")
        if self.access_token_expire_seconds > self.refresh_token_expire_days * 24 * 60 * 60:
            raise ValueError("Access token lifetime cannot exceed the refresh/session lifetime")
