from datetime import datetime
from typing import Protocol


class LoginAttemptLimiter(Protocol):
    """Persistent failed-sign-in counter shared by every Core worker (F-004).

    ``email`` is the normalized submitted address (the account may not exist);
    ``ip_address`` is the client address as seen by Core, if any.
    """

    def locked_until(self, email: str, ip_address: str | None, now: datetime) -> datetime | None: ...

    def register_failure(self, email: str, ip_address: str | None, now: datetime) -> None: ...

    def reset(self, email: str, ip_address: str | None) -> None: ...
