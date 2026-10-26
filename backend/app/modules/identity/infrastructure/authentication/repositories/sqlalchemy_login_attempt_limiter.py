"""Database-backed sign-in throttle (SECURITY_PROGRAM F-004).

Core runs several workers/processes, so counters live in the database rather
than in process memory: every worker sees the same failures and a restart does
not clear a lock. Three counters are kept per failed attempt, each with its own
threshold; a threshold of 0 disables that counter:

* ``account_ip``: submitted email + client address (default 5 per window),
* ``account``: submitted email from any address (default 10 per window),
* ``ip``: client address across accounts (default off, because FAIR CRM signs
  users in server-to-server and Core then sees one address for all of them).

Counting starts at the first failure of a window; reaching a threshold locks
that key until ``now + lockout``. A successful sign-in clears the account
counters (not the address counter). Keys are hashed. The submitted email may
not belong to any account, so a lock never reveals whether an account exists.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.modules.identity.infrastructure.authentication.persistence.models.login_throttle import (
    LoginThrottleModel,
)

_STALE_AFTER = timedelta(days=1)


@dataclass(frozen=True, slots=True)
class LoginThrottlePolicy:
    window_seconds: int = 900
    lockout_seconds: int = 900
    max_failures_per_account_ip: int = 5
    max_failures_per_account: int = 10
    max_failures_per_ip: int = 0


def _key(scope: str, value: str) -> str:
    return hashlib.sha256(f"kyrox-login:{scope}:{value}".encode()).hexdigest()


def _as_utc(value: datetime | None) -> datetime | None:
    # SQLite drops the offset of timezone-aware columns; stored values are UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class SqlAlchemyLoginAttemptLimiter:
    def __init__(self, session: DbSession, policy: LoginThrottlePolicy) -> None:
        self._session = session
        self._policy = policy

    def _keys(self, email: str, ip_address: str | None) -> list[tuple[str, str, int]]:
        address = ip_address or "unknown"
        candidates = (
            ("account_ip", f"{email}|{address}", self._policy.max_failures_per_account_ip),
            ("account", email, self._policy.max_failures_per_account),
            ("ip", address, self._policy.max_failures_per_ip),
        )
        return [(scope, _key(scope, value), limit) for scope, value, limit in candidates if limit > 0]

    def locked_until(self, email: str, ip_address: str | None, now: datetime) -> datetime | None:
        hashes = [key for _, key, _ in self._keys(email, ip_address)]
        if not hashes:
            return None
        locks = [
            _as_utc(value)
            for value in self._session.scalars(
                select(LoginThrottleModel.locked_until).where(LoginThrottleModel.key_hash.in_(hashes))
            ).all()
        ]
        active = [value for value in locks if value is not None and value > now]
        return max(active) if active else None

    def register_failure(self, email: str, ip_address: str | None, now: datetime) -> None:
        window = timedelta(seconds=self._policy.window_seconds)
        lockout = timedelta(seconds=self._policy.lockout_seconds)
        for scope, key, limit in self._keys(email, ip_address):
            row = self._locked_row(key)
            if row is None:
                row = self._insert(scope, key, now)
                if row is not None:
                    self._apply_limit(row, limit, now, lockout)
                    continue
                # Created concurrently by another worker: count on that row.
                row = self._locked_row(key)
            if now - _as_utc(row.window_started_at) >= window:
                row.failure_count = 1
                row.window_started_at = now
                row.locked_until = None
            else:
                row.failure_count += 1
            row.updated_at = now
            self._apply_limit(row, limit, now, lockout)
        self._session.execute(
            delete(LoginThrottleModel).where(LoginThrottleModel.updated_at < now - _STALE_AFTER)
        )
        self._session.flush()

    def reset(self, email: str, ip_address: str | None) -> None:
        hashes = [key for scope, key, _ in self._keys(email, ip_address) if scope != "ip"]
        if hashes:
            self._session.execute(delete(LoginThrottleModel).where(LoginThrottleModel.key_hash.in_(hashes)))
            self._session.flush()

    @staticmethod
    def _apply_limit(row: LoginThrottleModel, limit: int, now: datetime, lockout: timedelta) -> None:
        if row.failure_count >= limit:
            row.locked_until = now + lockout

    def _locked_row(self, key: str) -> LoginThrottleModel | None:
        return self._session.scalars(
            select(LoginThrottleModel).where(LoginThrottleModel.key_hash == key).with_for_update()
        ).first()

    def _insert(self, scope: str, key: str, now: datetime) -> LoginThrottleModel | None:
        row = LoginThrottleModel(
            key_hash=key, scope=scope, failure_count=1,
            window_started_at=now, locked_until=None, updated_at=now,
        )
        savepoint = self._session.begin_nested()
        try:
            self._session.add(row)
            self._session.flush()
        except IntegrityError:
            savepoint.rollback()
            return None
        savepoint.commit()
        return row
