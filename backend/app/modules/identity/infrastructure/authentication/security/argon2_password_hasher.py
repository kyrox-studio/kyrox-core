
from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.modules.identity.domain.authentication.value_objects.security.password_hash import (
    PasswordHash,
)


class Argon2idPasswordHasher:
    def __init__(self) -> None:
        self._hasher = Argon2PasswordHasher()

    def hash(self, password: str) -> PasswordHash:
        return PasswordHash(self._hasher.hash(password))

    def verify(self, password: str, password_hash: PasswordHash) -> bool:
        try:
            return self._hasher.verify(password_hash.value, password)
        except VerifyMismatchError:
            return False

    def needs_rehash(self, password_hash: PasswordHash) -> bool:
        return self._hasher.check_needs_rehash(password_hash.value)
