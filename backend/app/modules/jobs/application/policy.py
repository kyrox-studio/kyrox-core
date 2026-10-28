import json
import re
from dataclasses import dataclass
from typing import Any

from app.modules.jobs.domain.exceptions import InvalidJobPayloadError
from app.modules.jobs.domain.value_objects.job_type import JobType

DEFAULT_MAX_ATTEMPTS = 3
MAX_MAX_ATTEMPTS = 10
MIN_MAX_ATTEMPTS = 1
MAX_PAYLOAD_BYTES = 65536
DEFAULT_BATCH_SIZE = 10
_MAX_IDEMPOTENCY_KEY_LENGTH = 128
_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass(frozen=True, slots=True)
class JobPolicy:
    default_max_attempts: int = DEFAULT_MAX_ATTEMPTS
    max_max_attempts: int = MAX_MAX_ATTEMPTS
    min_max_attempts: int = MIN_MAX_ATTEMPTS
    max_payload_bytes: int = MAX_PAYLOAD_BYTES
    default_batch_size: int = DEFAULT_BATCH_SIZE

    def normalize_job_type(self, raw: str) -> JobType:
        return JobType.create(raw)

    def normalize_max_attempts(self, raw: int | None) -> int:
        if raw is None:
            return self.default_max_attempts
        if raw < self.min_max_attempts or raw > self.max_max_attempts:
            raise InvalidJobPayloadError(
                f"max_attempts must be between {self.min_max_attempts} and {self.max_max_attempts}"
            )
        return raw

    def validate_payload(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise InvalidJobPayloadError("Job payload must be a JSON object")
        try:
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise InvalidJobPayloadError("Job payload must be JSON-serializable") from exc
        if len(serialized.encode("utf-8")) > self.max_payload_bytes:
            raise InvalidJobPayloadError(
                f"Job payload exceeds maximum size of {self.max_payload_bytes} bytes"
            )
        return payload

    def normalize_idempotency_key(self, raw: str | None) -> str | None:
        if raw is None:
            return None
        normalized = raw.strip()
        if not normalized:
            raise InvalidJobPayloadError("idempotency_key cannot be empty")
        if len(normalized) > _MAX_IDEMPOTENCY_KEY_LENGTH:
            raise InvalidJobPayloadError(
                f"idempotency_key exceeds maximum length of {_MAX_IDEMPOTENCY_KEY_LENGTH} characters"
            )
        if not _IDEMPOTENCY_KEY_PATTERN.match(normalized):
            raise InvalidJobPayloadError(
                "idempotency_key may contain only letters, numbers, underscores, and hyphens"
            )
        return normalized

    def canonical_payload(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def payloads_match(self, left: dict[str, Any], right: dict[str, Any]) -> bool:
        return self.canonical_payload(left) == self.canonical_payload(right)

    def normalize_batch_size(self, raw: int) -> int:
        if raw < 1:
            raise InvalidJobPayloadError("Batch size must be at least 1")
        return raw
