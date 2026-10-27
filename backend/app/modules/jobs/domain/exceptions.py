class JobError(Exception):
    """Base exception for jobs domain errors."""


class JobNotFoundError(JobError):
    """Raised when a job does not exist or is not visible in org scope."""


class InvalidJobTypeError(JobError):
    """Raised when job_type violates format rules."""


class InvalidJobPayloadError(JobError):
    """Raised when payload or related JSON input is invalid."""


class DuplicateIdempotencyConflictError(JobError):
    """Raised when idempotency key is reused with a different payload."""


