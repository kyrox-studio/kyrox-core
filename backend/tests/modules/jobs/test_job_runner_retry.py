import uuid
from datetime import UTC, datetime


from app.modules.jobs.application.worker.job_runner import JobRunner
from app.modules.jobs.application.worker.registry import InMemoryJobHandlerRegistry
from app.modules.jobs.domain.entities import Job
from app.modules.jobs.domain.ports import JobHandler, JobHandlerResult
from app.modules.jobs.domain.value_objects.job_status import JobStatus
from app.modules.jobs.domain.value_objects.job_type import JobType


class FailingJobHandler(JobHandler):
    def handle(self, job: Job) -> JobHandlerResult:
        raise RuntimeError("boom")


def _running_job(*, max_attempts: int, attempt_count: int) -> Job:
    now = datetime.now(UTC)
    return Job(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        job_type=JobType.create("core.platform.echo"),
        payload={"value": 1},
        status=JobStatus.RUNNING,
        idempotency_key=None,
        attempt_count=attempt_count,
        max_attempts=max_attempts,
        result=None,
        failure_reason=None,
        created_at=now,
        started_at=now,
        finished_at=None,
    )


def test_job_runner_retries_until_max_attempts() -> None:
    registry = InMemoryJobHandlerRegistry()
    registry.register(JobType.create("core.platform.echo"), FailingJobHandler())
    runner = JobRunner(registry)

    job = _running_job(max_attempts=3, attempt_count=1)
    retried = runner.run(job)
    assert retried.status is JobStatus.PENDING
    assert retried.failure_reason is not None

    retried.attempt_count = 3
    retried.status = JobStatus.RUNNING
    failed = runner.run(retried)
    assert failed.status is JobStatus.FAILED
    assert failed.failure_reason is not None
    assert failed.finished_at is not None
