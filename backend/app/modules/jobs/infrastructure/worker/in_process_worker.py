from app.modules.jobs.application.commands import ProcessPendingJobsCommand
from app.modules.jobs.application.policy import JobPolicy
from app.modules.jobs.application.process_pending_jobs import ProcessPendingJobsUseCase


class InProcessJobWorker:
    def __init__(
        self,
        process_pending_jobs_use_case: ProcessPendingJobsUseCase,
        job_policy: JobPolicy | None = None,
    ) -> None:
        self._process_pending_jobs_use_case = process_pending_jobs_use_case
        self._job_policy = job_policy or JobPolicy()

    def process_batch(self) -> int:
        return self._process_pending_jobs_use_case.execute(
            ProcessPendingJobsCommand(limit=self._job_policy.default_batch_size)
        )
