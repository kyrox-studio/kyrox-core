from fastapi import Depends, Request
from sqlalchemy.orm import Session as DbSession

from app.db.session import get_db
from app.modules.jobs.application.enqueue_job import EnqueueJobUseCase
from app.modules.jobs.application.get_job import GetJobUseCase
from app.modules.jobs.application.policy import JobPolicy
from app.modules.jobs.application.process_pending_jobs import ProcessPendingJobsUseCase
from app.modules.jobs.domain.ports import JobHandlerRegistry, JobRepository
from app.modules.jobs.infrastructure.repositories import SqlAlchemyJobRepository
from app.modules.jobs.infrastructure.worker.in_process_worker import InProcessJobWorker


def get_job_repository(db: DbSession = Depends(get_db, scope="function")) -> JobRepository:
    return SqlAlchemyJobRepository(db)


def get_job_policy() -> JobPolicy:
    return JobPolicy()


def get_job_handler_registry(request: Request) -> JobHandlerRegistry:
    return request.app.state.job_handler_registry


def get_enqueue_job_use_case(
    job_repository: JobRepository = Depends(get_job_repository),
    job_policy: JobPolicy = Depends(get_job_policy),
) -> EnqueueJobUseCase:
    return EnqueueJobUseCase(job_repository=job_repository, job_policy=job_policy)


def get_get_job_use_case(
    job_repository: JobRepository = Depends(get_job_repository),
) -> GetJobUseCase:
    return GetJobUseCase(job_repository=job_repository)


def get_process_pending_jobs_use_case(
    job_repository: JobRepository = Depends(get_job_repository),
    handler_registry: JobHandlerRegistry = Depends(get_job_handler_registry),
    job_policy: JobPolicy = Depends(get_job_policy),
) -> ProcessPendingJobsUseCase:
    return ProcessPendingJobsUseCase(
        job_repository=job_repository,
        handler_registry=handler_registry,
        job_policy=job_policy,
    )


def get_in_process_job_worker(
    process_pending_jobs_use_case: ProcessPendingJobsUseCase = Depends(
        get_process_pending_jobs_use_case
    ),
    job_policy: JobPolicy = Depends(get_job_policy),
) -> InProcessJobWorker:
    return InProcessJobWorker(
        process_pending_jobs_use_case=process_pending_jobs_use_case,
        job_policy=job_policy,
    )
