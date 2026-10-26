import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from app.api.v1.router import api_v1_router
from app.core.config import settings, validate_runtime_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.modules.jobs.application.commands import ProcessPendingJobsCommand
from app.modules.jobs.application.policy import JobPolicy
from app.modules.jobs.application.process_pending_jobs import ProcessPendingJobsUseCase
from app.modules.jobs.bootstrap import build_job_handler_registry
from app.modules.jobs.infrastructure.repositories import SqlAlchemyJobRepository
from app.modules.notifications.bootstrap import register_notification_platform

logger = logging.getLogger(__name__)


def _process_pending_job_batch(app: FastAPI) -> None:
    db = SessionLocal()
    try:
        policy = JobPolicy()
        use_case = ProcessPendingJobsUseCase(
            job_repository=SqlAlchemyJobRepository(db),
            handler_registry=app.state.job_handler_registry,
            job_policy=policy,
        )
        use_case.execute(ProcessPendingJobsCommand(limit=policy.default_batch_size))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Core pending-job batch failed")
    finally:
        db.close()


async def _job_dispatch_loop(app: FastAPI) -> None:
    while True:
        await asyncio.to_thread(_process_pending_job_batch, app)
        await asyncio.sleep(settings.CORE_JOB_DISPATCH_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await asyncio.to_thread(_process_pending_job_batch, app)
    dispatcher = asyncio.create_task(_job_dispatch_loop(app))
    try:
        yield
    finally:
        dispatcher.cancel()
        with suppress(asyncio.CancelledError):
            await dispatcher


def create_app() -> FastAPI:
    setup_logging()
    # F-C5: refuse to start with unsafe production configuration.
    validate_runtime_settings(settings)

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
        lifespan=lifespan,
    )

    app.state.job_handler_registry = build_job_handler_registry()
    app.state.notification_channel_registry = register_notification_platform(
        app.state.job_handler_registry
    )

    register_exception_handlers(app)
    app.include_router(api_v1_router, prefix="/api/v1")

    return app


app = create_app()
