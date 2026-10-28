import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.modules.identity.infrastructure.persistence import models as identity_models  # noqa: F401
from app.modules.identity.infrastructure.persistence.models import UserModel


def test_get_db_commits_on_success(tmp_path, monkeypatch) -> None:
    db_file = tmp_path / "get_db_commit.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    test_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr("app.db.session.SessionLocal", test_session_local)

    from app.db.session import get_db

    user_id = uuid.uuid4()
    generator = get_db()
    session = next(generator)
    session.add(
        UserModel(
            id=user_id,
            email="persist@example.com",
            password_hash="hashed",
            status="active",
            is_super_admin=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    session.flush()
    try:
        next(generator)
    except StopIteration:
        pass

    verify_session = test_session_local()
    try:
        persisted = verify_session.scalars(
            select(UserModel).where(UserModel.email == "persist@example.com")
        ).first()
        assert persisted is not None
        assert persisted.id == user_id
    finally:
        verify_session.close()
        engine.dispose()


def test_get_db_rolls_back_on_exception(tmp_path, monkeypatch) -> None:
    db_file = tmp_path / "get_db_rollback.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    test_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr("app.db.session.SessionLocal", test_session_local)

    from app.db.session import get_db

    generator = get_db()
    session = next(generator)
    session.add(
        UserModel(
            id=uuid.uuid4(),
            email="rollback@example.com",
            password_hash="hashed",
            status="active",
            is_super_admin=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    session.flush()

    with pytest.raises(RuntimeError):
        generator.throw(RuntimeError("simulated failure"))

    verify_session = test_session_local()
    try:
        persisted = verify_session.scalars(
            select(UserModel).where(UserModel.email == "rollback@example.com")
        ).first()
        assert persisted is None
    finally:
        verify_session.close()
        engine.dispose()
